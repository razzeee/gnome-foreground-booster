"""Run both real binaries against private buses and a simulated cgroup filesystem.

Requires bubblewrap, dbus-daemon, Python dbus-python and PyGObject. No root needed.
The outer process mounts a temporary directory over /sys/fs/cgroup before any
test runs. Everything else is read-only except the test's temporary directory.
This tests process integration, not kernel controller semantics or Mutter itself.
"""

import argparse
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib


MANAGER = "org.freedesktop.systemd1.Manager"
FOCUS = "user.xdg.inactive-since"
STATE = "user.dmemcg-booster.dmem-low-state"
REGION = "drm/0000:03:00.0/vram"
CAPACITY = 100
CGROUP = Path("/sys/fs/cgroup")
OPTIONS = None


def object_path(name):
    escaped = "".join(
        char if char.isascii() and char.isalnum() else f"_{ord(char):02x}"
        for char in name
    )
    return "/org/freedesktop/systemd1/unit/" + escaped


class Unit(dbus.service.Object):
    def __init__(self, bus, name, path):
        self.name = name
        self.cgroup = path
        self.requests = []
        self.object_path = object_path(name)
        super().__init__(bus, self.object_path)

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v", sender_keyword="sender")
    def Get(self, interface, prop, sender=None):
        expected = "org.freedesktop.systemd1." + self.name.rsplit(".", 1)[1].capitalize()
        if prop != "ControlGroup" or interface != expected:
            raise dbus.exceptions.DBusException("unknown property")
        self.requests.append(sender)
        return dbus.String(self.cgroup, variant_level=1)


class Manager(dbus.service.Object):
    def __init__(self, bus):
        self.bus = bus
        self.name = dbus.service.BusName("org.freedesktop.systemd1", bus=bus)
        self.units = {}
        self.subscribers = set()
        super().__init__(bus, "/org/freedesktop/systemd1")

    @dbus.service.method(MANAGER, in_signature="", out_signature="", sender_keyword="sender")
    def Subscribe(self, sender=None):
        self.subscribers.add(sender)

    @dbus.service.method(MANAGER, in_signature="", out_signature="a(ssssssouso)")
    def ListUnits(self):
        return [
            (unit.name, unit.name, "loaded", "active", "running", "",
             unit.object_path, 0, "", "/")
            for unit in self.units.values()
        ]

    @dbus.service.signal(MANAGER, signature="so")
    def UnitNew(self, name, path):
        pass

    @dbus.service.signal(MANAGER, signature="so")
    def UnitRemoved(self, name, path):
        pass

    def add(self, name, path, announce=True):
        unit = Unit(self.bus, name, path)
        self.units[name] = unit
        # Like systemd, emit unit notifications when at least one client subscribes.
        if announce and any(self.bus.name_has_owner(sender) for sender in self.subscribers):
            self.UnitNew(name, unit.object_path)
        return unit


class CompanionTests(unittest.TestCase):
    def setUp(self):
        # Refuse to operate unless the runner mounted our regular directory here.
        fixture = Path(OPTIONS.sandbox) / "cgroup"
        self.assertTrue(CGROUP.samefile(fixture), "test requires the isolated cgroup mount")
        self.directory = Path(tempfile.mkdtemp(prefix="case-", dir=OPTIONS.sandbox))
        self.processes = []
        self.buses = []
        self.logs = []
        self.groups = set()
        self.deferred_low = {}
        self.addCleanup(self.cleanup)
        self.context = GLib.MainContext.default()
        self.user_bus, self.user_address = self.bus("user")
        self.system_bus, self.system_address = self.bus("system")
        self.user_manager = Manager(self.user_bus)
        self.system_manager = Manager(self.system_bus)
        self.environment = dict(os.environ,
            DBUS_SESSION_BUS_ADDRESS=self.user_address,
            DBUS_SYSTEM_BUS_ADDRESS=self.system_address)
        self.make_group(CGROUP, interior=True)
        (CGROUP / "dmem.capacity").write_text(f"{REGION} {CAPACITY}\n")
        self.user_slice = CGROUP / "user.slice" / f"user-{os.getuid()}.slice"
        self.user_service = self.user_slice / f"user@{os.getuid()}.service"
        self.app_root = self.user_service / "app.slice"
        for path in [CGROUP / "user.slice", self.user_slice, self.user_service, self.app_root]:
            self.make_group(path, interior=True)
        self.user_manager.add("app.slice", self.relative(self.app_root), announce=False)
        self.a = self.app_root / "a.scope"
        self.b = self.app_root / "b.service"
        self.make_app(self.a, 10, active=True, announce=False)
        self.make_app(self.b, 20, announce=False)

    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for pipe in [process.stdout, process.stderr]:
                if pipe is not None:
                    pipe.close()
        for bus in self.buses:
            bus.close()
        for log in self.logs:
            log.close()
        for path in CGROUP.iterdir():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        shutil.rmtree(self.directory)

    def bus(self, name):
        process = subprocess.Popen([
            "dbus-daemon", "--session", "--nofork", "--print-address=1",
            f"--address=unix:path={self.directory / (name + '.bus')}",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        address = process.stdout.readline().strip()
        if not address:
            _, error = process.communicate(timeout=5)
            self.fail("private D-Bus daemon did not start: " + error)
        bus = dbus.bus.BusConnection(address)
        bus.set_exit_on_disconnect(False)
        self.buses.append(bus)
        return bus, address

    def relative(self, path):
        return "/" + str(path.relative_to(CGROUP))

    def make_group(self, path, interior=False, baseline=0, deferred=False):
        path.mkdir(exist_ok=True)
        (path / "cgroup.subtree_control").write_text("cpu" if interior else "")
        self.groups.add(path)
        if deferred:
            self.deferred_low[path] = baseline
        else:
            self.write_low(path, baseline)

    def make_app(self, path, baseline, active=False, announce=True, assigned=True):
        self.make_group(path, baseline=baseline, deferred=True)
        os.setxattr(path, FOCUS, b"-1" if active else b"1")
        return self.user_manager.add(path.name, self.relative(path) if assigned else "", announce)

    def write_low(self, path, value):
        (path / "dmem.low").write_text(f"{REGION} {value}\n")

    def low(self, path):
        try:
            fields = (path / "dmem.low").read_text().split()
            return int(fields[1]) if len(fields) == 2 else None
        except FileNotFoundError:
            return None

    def state(self, path):
        try:
            return os.getxattr(path, STATE)
        except OSError as error:
            if error.errno == errno.ENODATA:
                return None
            raise

    def pump(self):
        while self.context.pending():
            self.context.iteration(False)
        # Model the kernel's command-style subtree_control file and child dmem
        # file creation. Application limits themselves use real file I/O.
        for path in self.groups:
            control = path / "cgroup.subtree_control"
            if control.read_text().strip() == "+dmem":
                control.write_text("cpu dmem")
        for path, baseline in list(self.deferred_low.items()):
            if "dmem" in (path.parent / "cgroup.subtree_control").read_text().split():
                self.write_low(path, baseline)
                del self.deferred_low[path]

    def wait(self, predicate, description, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if predicate():
                return
            time.sleep(0.01)
        diagnostics = []
        for log in self.logs:
            log.flush()
            log.seek(0)
            diagnostics.append(log.read())
        self.fail(description + "\n" + "\n".join(diagnostics))

    def settle(self, seconds=0.2):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.pump()
            time.sleep(0.01)

    def launch(self, executable, *args):
        log = tempfile.TemporaryFile(mode="w+", dir=self.directory)
        self.logs.append(log)
        process = subprocess.Popen([executable, *args], env=self.environment, stdout=log, stderr=log)
        self.processes.append(process)
        return process

    def foreground(self):
        process = self.launch(OPTIONS.foreground)
        self.wait(lambda: any(self.user_bus.name_has_owner(sender) for sender in self.user_manager.subscribers),
                  "foreground did not subscribe")
        return process

    def shims(self):
        system = self.launch(OPTIONS.companion, "--use-system-bus")
        self.wait(lambda: self.low(self.user_service) == CAPACITY,
                  "system shim did not protect the user service")
        self.assertEqual(self.low(self.app_root), 0, "system shim changed a delegated user limit")
        user = self.launch(OPTIONS.companion)
        self.wait(lambda: self.low(self.app_root) == CAPACITY,
                  "user shim did not protect app.slice")
        self.wait(lambda: self.low(self.a) is not None, "shim did not enable application dmem")
        self.assertIsNone(system.poll())
        self.assertIsNone(user.poll())
        return system, user

    def stop(self, process):
        process.terminate()
        self.wait(lambda: process.poll() is not None, "process did not terminate")

    def focus(self, previous, current):
        os.setxattr(previous, FOCUS, b"42")
        os.setxattr(current, FOCUS, b"-1")

    def test_focus_restore_external_writes_and_duplicate_process(self):
        _, user = self.shims()
        self.assertEqual(self.low(self.a), 10, "shim changed an application baseline")
        foreground = self.foreground()
        self.wait(lambda: self.low(self.a) == CAPACITY, "initial foreground was not boosted")
        self.assertIn(f"{REGION} 10 {CAPACITY}".encode(), self.state(self.a))
        self.focus(self.a, self.b)
        self.wait(lambda: self.low(self.a) == 10 and self.low(self.b) == CAPACITY,
                  "focus switch did not transfer protection")
        self.assertIsNone(self.state(self.a))
        self.write_low(self.b, 75)
        self.focus(self.b, self.a)
        self.wait(lambda: self.low(self.a) == CAPACITY and self.state(self.b) is None,
                  "external-write restoration did not finish")
        self.assertEqual(self.low(self.b), 75)
        self.stop(user)
        self.launch(OPTIONS.companion)
        self.settle(1.2)
        self.assertEqual(self.low(self.a), CAPACITY, "shim restart overwrote foreground protection")
        duplicate = self.launch(OPTIONS.foreground)
        self.wait(lambda: duplicate.poll() is not None, "duplicate foreground instance did not exit")
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertEqual(self.low(self.a), CAPACITY)
        self.stop(foreground)
        self.assertEqual(foreground.returncode, 0)
        self.assertEqual(self.low(self.a), 10)
        self.assertIsNone(self.state(self.a))
        self.assertEqual(self.low(self.app_root), CAPACITY)

    def test_foreground_first_and_new_application_hierarchy(self):
        foreground = self.foreground()
        self.settle()
        self.assertIsNone(self.low(self.a), "foreground enabled the controller itself")
        self.assertEqual(self.low(self.app_root), 0)
        self.shims()
        self.wait(lambda: self.low(self.a) == CAPACITY, "foreground did not recover from late shim startup")
        nested = self.app_root / "nested.slice"
        self.make_group(nested, interior=True)
        self.user_manager.add(nested.name, self.relative(nested))
        app = nested / "new.scope"
        self.make_app(app, 7)
        self.focus(self.a, app)
        self.wait(lambda: self.low(app) == CAPACITY and self.low(self.a) == 10,
                  "new application hierarchy was not enabled and boosted")
        late = self.app_root / "late.scope"
        unit = self.make_app(late, 9, assigned=False)
        self.settle(1.2)
        unit.cgroup = self.relative(late)
        self.focus(app, late)
        self.wait(lambda: self.low(late) == CAPACITY and self.low(app) == 7,
                  "late ControlGroup assignment was not recovered")
        self.stop(foreground)
        self.assertEqual(self.low(late), 9)

    def test_crash_recovery_and_bus_failure_cleanup(self):
        self.shims()
        foreground = self.foreground()
        self.wait(lambda: self.low(self.a) == CAPACITY, "initial boost failed")
        foreground.kill()
        foreground.wait(timeout=5)
        self.assertEqual(self.low(self.a), CAPACITY)
        self.assertIsNotNone(self.state(self.a))
        foreground = self.foreground()
        self.settle(0.3)
        self.focus(self.a, self.b)
        self.wait(lambda: self.low(self.a) == 10 and self.low(self.b) == CAPACITY,
                  "replacement process lost the original baseline")
        self.processes[0].terminate()  # Private user bus, never the host's bus.
        self.wait(lambda: foreground.poll() is not None, "foreground did not exit on bus loss")
        self.assertNotEqual(foreground.returncode, 0)
        self.assertEqual(self.low(self.b), 20, "bus failure bypassed restoration")
        self.assertIsNone(self.state(self.b))

    def test_recreated_cgroup_and_application_tree_isolation(self):
        background = self.user_service / "background.slice"
        self.make_group(background, interior=True)
        outside = background / "outside.scope"
        self.make_app(outside, 11, active=True, announce=False)
        self.shims()
        foreground = self.foreground()
        self.wait(lambda: self.low(self.a) == CAPACITY, "outside focus affected application selection")
        self.assertEqual(self.low(outside), 11)
        self.assertIsNone(self.state(outside))
        shutil.rmtree(self.a)
        self.make_group(self.a, baseline=30, deferred=True)
        os.setxattr(self.a, FOCUS, b"-1")
        self.wait(lambda: self.low(self.a) == CAPACITY and
                  f"{REGION} 30 {CAPACITY}".encode() in (self.state(self.a) or b""),
                  "recreated cgroup was not recovered without UnitNew")
        self.stop(foreground)
        self.assertEqual(self.low(self.a), 30)

    def test_delayed_assignment_in_new_hierarchy(self):
        self.shims()
        foreground = self.foreground()
        self.wait(lambda: self.low(self.a) == CAPACITY, "initial boost failed")
        nested = self.app_root / "delayed.slice"
        self.make_group(nested, interior=True)
        slice_unit = self.user_manager.add(nested.name, "")
        app = nested / "delayed.scope"
        app_unit = self.make_app(app, 8, assigned=False)
        self.wait(lambda: all(any(sender not in self.user_manager.subscribers
                                 for sender in unit.requests)
                              for unit in [slice_unit, app_unit]),
                  "companion did not receive the early UnitNew notifications")
        slice_unit.cgroup = self.relative(nested)
        app_unit.cgroup = self.relative(app)
        self.focus(self.a, app)
        self.wait(lambda: self.low(app) == CAPACITY,
                  "late-assigned application in a new hierarchy was not boosted")
        self.assertIn("dmem", (nested / "cgroup.subtree_control").read_text().split())
        self.assertEqual(self.low(self.a), 10)
        self.stop(foreground)
        self.assertEqual(self.low(app), 8)


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--companion", required=True, type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--foreground", default=str(Path(__file__).resolve().parents[1] / "target/release/gnome-foreground-booster"),
                        type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--sandbox", help=argparse.SUPPRESS)
    parser.add_argument("--test", help="run one CompanionTests method")
    OPTIONS = parser.parse_args()
    if OPTIONS.sandbox:
        DBusGMainLoop(set_as_default=True)
        suite = (unittest.TestSuite([CompanionTests(OPTIONS.test)]) if OPTIONS.test
                 else unittest.defaultTestLoader.loadTestsFromTestCase(CompanionTests))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    for binary in [OPTIONS.companion, OPTIONS.foreground]:
        if not os.access(binary, os.X_OK):
            parser.error(f"build the binary first: {binary}")
    with tempfile.TemporaryDirectory(prefix="gnome-companion-") as directory:
        fixture = Path(directory) / "cgroup"
        fixture.mkdir()
        command = [
            "bwrap", "--unshare-user", "--die-with-parent", "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--bind", directory, directory, "--bind", str(fixture), str(CGROUP),
            "--setenv", "TMPDIR", directory, "--",
            sys.executable, str(Path(__file__).resolve()),
            "--companion", OPTIONS.companion, "--foreground", OPTIONS.foreground,
            "--sandbox", directory,
        ]
        if OPTIONS.test:
            command.extend(["--test", OPTIONS.test])
        return subprocess.call(command)


if __name__ == "__main__":
    sys.exit(main())

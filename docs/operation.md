# Operation and recovery

## Setup

Run the system and user [dmemcg-booster](https://github.com/razzeee/dmemcg-booster)
services first. They enable the dmem controller and protect ancestor cgroups.
Starting gnome-foreground-booster does not start them automatically.

The service needs readable root `dmem.capacity`, writable application `dmem.low`,
and readable and writable user xattrs on application cgroups. It retries setup
when dmem files are unavailable. Missing or ambiguous focus information does not
cause a boost.

## Recovery

The service saves original limits before boosting and restores them on focus
loss or shutdown. It preserves differing limits written by other programs.

Stop it normally to restore limits:

```sh
systemctl --user stop gnome-foreground-booster.service
```

After a crash, a boost can remain until the service restarts and recovers its
saved state, or the application cgroup disappears.

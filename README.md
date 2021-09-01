# tcp-audit-tracefs-eventer

This module implements a `tcp-audit` Eventer plugin which sources TCP state change events from the kernel tracepoints via the `tracefs` virtual filesystem.

It will attempt to use the tracefs filesystem mounted at the following mountpoints:

- `/sys/kernel/tracing`
- `/sys/kernel/debug/tracing`

When running tcp-audit in a container, the host's tracefs must be mounted into the container at one of these paths. For example, for Docker, the `--volume /sys/kernel/tracing:/sys/kernel/tracing` argument would be required to `docker run`.

When using this Eventer, tcp-audit must run as UID 0 (`root`) as this is the owner of the pseudo-files exposed by the tracefs filesystem.

When running in a container, you may need to tune any security profile settings. For example, running with Docker on a system with apparmor enabled requires the `--security-opt apparmor=unconfined` argument.
# Sysbox-fs

The Sysbox file-system (Sysbox-fs) is one of the three active components of the
Sysbox runtime, along Sysbox-mgr and Sysbox-runc.

Sysbox-fs provides file-system emulation capabilities to offer a more complete
and secure "virtual-host" abstraction to the processes running inside Sysbox
containers.

## Main Features

As of today, Sysbox-fs supports the (partial) emulation of the following
components:

* procfs & sysfs emulation: The goal here is to expose and emulate resources
that are not yet namespaced by the Linux kernel, or that are only reachable
within the initial user-namespace.

    Sysbox-fs achieves this by mounting a FUSE file-system over specific
    sections of the `/proc` and `/sys` virtual file-systems, so that I/O
    requests targeting those resources are handled by Sysbox-fs in user-space.

* Syscall emulation: Sysbox-fs traps and emulate a small set of syscalls inside
a system container. The main purpose here is to provide processes inside the
system container with a more complete and consistent view of the resources
that are reachable within a system container. We rely on the Linux kernel's
seccomp BPF features to achieve this.

    For example, inside a system container we trap the `mount` system call in
    order to ensure that such mounts always result in the Sysbox-fs' emulated
    procfs being mounted, rather than the kernel's procfs.

    Another example is the `umount` syscall, which we trap to ensure that
    Sysbox-fs' emulated components cannot be unmounted to expose the kernel's
    version of the corresponding FS node.

## Build & Usage

Sysbox-fs is built through the Makefile targets exposed in the Sysbox
repository. Refer to its [README](../README.md) file for details.

## Testing

Sysbox-fs' repository incorporates unit-tests to verify the basic operation
of its main packages. You can manually execute these unit-tests through the
usual `go test ./...` instruction.

For a more thorough verification of Sysbox-fs features, refer to the
integration-testsuites hosted in the Sysbox repository and executed as
part of the testing Makefile targets (e.g. `make test`).
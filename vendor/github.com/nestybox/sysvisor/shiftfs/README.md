shiftfs Linux Kernel Module
===========================

This directory contains the shiftfs Linux kernel module, which is
as a thin overlay fs that performs uid and gid shifting betweeen user
namespaces.

shiftfs was originally written by James Bottomley and has been modified
slightly by Nestybox (see section Nestybox changes below).

# Uid/Gid Shifting

uid/gid shifting allows the root user in the system container to access
files owned by true root on the host.

Without uid/gid shifting this is not possible, because user namespace
uid/gid mappings in a system container normally map the root user in the
container to a non-root uid/gid on the host.

More generically, uid/gid shifting allows a user with uid/gid X in a
user namespace to access files owned by the uid/gid X on the
host.

In order to ensure this is secure, true root must first "mark" a
directory that it owns as a shiftfs mount point via

`mount -t shiftfs -o mark <dir> <dir>`

Once the mark is set, a root user in another user namespace
can mount shiftfs on the directory via

`mount -t shiftfs <dir> <dir>`.

# Installation

The module is not yet upstreamed to the Linux kernel, so it must be
built and installed out-of-tree.

```bash
$ sudo make clean
$ sudo make
$ sudo insmod shiftfs.ko
```

# Usage

* Create a fake container rootfs:

```bash
chino@deb1:~$ sudo mkdir -p container/rootfs
```

* Mark the rootfs as a shiftfs mount point:

```bash
chino@deb1:~$ sudo mount -t shiftfs -o mark rootfs rootfs
chino@deb1:~$ findmnt | grep shiftfs
└─/home/chino/container/rootfs        /home/chino/container/rootfs shiftfs    rw,relatime,mark
```

* Unshare into a new user namespace (must do this before mounting shiftfs):

```bash
chino@deb1:~/container$ unshare -m -u -i -n -p -U -C -f -r /bin/bash
root@deb1:~/container# l
total 0
drwxrwxrwx 1 nobody nogroup 0 Mar 13 15:27 rootfs
```

* Mount shiftfs inside the rootfs:

```bash
root@deb1:~/container# mount -t shiftfs rootfs rootfs
root@deb1:~/container# l
total 0
drwxrwxrwx 1 root root 0 Mar 13 15:27 rootfs
```

* As shown, the container's root user now sees rootfs as owned by it,
  even though rootfs is really owned by root.

* Shiftfs is shifting the uid of root in the container (whose uid is a
  regular user in the host) to the uid of root in the host. In other
  words, root in the container is equivalent to root in the host while
  shiftfs is mounted.

* In fact, when root in the container creates a new file under the
  shiftfs mountpoint, this file has true root ownership in the
  host. And this remains as is even after shiftfs is unmounted.


```bash
root@deb1:~/container# cd rootfs/
root@deb1:~/container/rootfs# l
total 0
root@deb1:~/container/rootfs# touch foo
root@deb1:~/container/rootfs# l
total 0
-rw-r--r-- 1 root root 0 Mar 13 15:29 foo
```

* Unmount shiftfs from within the user namespace:

```bash
root@deb1:~/container/rootfs# cd ..
root@deb1:~/container# umount rootfs
root@deb1:~/container# l
total 0
drwxrwxrwx 1 nobody nogroup 6 Mar 13 15:29 rootfs
```

* Exit the user namespace and remove the shiftfs mark of rootfs:

```bash
root@deb1:~/container# exit
chino@deb1:~/container$ l
total 0
drwxrwxrwx 1 root root 6 Mar 13 15:29 rootfs
chino@deb1:~/container$ sudo umount rootfs
chino@deb1:~/container$ findmnt | grep shiftfs
```

# Nestybox Changes to Shiftfs

Changes by Nestybox include bug fixes, addition of functionality
(e.g., mknod support), and creating different versions of the module
so it can be used with different Linux distros. Refer to the Nestybox
sysvisor issues on Github for further details.

# Sysvisor + Shiftfs

sysvisor-runc uses shiftfs to support two important features:

* Docker containers without userns-remap.

* Sharing of volume mounts across system containers.

## Docker containers without userns-remap

sysvisor-runc uses shiftfs to support docker containers when the
docker daemon is configured without userns-remap (as it is by
default).

In this case the system container rootfs files are owned by true
root and are normally located under `/var/lib/docker/...`.

When a user launches the system container with docker, sysvisor-runc
detects that the container does not have a uid/gid mapping and
generates one. It then creates the container and marks and mounts
shiftfs on the system container's rootfs. This allows the system
container's root user to access the container's rootfs without
problem.

Here is an example of a system container's mounts without docker
userns-remap (i.e., with uid/gid shifting):

```
$ docker run -it --rm --runtime=sysvisor-runc debian:latest
root@5ff8b7786772:/# findmnt
TARGET                                SOURCE                                                    FSTYPE   OPTIONS
/                                     .                                                         shiftfs  rw,relatime
|-/proc                               proc                                                      proc     rw,nosuid,nodev,noexec,relatime
| |-/proc/bus                         proc[/bus]                                                proc     ro,relatime
| |-/proc/fs                          proc[/fs]                                                 proc     ro,relatime
| |-/proc/irq                         proc[/irq]                                                proc     ro,relatime

```

Notice how shiftfs is mounted in the container's rootfs.

Uid/gid shifting is not used by sysvisor when docker userns-remap is
enabled, as in this case docker ensures that the container's rootfs is
owned by the same host user that maps to the container's root
user. Sysvisor-runc detects this situation and does not use shiftfs on
the container rootfs.

Here is an example of a system container mounts with docker userns-remap
(i.e., without uid/gid shifting):

```
$ docker run -it --rm --runtime=sysvisor-runc debian:latest
root@92ce5789c394:/# findmnt
TARGET                                SOURCE                                      FSTYPE   OPTIONS
/                                     /dev/sda[/var/lib/docker/231072.231072/btrfs/subvolumes/70d8a082b1d2f0fab5b918aa634d7448fd19292db1b3ae721be68172022b9522]
|                                                                                 btrfs    rw,relatime,space_cache,user_subvol_rm_allowed,subvolid=3355,subvol=/var/lib/docker/231072.231072/btrfs/subvolumes/70d8a082b1d2f0fab5b918aa634d7448fd19292db1b3ae721be68172022b9522
|-/proc                               proc                                        proc     rw,nosuid,nodev,noexec,relatime
| |-/proc/bus                         proc[/bus]                                  proc     ro,relatime
| |-/proc/fs                          proc[/fs]                                   proc     ro,relatime
| |-/proc/irq                         proc[/irq]                                  proc     ro,relatime
```

Notice how shiftfs is not mounted in the container's rootfs (there was
no need to).

Based on the above, the following is sysvisor's behavior with respect
to Docker userns remap:

| Docker userns-remap | Description |
|---------------------|-------------|
| disabled            | sysvisor will allocate exclusive uid/gid mappings per sys container and perform uid/gid shifting. |
|                     | Strong container-to-host isolation. |
|                     | Strong container-to-container isolation. |
|                     | Storage efficient (shared docker images). |
|                     | Requires shiftfs module in kernel (must be loaded by sysvisor installer). |
|                     |
| enabled             | sysvisor will honor docker's uid/gid mappings. |
|                     | uid/gid shifting won't be used because container uid/gid mappings match rootfs owner. |
|                     | Strong container-to-host isolation. |
|                     | Reduced container-to-container isolation (same uid/gid range). |
|                     | Storage efficient (shared docker images). |
|                     | Does not require shiftfs module in kernel. |

## Sharing of volume mounts across containers

In addition to the above, sysvisor-runc uses shiftfs to support
sharing of volumes across system containers.

Without shiftfs, mounting a shared volume across system containers is
challenging. Each system container has a dedicated uid/gid mapping on
the host. In order to mount a shared volume across multiple system
containers, an administrator would need to configure permissions on
the shared volume such that it can be accessed by the host users
corresponding to the system containers. That requires giving the
shared directory read-write permissions to "other" (which is not safe
as it allows any user on the host to access the directory), or using
access control lists (which is complicated because the container
uid/gid mappings are generated when the container is spawned).

By using uid/gid shifting, the shared volume can be owned by true
root (with read-write permissions given to true root only). An admin
can then set a shiftf mark on the directory `mount -t shiftfs -o mark <dir> <dir>`.

Then launch a docker container with a bind mount:

`$ docker run --runtime sysvisor-runc --mount type=bind,source=<dir>,target=/mnt/shared ...`.

When this occurs, sysvisor-runc detects that the bind mount source is
marked for shiftfs and automatically mounts shiftfs on it. This allows
the root user in the system container(s) to access the shared volume
mount, thus overcoming the problem described earlier.

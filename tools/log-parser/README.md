# Sysbox-fs Log Parser

Simple program to parse FUSE transactions per sys-container in
sysbox-fs logs.

Requires that sysbox-fs debug logging be enabled and that Sysbox
uid-shifting be enabled (i.e., the script uses the uid(gid) to
differentiate between system containers).

## Build

```
go build
```

## Usage

* Run sysbox with uid-shifting, and sysbox-fs with debug logging enabled.

* Parse the sysbox-fs log with:

```
./log-parser /var/log/sysbox-fs.log
```

* This creates several files in the current directory, each showing
  FUSE transactions received by sysbox-fs from each sys container.

* FYI: the parsing can take several seconds.

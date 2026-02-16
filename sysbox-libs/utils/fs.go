//
// Copyright 2020 - 2022 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package utils

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var unixFsNameTable = map[int64]string{
	unix.AAFS_MAGIC:            "aafs",
	unix.ADFS_SUPER_MAGIC:      "adfs",
	unix.AFFS_SUPER_MAGIC:      "affs",
	unix.AFS_FS_MAGIC:          "afs",
	unix.AFS_SUPER_MAGIC:       "afs",
	unix.ANON_INODE_FS_MAGIC:   "anon",
	unix.AUTOFS_SUPER_MAGIC:    "autofs",
	unix.BDEVFS_MAGIC:          "bdevfs",
	unix.BINDERFS_SUPER_MAGIC:  "binderfs",
	unix.BINFMTFS_MAGIC:        "binfmtfs",
	unix.BPF_FS_MAGIC:          "bpf fs",
	unix.BTRFS_SUPER_MAGIC:     "btrfs",
	unix.BTRFS_TEST_MAGIC:      "btrfs",
	unix.CRAMFS_MAGIC:          "cramfs",
	unix.DAXFS_MAGIC:           "daxfs",
	unix.DEBUGFS_MAGIC:         "debugfs",
	unix.ECRYPTFS_SUPER_MAGIC:  "encryptfs",
	unix.EFIVARFS_MAGIC:        "efivarfs",
	unix.EFS_SUPER_MAGIC:       "efs",
	unix.EROFS_SUPER_MAGIC_V1:  "erofs",
	unix.EXT4_SUPER_MAGIC:      "ext4",
	unix.F2FS_SUPER_MAGIC:      "f2fs",
	unix.FUTEXFS_SUPER_MAGIC:   "futexfs",
	unix.HOSTFS_SUPER_MAGIC:    "hostfs",
	unix.HPFS_SUPER_MAGIC:      "hpfs",
	unix.HUGETLBFS_MAGIC:       "hugetlbfs",
	unix.ISOFS_SUPER_MAGIC:     "isofs",
	unix.JFFS2_SUPER_MAGIC:     "jffs2",
	unix.MTD_INODE_FS_MAGIC:    "mtd",
	unix.NFS_SUPER_MAGIC:       "nfs",
	unix.NILFS_SUPER_MAGIC:     "nilfs",
	unix.NSFS_MAGIC:            "nsfs",
	unix.OCFS2_SUPER_MAGIC:     "ocfs2",
	unix.OVERLAYFS_SUPER_MAGIC: "overlayfs",
	unix.PIPEFS_MAGIC:          "pipefs",
	unix.PSTOREFS_MAGIC:        "pstorefs",
	unix.RAMFS_MAGIC:           "ramfs",
	unix.REISERFS_SUPER_MAGIC:  "reiserfs",
	unix.SECURITYFS_MAGIC:      "securityfs",
	unix.SOCKFS_MAGIC:          "sockfs",
	unix.SQUASHFS_MAGIC:        "squashfs",
	unix.SYSFS_MAGIC:           "sysfs",
	unix.TMPFS_MAGIC:           "tmpfs",
	unix.TRACEFS_MAGIC:         "tracefs",
	unix.V9FS_MAGIC:            "v9fs",
	unix.XENFS_SUPER_MAGIC:     "xenfs",
	unix.XFS_SUPER_MAGIC:       "xfs",
	unix.ZONEFS_MAGIC:          "zonefs",

	// Magic codes not yet defined in Unix package
	0x65735546: "fuse",
	0x6a656a62: "shiftfs",
	0x6a656a63: "fakeowner",
}

func GetFsName(path string) (string, error) {
	var fs unix.Statfs_t

	err := unix.Statfs(path, &fs)
	if err != nil {
		return "", err
	}

	name, ok := unixFsNameTable[fs.Type]
	if !ok {
		return "unknown fs", fmt.Errorf("unknown fs")
	}

	return name, nil
}

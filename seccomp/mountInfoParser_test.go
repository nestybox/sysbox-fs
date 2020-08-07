
package seccomp

import (
	"testing"
)

var mountInfoData = []byte(`1526 1218 0:86 / / rw,relatime - shiftfs /var/lib/docker/overlay2/85257da8a9d3ce990cc15656845ff381b195501df3aedce24748282556baec11/merged rw
1531 1526 0:95 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
1532 1531 0:96 / /sys/fs/cgroup ro,nosuid,nodev,noexec - tmpfs tmpfs ro,mode=755,uid=231072,gid=231072
1533 1532 0:27 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime - cgroup systemd rw,xattr,name=systemd
1534 1532 0:30 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct
1535 1532 0:31 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,blkio
1536 1532 0:32 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,net_cls,net_prio
1537 1532 0:33 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,hugetlb
1538 1532 0:34 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,perf_event
1539 1532 0:35 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpuset,clone_children
1540 1532 0:36 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,devices
1541 1532 0:37 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,memory
1542 1532 0:38 / /sys/fs/cgroup/rdma rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,rdma
1543 1532 0:39 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,pids
1544 1532 0:40 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,freezer
1555 1531 0:97 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=1024k,uid=231072,gid=231072
1583 1531 0:98 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=1024k,uid=231072,gid=231072
1589 1531 0:77 /sys/module/nf_conntrack/parameters/hashsize /sys/module/nf_conntrack/parameters/hashsize rw,nosuid,nodev,relatime - fuse sysboxfs rw,user_id=0,group_id=0,default_permissions,allow_other
1590 1526 0:85 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1610 1590 0:77 /proc/swaps /proc/swaps rw,nosuid,nodev,relatime - fuse sysboxfs rw,user_id=0,group_id=0,default_permissions,allow_other
1638 1590 0:77 /proc/sys /proc/sys rw,nosuid,nodev,relatime - fuse sysboxfs rw,user_id=0,group_id=0,default_permissions,allow_other
1644 1590 0:77 /proc/uptime /proc/uptime rw,nosuid,nodev,relatime - fuse sysboxfs rw,user_id=0,group_id=0,default_permissions,allow_other
1645 1526 0:104 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,uid=231072,gid=231072
1711 1645 0:6 /null /dev/kmsg rw,nosuid,relatime - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1712 1645 0:84 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
1713 1645 0:105 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=231077,mode=620,ptmxmode=666
1714 1645 0:106 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,uid=231072,gid=231072
1715 1526 0:94 /resolv.conf /etc/resolv.conf rw,relatime - shiftfs /var/lib/docker/containers/acbc2a6670e672cbaf39897aaaabce7f245a8c09a27458173e8a9b99c28ac6ae rw
1716 1526 0:94 /hostname /etc/hostname rw,relatime - shiftfs /var/lib/docker/containers/acbc2a6670e672cbaf39897aaaabce7f245a8c09a27458173e8a9b99c28ac6ae rw
1717 1526 0:94 /hosts /etc/hosts rw,relatime - shiftfs /var/lib/docker/containers/acbc2a6670e672cbaf39897aaaabce7f245a8c09a27458173e8a9b99c28ac6ae rw
1718 1526 0:90 / /usr/src/linux-headers-5.0.0-38-generic ro,relatime - shiftfs /usr/src/linux-headers-5.0.0-38-generic rw
1719 1526 0:88 / /usr/src/linux-headers-5.0.0-38 ro,relatime - shiftfs /usr/src/linux-headers-5.0.0-38 rw
1720 1526 0:87 / /usr/lib/modules/5.0.0-38-generic ro,relatime - shiftfs /lib/modules/5.0.0-38-generic rw
1721 1526 8:1 /var/lib/sysbox/docker/baseVol/acbc2a6670e672cbaf39897aaaabce7f245a8c09a27458173e8a9b99c28ac6ae /var/lib/docker rw,relatime shared:815 - ext4 /dev/sda1 rw,errors=remount-ro
1722 1526 8:1 /var/lib/sysbox/kubelet/acbc2a6670e672cbaf39897aaaabce7f245a8c09a27458173e8a9b99c28ac6ae /var/lib/kubelet rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro
1723 1526 8:1 /var/lib/sysbox/containerd/acbc2a6670e672cbaf39897aaaabce7f245a8c09a27458173e8a9b99c28ac6ae /var/lib/containerd rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro
1724 1526 0:107 / /run rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=65536k,mode=755,uid=231072,gid=231072
1725 1724 0:108 / /run/lock rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=4096k,uid=231072,gid=231072
1726 1526 0:109 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k,uid=231072,gid=231072
1727 1645 0:6 /null /dev/null rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1728 1645 0:6 /random /dev/random rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1729 1645 0:6 /full /dev/full rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1730 1645 0:6 /tty /dev/tty rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1731 1645 0:6 /zero /dev/zero rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1732 1645 0:6 /urandom /dev/urandom rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1219 1645 0:105 /0 /dev/console rw,nosuid,noexec,relatime - devpts devpts rw,gid=231077,mode=620,ptmxmode=666
1343 1590 0:85 /bus /proc/bus ro,relatime - proc proc rw
1344 1590 0:85 /fs /proc/fs ro,relatime - proc proc rw
1345 1590 0:85 /irq /proc/irq ro,relatime - proc proc rw
1360 1590 0:85 /sysrq-trigger /proc/sysrq-trigger ro,relatime - proc proc rw
1361 1590 0:110 / /proc/asound ro,relatime - tmpfs tmpfs ro,uid=231072,gid=231072
1362 1590 0:111 / /proc/acpi ro,relatime - tmpfs tmpfs ro,uid=231072,gid=231072
1393 1590 0:6 /null /proc/keys rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1399 1590 0:6 /null /proc/timer_list rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1400 1590 0:6 /null /proc/sched_debug rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4058184k,nr_inodes=1014546,mode=755
1416 1590 0:112 / /proc/scsi ro,relatime - tmpfs tmpfs ro,uid=231072,gid=231072
1417 1531 0:113 / /sys/firmware ro,relatime - tmpfs tmpfs ro,uid=231072,gid=231072
`)

// Benchmark /proc/pid/mountinfo parsing logic.
func Benchmark_parseData(b *testing.B) {

	mi := &mountInfoParser{
		mh:     nil,
		cntr:   nil,
		pid:    0,
		deep:   true,
		mpInfo: make(map[string]*mountInfo),
		idInfo: make(map[int]*mountInfo),
	}

	for i := 0; i < b.N; i++ {
		err := mi.parseData(mountInfoData)
		if err != nil {
			b.Errorf("err")
		}
	}
}

package seccomp

import (
	libcontainer "github.com/nestybox/sysbox-runc/libcontainer/mount"
)

type mountInfoParser struct {
	hm                    map[int]*libcontainer.Info // hashmap to store all mountinfo entries
	pid                   uint32                     // process generating mount/umount syscall
	targetInfo            *libcontainer.Info         // mountinfo attrs of mount/umount target (e.g. "/proc/sys")
	targetParentInfo      *libcontainer.Info         // attrs of target parent (e.g. "/proc")
	targetGrandParentInfo *libcontainer.Info         // attrs of target grand-parent (e.g. "/")
}

func newMountInfoParser(pid uint32, target string) (*mountInfoParser, error) {

	t := &mountInfoParser{
		hm:                    make(map[int]*libcontainer.Info),
		pid:                   pid,
		targetInfo:            nil,
		targetParentInfo:      nil,
		targetGrandParentInfo: nil,
	}

	// Extract mountinfo attrs for all existing mountpoints.
	if err := t.extractMountInfoAttrs(target); err != nil {
		return nil, err
	}

	return t, nil
}

// Method iterates through "/proc/pid/mountinfo" file to extract all the state
// of the existing mountpoints. Collected data is placed in a hashmap indexed
// by libcontainer.Info.ID (int).
//
// Iteration process will stop the moment in which the desire 'target' is found,
// which is a valid optimization given that 'parent' entries are always placed
// ahead of their 'child' ones.
func (t *mountInfoParser) extractMountInfoAttrs(target string) error {

	entries, err := libcontainer.GetMountsPid(t.pid)
	if err != nil {
		return err
	}

	// Search the table for the given mountpoint.
	for i := 0; i < len(entries); i++ {

		// Populate the hashmap as we go.
		t.hm[entries[i].ID] = entries[i]

		// Stop if a match is found.
		if entries[i].Mountpoint == target {
			t.targetInfo = entries[i]
			break
		}
	}

	return nil
}

func (t *mountInfoParser) getTargetInfo() *libcontainer.Info {

	return t.targetInfo
}

func (t *mountInfoParser) getTargetParentInfo() *libcontainer.Info {

	if t.targetParentInfo != nil {
		return t.targetParentInfo
	}

	targetInfo := t.getTargetInfo()
	if targetInfo == nil {
		return nil
	}

	targetParentInfo, ok := t.hm[targetInfo.Parent]
	if !ok {
		return nil
	}

	t.targetParentInfo = targetParentInfo

	return t.targetParentInfo
}

func (t *mountInfoParser) getTargetGrandParentInfo() *libcontainer.Info {

	if t.targetGrandParentInfo != nil {
		return t.targetGrandParentInfo
	}

	targetParentInfo := t.getTargetParentInfo()
	if targetParentInfo == nil {
		return nil
	}

	targetGrandParentInfo, ok := t.hm[targetParentInfo.Parent]
	if !ok {
		return nil
	}

	t.targetGrandParentInfo = targetGrandParentInfo

	return t.targetGrandParentInfo
}

func (t *mountInfoParser) getTargetGrandGrandParentInfo() *libcontainer.Info {

	grandParent := t.getTargetGrandParentInfo()
	if grandParent == nil {
		return nil
	}

	grandgrandParent, ok := t.hm[grandParent.Parent]
	if !ok {
		return nil
	}

	return grandgrandParent
}

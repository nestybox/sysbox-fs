// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func Memory(mount, reader, container string) (uint64, uint64, error) {
	const unlimited = uint64(math.MaxUint64)
	limit, available, sharedLimit := unlimited, unlimited, unlimited
	inside := true
	for path := reader; path != "/"; path = filepath.Dir(path) {
		dir := filepath.Join(mount, path)
		data, err := os.ReadFile(filepath.Join(dir, "memory.max"))
		if err != nil && !os.IsNotExist(err) {
			return 0, 0, err
		}
		if err == nil && strings.TrimSpace(string(data)) != "max" {
			max, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				return 0, 0, err
			}
			limit = min(limit, max)
			if inside {
				headroom, err := memoryHeadroom(dir, max)
				if err != nil {
					return 0, 0, err
				}
				available = min(available, headroom)
			} else {
				sharedLimit = min(sharedLimit, max)
			}
		}
		inside = inside && path != container
	}
	if limit == unlimited {
		return 0, 0, syscall.ENODATA
	}
	if sharedLimit != unlimited {
		// A shared ancestor's usage includes other containers.
		headroom, err := memoryHeadroom(filepath.Join(mount, container), sharedLimit)
		if err != nil {
			return 0, 0, err
		}
		available = min(available, headroom)
	}
	return limit, min(available, limit), nil
}

func memoryHeadroom(dir string, limit uint64) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return 0, err
	}
	used, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return limit - min(used, limit), nil
}

// SPDX-License-Identifier: Apache-2.0

package implementations

import (
	"fmt"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/resourceview"
)

var ProcMeminfo_Handler = newProcCgroupFile("ProcMeminfo", "/proc/meminfo", procMeminfo)

func procMeminfo(_ *domain.HandlerRequest, reader, container string) (string, error) {
	limit, available, err := resourceview.Memory(cgroupMount, reader, container)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("MemTotal: %d kB\nMemFree: %d kB\nMemAvailable: %d kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
		limit/1024, available/1024, available/1024), nil
}

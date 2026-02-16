//
// Copyright 2020-2023 Nestybox, Inc.
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

package linuxUtils

import (
	"testing"

	"github.com/spf13/afero"
)

func TestMain(m *testing.M) {
	appFs = afero.NewMemMapFs()
	m.Run()
}

func TestGetDistroPath(t *testing.T) {
	type args struct {
		rootfs string
	}

	var s1 = `NAME="Ubuntu"
VERSION="20.04.1 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.1 LTS"
VERSION_ID="20.04"
`

	var s2 = `NAME="Ubuntu"
VERSION="20.04.1 LTS (Focal Fossa)"
IDNO=ubuntu
ID_LIKE=debian
`

	var s3 = `NAME="Ubuntu"
IDubuntu
blah
`

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
		prepare func()
	}{
		{
			// Test-case 1: Primary os-release file with regular (/) path.
			name:    "1",
			args:    args{rootfs: "/"},
			want:    "ubuntu",
			wantErr: false,
			prepare: func() {

				appFs.MkdirAll("/etc", 0755)
				afero.WriteFile(appFs, "/etc/os-release", []byte(s1), 0644)
			},
		},
		{
			// Test-case 2: Primary os-release file with custom path.
			name:    "2",
			args:    args{"/var/lib/docker/rootfs"},
			want:    "ubuntu",
			wantErr: false,
			prepare: func() {

				appFs.MkdirAll("/var/lib/docker/rootfs/etc", 0755)
				afero.WriteFile(appFs, "/var/lib/docker/rootfs/etc/os-release", []byte(s1), 0644)
			},
		},
		{
			// Test-case 3: Secondary os-release file with custom path.
			name:    "3",
			args:    args{"/var/lib/docker/rootfs"},
			want:    "ubuntu",
			wantErr: false,
			prepare: func() {

				appFs.MkdirAll("/var/lib/docker/rootfs/usr/lib", 0755)
				afero.WriteFile(appFs, "/var/lib/docker/rootfs/usr/lib/os-release", []byte(s1), 0644)
			},
		},
		{
			// Test-case 4: Bogus os-release file. Error expected.
			name:    "4",
			args:    args{"/"},
			want:    "",
			wantErr: true,
			prepare: func() {

				appFs.MkdirAll("/etc", 0755)
				afero.WriteFile(appFs, "/etc/os-release", []byte(s2), 0644)
			},
		},
		{
			// Test-case 5: Bogus os-release file. Error expected.
			name:    "5",
			args:    args{"/"},
			want:    "",
			wantErr: true,
			prepare: func() {

				appFs.MkdirAll("/etc", 0755)
				afero.WriteFile(appFs, "/etc/os-release", []byte(s3), 0644)
			},
		},
	}

	// Testcase executions.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Wipe out memfs.
			if err := appFs.RemoveAll("/"); err != nil {
				t.Errorf("Couldn't clean memMapFs: %v", err)
				return
			}

			// Prepare the setup.
			if tt.prepare != nil {
				tt.prepare()
			}

			got, err := GetDistroPath(tt.args.rootfs)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDistroPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetDistroPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

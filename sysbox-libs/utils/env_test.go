//
// Copyright 2019-2020 Nestybox, Inc.
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

import "testing"

func TestGetEnvVarInfo(t *testing.T) {

	test := []string{"a=b", "var=1", "other-var=hello", "var2="}
	name := []string{"a", "var", "other-var", "var2"}
	val := []string{"b", "1", "hello", ""}

	for i, _ := range test {
		n, v, err := GetEnvVarInfo(test[i])
		if err != nil {
			t.Errorf("GetEnvVarInfo(%s) failed: returned unexpected error %v", test[i], err)
		}
		if n != name[i] || v != val[i] {
			t.Errorf("GetEnvVarInfo(%s) failed: want %s, %s; got %s, %s", test[i], name[i], val[i], n, v)
		}
	}

	if _, _, err := GetEnvVarInfo("a=b=c"); err == nil {
		t.Errorf("GetEnvVarInfo(%s) failed: expected error, got no error.", "a=b=c")
	}
}

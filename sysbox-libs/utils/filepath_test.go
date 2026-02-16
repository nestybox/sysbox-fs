//
// Copyright 2019-2022 Nestybox, Inc.
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

func TestFilepathSort(t *testing.T) {

	paths := []string{
		"/a",
		"/a/b/c",
		"/a/b",
		"/w/x/y/z",
		"/w",
	}

	FilepathSort(paths)

	want := []string{
		"/a",
		"/w",
		"/a/b",
		"/a/b/c",
		"/w/x/y/z",
	}

	if !StringSliceEqual(paths, want) {
		t.Errorf("FilepathSort() failed: want %v, got %v", want, paths)
	}
}

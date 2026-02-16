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

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

// StringSliceContains returns true if x is in a
func StringSliceContains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// StringSliceEqual compares two slices and returns true if they match
func StringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// StringSliceRemove removes from slice 's' any elements which occur on slice 'db'.
func StringSliceRemove(s, db []string) []string {
	var r []string
	for i := 0; i < len(s); i++ {
		found := false
		for _, e := range db {
			if s[i] == e {
				found = true
				break
			}
		}
		if !found {
			r = append(r, s[i])
		}
	}
	return r
}

// StringSliceRemoveMatch removes from slice 's' any elements for which the 'match'
// function returns true.
func StringSliceRemoveMatch(s []string, match func(string) bool) []string {
	var r []string
	for i := 0; i < len(s); i++ {
		if !match(s[i]) {
			r = append(r, s[i])
		}
	}
	return r
}

// uniquify a string slice (i.e., remove duplicate elements)
func StringSliceUniquify(s []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, str := range s {
		if _, ok := keys[str]; !ok {
			keys[str] = true
			result = append(result, str)
		}
	}
	return result
}

// finds the shortest string in the given slice
func StringSliceFindShortest(s []string) string {
	if len(s) == 0 {
		return ""
	}
	shortest := s[0]
	for _, str := range s {
		if len(str) < len(shortest) {
			shortest = str
		}
	}
	return shortest
}

// Compares the given mount slices and returns true if the match
func MountSliceEqual(a, b []specs.Mount) bool {
	if len(a) != len(b) {
		return false
	}
	for i, m := range a {
		if m.Destination != b[i].Destination ||
			m.Source != b[i].Source ||
			m.Type != b[i].Type ||
			!StringSliceEqual(m.Options, b[i].Options) {
			return false
		}
	}
	return true
}

// MountSliceRemove removes from slice 's' any elements which occur on slice 'db'; the
// given function is used to compare elements.
func MountSliceRemove(s, db []specs.Mount, cmp func(m1, m2 specs.Mount) bool) []specs.Mount {
	var r []specs.Mount
	for i := 0; i < len(s); i++ {
		found := false
		for _, e := range db {
			if cmp(s[i], e) {
				found = true
				break
			}
		}
		if !found {
			r = append(r, s[i])
		}
	}
	return r
}

// MountSliceRemoveMatch removes from slice 's' any elements for which the 'match'
// function returns true.
func MountSliceRemoveMatch(s []specs.Mount, match func(specs.Mount) bool) []specs.Mount {
	var r []specs.Mount
	for i := 0; i < len(s); i++ {
		if !match(s[i]) {
			r = append(r, s[i])
		}
	}
	return r
}

// MountSliceContains returns true if mount x is in slice s.
func MountSliceContains(s []specs.Mount, x specs.Mount, match func(a, b specs.Mount) bool) bool {
	for _, m := range s {
		if match(m, x) {
			return true
		}
	}
	return false
}

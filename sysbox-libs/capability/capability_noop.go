//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

// Copyright (c) 2013, Suryandaru Triandana <syndtr@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// +build !linux

package capability

import "errors"

func newPid(pid int) (Capabilities, error) {
	return nil, errors.New("not supported")
}

func newFile(path string) (Capabilities, error) {
	return nil, errors.New("not supported")
}

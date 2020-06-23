//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package implementations


// copytResultBuffer function copies the obtained 'result' buffer into the 'I/O'
// buffer supplied by the user, while ensuring that 'I/O' buffer capacity is not
// exceeded.
func copyResultBuffer(ioBuf []byte, result []byte) (int, error) {

	var length int

	resultLen := len(result)
	ioBufLen := len(ioBuf)

	// Adjust the number of bytes to copy based on the ioBuf capacity.
	if ioBufLen < resultLen {
		copy(ioBuf, result[:ioBufLen])
		length = ioBufLen
	} else {
		copy(ioBuf[:resultLen], result)
		length = resultLen
	}

	return length, nil
}
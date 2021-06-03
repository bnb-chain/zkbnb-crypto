package bulletProofs

import "errors"

var (
	ErrUnequalLength = errors.New("err: the length of secrets and random values are not equal")
	ErrNotPowerOfTwo = errors.New("err: the length of secrets should be power of 2")
	ErrNilParams     = errors.New("err: input params are nil pointers")
	ErrNonBinaryElement = errors.New("input contains non-binary element")
)

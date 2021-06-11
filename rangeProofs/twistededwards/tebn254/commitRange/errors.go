package commitRange

import "errors"

var (
	ErrInvalidRangeParams      = errors.New("err: invalid params for range proof")
	errInvalidBinaryParams     = errors.New("err: invalid binary params")
	errInvalidCommitmentParams = errors.New("err: invalid commitment params")
)

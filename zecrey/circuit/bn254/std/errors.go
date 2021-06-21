package std

import "errors"

var (
	ErrInvalidSetParams   = errors.New("err: invalid params to generate circuit")
	ErrInvalidRangeParams = errors.New("err: invalid params for range proof")
	ErrInvalidChallenge   = errors.New("err: invalid challenge")
	ErrInvalidProof       = errors.New("err: invalid proof")
	ErrInvalidBStar          = errors.New("err: bstar should smaller than zero")
)

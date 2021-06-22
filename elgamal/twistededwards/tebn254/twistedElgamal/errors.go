package twistedElgamal

import "errors"

var (
	ErrParams          = errors.New("err: invalid params")
	ErrDec             = errors.New("err: can not decrypt the encryption")
	ErrInvalidEncValue = errors.New("err: invalid enc value")
)

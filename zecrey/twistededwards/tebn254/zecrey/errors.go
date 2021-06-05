package zecrey

import "errors"

var (
	ErrInvalidParams         = errors.New("err: invalid params")
	ErrStatements            = errors.New("err: invalid statements")
	ErrInconsistentPublicKey = errors.New("err: inconsistent public key")
	ErrInsufficientBalance   = errors.New("err: insufficient balance")
	ErrInvalidDelta          = errors.New("err: you cannot transfer to yourself positive amount")
)

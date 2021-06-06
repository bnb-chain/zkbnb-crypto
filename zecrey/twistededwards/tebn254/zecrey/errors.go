package zecrey

import "errors"

var (
	ErrInvalidParams         = errors.New("err: invalid params")
	ErrStatements            = errors.New("err: invalid statements")
	ErrNegativeBStar         = errors.New("err: bstar should be positive")
	ErrInvalidChallenge      = errors.New("err: invalid challenge")
	ErrInvalidBPParams       = errors.New("err: invalid bulletproof prove params")
	ErrInconsistentPublicKey = errors.New("err: inconsistent public key")
	ErrInsufficientBalance   = errors.New("err: insufficient balance")
	ErrInvalidDelta          = errors.New("err: you cannot transfer to yourself positive amount")
)

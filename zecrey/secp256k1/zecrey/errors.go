package zecrey

import "errors"

var (
	InconsistentPublicKey = errors.New("inconsistent public key")
	InsufficientBalance   = errors.New("insufficient balance")
	InvalidBalance        = errors.New("invalid balance")
	InvalidOwnership      = errors.New("you cannot transfer funds to accounts that do not belong to you")
	InvalidParams         = errors.New("params error")
)

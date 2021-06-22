package wasm

const (
	ErrUnmarshal                     = -1001
	ErrInvalidWithdrawParams         = -1002
	ErrParseEnc                      = -1003
	ErrParsePoint                    = -1004
	ErrParseBigInt                   = -1005
	ErrInvalidWithdrawRelationParams = -1006
	ErrProveWithdraw                 = -1007
	ErrMarshalTx                     = -1008

	ErrInvalidTransferParams         = -1009
	ErrInvalidTransferRelationParams = -1010
	ErrProveTransfer                 = -1011

	ErrL2SkParams = -1012

	ErrInvalidEncParams = -1013
	ErrElGamalEnc       = -1014
	ErrInvalidDecParams = -1015
	ErrElGamalDec       = -1016

	Success = -1
)

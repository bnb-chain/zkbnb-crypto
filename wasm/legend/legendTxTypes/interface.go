package legendTxTypes

import "hash"

type TxInfo interface {
	GetTxType() int

	Validate() error

	VerifySignature(pubKey string) error

	GetFromAccountIndex() int64

	GetNonce() int64

	GetExpiredAt() int64

	ComputeMsgHash(hFunc hash.Hash) (msgHash []byte, err error)
}

package legendTxTypes

type TxInfo interface {
	Validate() error

	VerifySignature(pubKey string) error

	GetNonce() int64

	GetExpiredAt() int64
}

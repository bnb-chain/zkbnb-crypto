package legendTxTypes

type TxInfo interface {
	GetTxType() int

	Validate() error

	VerifySignature(pubKey string) error

	GetFromAccountIndex() int64

	GetNonce() int64

	GetExpiredAt() int64
}

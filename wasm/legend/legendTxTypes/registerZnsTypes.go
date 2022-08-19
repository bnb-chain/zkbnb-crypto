package legendTxTypes

type RegisterZnsTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	AccountIndex    int64
	AccountName     string
	AccountNameHash []byte
	PubKey          string
}

func (txInfo *RegisterZnsTxInfo) GetTxType() int {
	return TxTypeRegisterZns
}

func (txInfo *RegisterZnsTxInfo) Validate() error {
	return nil
}

func (txInfo *RegisterZnsTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *RegisterZnsTxInfo) GetFromAccountIndex() int64 {
	return -1
}

func (txInfo *RegisterZnsTxInfo) GetNonce() int64 {
	return 0
}

func (txInfo *RegisterZnsTxInfo) GetExpiredAt() int64 {
	return -1
}

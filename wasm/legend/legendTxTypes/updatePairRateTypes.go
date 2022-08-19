package legendTxTypes

type UpdatePairRateTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	PairIndex            int64
	FeeRate              int64
	TreasuryAccountIndex int64
	TreasuryRate         int64
}

func (txInfo *UpdatePairRateTxInfo) GetTxType() int {
	return TxTypeUpdatePairRate
}

func (txInfo *UpdatePairRateTxInfo) Validate() error {
	return nil
}

func (txInfo *UpdatePairRateTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *UpdatePairRateTxInfo) GetFromAccountIndex() int64 {
	return -1
}

func (txInfo *UpdatePairRateTxInfo) GetNonce() int64 {
	return 0
}

func (txInfo *UpdatePairRateTxInfo) GetExpiredAt() int64 {
	return -1
}

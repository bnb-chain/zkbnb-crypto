package legendTxTypes

type CreatePairTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	PairIndex            int64
	AssetAId             int64
	AssetBId             int64
	FeeRate              int64
	TreasuryAccountIndex int64
	TreasuryRate         int64
}

func (txInfo *CreatePairTxInfo) GetTxType() int {
	return TxTypeCreatePair
}

func (txInfo *CreatePairTxInfo) Validate() error {
	return nil
}

func (txInfo *CreatePairTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *CreatePairTxInfo) GetFromAccountIndex() int64 {
	return -1
}

func (txInfo *CreatePairTxInfo) GetNonce() int64 {
	return 0
}

func (txInfo *CreatePairTxInfo) GetExpiredAt() int64 {
	return -1
}

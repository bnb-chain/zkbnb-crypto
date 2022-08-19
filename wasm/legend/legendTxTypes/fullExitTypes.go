package legendTxTypes

import "math/big"

type FullExitTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	AccountNameHash []byte
	AssetId         int64

	// Set by layer2.
	AccountIndex int64
	AssetAmount  *big.Int
}

func (txInfo *FullExitTxInfo) GetTxType() int {
	return TxTypeFullExit
}

func (txInfo *FullExitTxInfo) Validate() error {
	return nil
}

func (txInfo *FullExitTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *FullExitTxInfo) GetFromAccountIndex() int64 {
	return -1
}

func (txInfo *FullExitTxInfo) GetNonce() int64 {
	return 0
}

func (txInfo *FullExitTxInfo) GetExpiredAt() int64 {
	return -1
}

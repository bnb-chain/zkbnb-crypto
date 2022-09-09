package legendTxTypes

import (
	"errors"
	"hash"
	"math/big"
)

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
	return NilAccountIndex
}

func (txInfo *UpdatePairRateTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *UpdatePairRateTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *UpdatePairRateTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *UpdatePairRateTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

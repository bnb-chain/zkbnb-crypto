package legendTxTypes

import (
	"errors"
	"hash"
	"math/big"
)

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
	return NilTxAccountIndex
}

func (txInfo *CreatePairTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *CreatePairTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *CreatePairTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *CreatePairTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilTxAccountIndex, NilTxAssetId, nil
}

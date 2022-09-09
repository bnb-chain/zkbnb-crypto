package legendTxTypes

import (
	"errors"
	"hash"
	"math/big"
)

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
	return NilTxAccountIndex
}

func (txInfo *RegisterZnsTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *RegisterZnsTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *RegisterZnsTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *RegisterZnsTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilTxAccountIndex, NilTxAssetId, nil
}

package txtypes

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"math/big"
)

type FullExitTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	L1Address    string
	AssetId      int64
	AccountIndex int64

	// Set by layer2.
	AssetAmount *big.Int
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

func (txInfo *FullExitTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *FullExitTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *FullExitTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *FullExitTxInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *FullExitTxInfo) GetL1SignatureBody() string {
	return ""
}

func (txInfo *FullExitTxInfo) GetL1AddressBySignature() common.Address {
	return [20]byte{}
}

func (txInfo *FullExitTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *FullExitTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *FullExitTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *FullExitTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

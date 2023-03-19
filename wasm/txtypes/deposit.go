package txtypes

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"math/big"
)

type DepositTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	L1Address   string
	AssetId     int64
	AssetAmount *big.Int

	// Set by layer2.
	AccountIndex int64
}

func (txInfo *DepositTxInfo) GetTxType() int {
	return TxTypeDeposit
}

func (txInfo *DepositTxInfo) Validate() error {
	if txInfo.AccountIndex < minAccountIndex-1 {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return ErrFromAccountIndexTooHigh
	}
	return nil
}

func (txInfo *DepositTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *DepositTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *DepositTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *DepositTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *DepositTxInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *DepositTxInfo) GetL1SignatureBody() string {
	return ""
}

func (txInfo *DepositTxInfo) GetL1AddressBySignature() common.Address {
	return [20]byte{}
}

func (txInfo *DepositTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *DepositTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *DepositTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *DepositTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

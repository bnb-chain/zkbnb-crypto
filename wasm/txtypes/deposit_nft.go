package txtypes

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"math/big"
)

type DepositNftTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	L1Address           string
	CreatorAccountIndex int64
	RoyaltyRate         int64
	NftContentType      int64
	NftContentHash      []byte
	CollectionId        int64

	// New nft set by layer2, otherwise get from layer1.
	NftIndex int64

	// Set by layer2.
	AccountIndex int64
}

func (txInfo *DepositNftTxInfo) GetTxType() int {
	return TxTypeDepositNft
}

func (txInfo *DepositNftTxInfo) Validate() error {
	if txInfo.AccountIndex < minAccountIndex-1 {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return ErrFromAccountIndexTooHigh
	}
	return nil
}

func (txInfo *DepositNftTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *DepositNftTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *DepositNftTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *DepositNftTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *DepositNftTxInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *DepositNftTxInfo) GetL1SignatureBody() string {
	return ""
}

func (txInfo *DepositNftTxInfo) GetL1AddressBySignature() common.Address {
	return [20]byte{}
}

func (txInfo *DepositNftTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *DepositNftTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *DepositNftTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *DepositNftTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

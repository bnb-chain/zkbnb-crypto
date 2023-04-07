package txtypes

import (
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"math/big"
)

type FullExitNftTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	NftIndex     int64
	L1Address    string
	AccountIndex int64
	// Set by layer2.
	CreatorAccountIndex int64
	RoyaltyRate         int64
	CreatorL1Address    string
	NftContentHash      []byte
	NftContentType      int64
	CollectionId        int64
}

func (txInfo *FullExitNftTxInfo) GetTxType() int {
	return TxTypeFullExitNft
}

func (txInfo *FullExitNftTxInfo) Validate() error {
	return nil
}

func (txInfo *FullExitNftTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *FullExitNftTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *FullExitNftTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *FullExitNftTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *FullExitNftTxInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *FullExitNftTxInfo) GetL1SignatureBody() string {
	return ""
}

func (txInfo *FullExitNftTxInfo) GetL1AddressBySignature() common.Address {
	return [20]byte{}
}

func (txInfo *FullExitNftTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *FullExitNftTxInfo) GetExpiredAt() int64 {
	return NilExpiredAt
}

func (txInfo *FullExitNftTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	return msgHash, errors.New("not support")
}

func (txInfo *FullExitNftTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

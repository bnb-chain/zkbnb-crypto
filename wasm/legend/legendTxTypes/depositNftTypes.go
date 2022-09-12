package legendTxTypes

import (
	"context"
	"errors"
	"hash"
	"math/big"
)

type DepositNftTxInfo struct {
	TxType uint8

	// Get from layer1 events.
	IsNewNft            uint8
	AccountNameHash     []byte
	CreatorAccountIndex int64
	CreatorTreasuryRate int64
	NftL1Address        string
	NftL1TokenId        *big.Int
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

func (txInfo *DepositNftTxInfo) WitnessKeys(_ context.Context) *TxWitnessKeys {
	return defaultTxWitnessKeys().
		appendAccountKey(&AccountKeys{
			// TODO should prepare asset 0?
			Index: txInfo.AccountIndex,
		}).
		setNftKey(txInfo.NftIndex)
}

func (txInfo *DepositNftTxInfo) Validate() error {
	return nil
}

func (txInfo *DepositNftTxInfo) VerifySignature(pubKey string) error {
	return nil
}

func (txInfo *DepositNftTxInfo) GetFromAccountIndex() int64 {
	return NilAccountIndex
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

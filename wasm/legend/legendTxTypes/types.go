package legendTxTypes

import (
	"context"
	"hash"
	"math/big"
)

type TxInfo interface {
	GetTxType() int

	Validate() error

	VerifySignature(pubKey string) error

	GetFromAccountIndex() int64

	GetNonce() int64

	GetExpiredAt() int64

	Hash(hFunc hash.Hash) (msgHash []byte, err error)

	WitnessKeys(ctx context.Context) *TxWitnessKeys

	GetGas() (int64, int64, *big.Int)
}

type TxWitnessKeys struct {
	Accounts  []*AccountKeys
	PairIndex int64
	NftIndex  int64
}

type AccountKeys struct {
	Index  int64
	Assets []int64
}

func defaultTxWitnessKeys() *TxWitnessKeys {
	return &TxWitnessKeys{
		PairIndex: LastPairIndex,
		NftIndex:  LastNftIndex,
	}
}

func (w *TxWitnessKeys) appendAccountKey(ak *AccountKeys) *TxWitnessKeys {
	w.Accounts = append(w.Accounts, ak)
	return w
}

func (w *TxWitnessKeys) setNftKey(nftIndex int64) *TxWitnessKeys {
	w.NftIndex = nftIndex
	return w
}

func (w *TxWitnessKeys) setPairKey(pairIndex int64) *TxWitnessKeys {
	w.PairIndex = pairIndex
	return w
}

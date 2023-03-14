package txtypes

import (
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"math/big"
)

type TxInfo interface {
	GetTxType() int

	Validate() error

	VerifySignature(pubKey string) error

	GetPubKey() string

	GetAccountIndex() int64

	GetFromAccountIndex() int64

	GetToAccountIndex() int64

	GetL1SignatureBody() string

	GetL1AddressBySignature() common.Address

	GetNonce() int64

	GetExpiredAt() int64

	Hash(hFunc hash.Hash) (msgHash []byte, err error)

	GetGas() (int64, int64, *big.Int)
}

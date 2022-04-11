package std

import (
	"log"
	"math/big"
)

type DepositNftTxConstraints struct {
	ChainId        Variable
	AccountIndex   Variable
	NftContentHash Variable
	NativeAddress  Variable
	IsEnabled      Variable
}

type DepositNftTx struct {
	ChainId        uint64
	AccountIndex   uint64
	NftContentHash []byte
	NativeAddress  *big.Int
}

func SetEmptyDepositNftWitness() (witness DepositNftTxConstraints) {
	witness.ChainId = ZeroInt
	witness.AccountIndex = ZeroInt
	witness.NftContentHash = ZeroInt
	witness.NativeAddress = ZeroInt
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

func SetDepositNftWitness(tx *DepositNftTx, isEnabled bool) (witness DepositNftTxConstraints, err error) {
	if tx == nil {
		log.Println("[SetDepositNftWitness] invalid params")
		return witness, err
	}
	witness.ChainId = tx.ChainId
	witness.AccountIndex = tx.AccountIndex
	witness.NftContentHash = tx.NftContentHash
	witness.NativeAddress = tx.NativeAddress
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

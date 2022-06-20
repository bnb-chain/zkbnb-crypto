package std

import (
	"log"
	"math/big"
)

type DepositNftTxConstraints struct {
	ChainId        Variable
	AccountIndex   Variable
	NftAssetId     Variable
	NftIndex       Variable
	NftContentHash Variable
	NftL1Address   Variable
	NftTokenId     Variable
	IsEnabled      Variable
}

type DepositNftTx struct {
	ChainId        uint64
	AccountIndex   uint64
	NftAssetId     uint64
	NftIndex       uint64
	NftContentHash []byte
	L1Address      *big.Int
	L1TokenId      *big.Int
}

func SetEmptyDepositNftWitness() (witness DepositNftTxConstraints) {
	witness.ChainId = ZeroInt
	witness.AccountIndex = ZeroInt
	witness.NftAssetId = ZeroInt
	witness.NftIndex = ZeroInt
	witness.NftContentHash = ZeroInt
	witness.NftL1Address = ZeroInt
	witness.NftTokenId = ZeroInt
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
	witness.NftAssetId = tx.NftAssetId
	witness.NftIndex = tx.NftIndex
	witness.NftContentHash = tx.NftContentHash
	witness.NftL1Address = tx.L1Address
	witness.NftTokenId = tx.L1TokenId
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

/*
	VerifyDepositNftTxParams:
	account order is:
	- From Account
		- Nft:
			Nft index
	- To Account

*/
func VerifyDepositNftTxParams(api API, flag Variable, nilHash Variable, tx DepositNftTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// nft index
	IsVariableEqual(api, flag, tx.NftAssetId, accountsBefore[0].NftInfo.NftAssetId)
	// before account nft should be empty
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftIndex, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftContentHash, nilHash)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetAmount, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.ChainId, DefaultInt)
	// new nft should be right
	IsVariableEqual(api, flag, tx.NftIndex, accountsAfter[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.ChainId, accountsAfter[0].NftInfo.ChainId)
	IsVariableEqual(api, flag, tx.NftContentHash, accountsAfter[0].NftInfo.NftContentHash)
	IsVariableEqual(api, flag, tx.NftTokenId, accountsAfter[0].NftInfo.L1TokenId)
	IsVariableEqual(api, flag, tx.NftL1Address, accountsAfter[0].NftInfo.L1Address)
}

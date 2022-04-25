/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package std

import "math/big"

type TransferNftTx struct {
	/*
		- from account index
		- to account index
		- to account name
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- call data hash
		- nft index
		- nft asset Id
		- nft content hash
	*/
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	ToAccountName     string
	NftAssetId        int64
	NftIndex          int64
	NftContentHash    []byte
	ToNftAssetId      int64
	NftL1TokenId      *big.Int
	NftL1Address      []byte
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	CallDataHash      []byte
}

type TransferNftTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	ToAccountName     Variable
	NftAssetId        Variable
	NftIndex          Variable
	NftContentHash    Variable
	ToNftAssetId      Variable
	NftL1TokenId      Variable
	NftL1Address      Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	CallDataHash      Variable
}

func EmptyTransferNftTxWitness() (witness TransferNftTxConstraints) {
	return TransferNftTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		ToAccountName:     ZeroInt,
		NftAssetId:        ZeroInt,
		NftIndex:          ZeroInt,
		NftContentHash:    ZeroInt,
		ToNftAssetId:      ZeroInt,
		NftL1TokenId:      ZeroInt,
		NftL1Address:      ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
		CallDataHash:      ZeroInt,
	}
}

func SetTransferNftTxWitness(tx *TransferNftTx) (witness TransferNftTxConstraints) {
	witness = TransferNftTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		ToAccountIndex:    tx.ToAccountIndex,
		ToAccountName:     tx.ToAccountName,
		NftAssetId:        tx.NftAssetId,
		NftIndex:          tx.NftIndex,
		NftContentHash:    tx.NftContentHash,
		ToNftAssetId:      tx.ToNftAssetId,
		NftL1TokenId:      tx.NftL1TokenId,
		NftL1Address:      tx.NftL1Address,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		CallDataHash:      tx.CallDataHash,
	}
	return witness
}

func ComputeHashFromTransferNftTx(tx TransferNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.ToAccountIndex,
		tx.ToAccountName,
		tx.NftAssetId,
		tx.NftIndex,
		tx.NftContentHash,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		tx.CallDataHash,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyGenericTransferTx:
	accounts order is:
	- FromAccount
		- Assets
			- AssetGas
		- Nft
			- nft index
	- ToAccount
		- Nft
			- nft index
	- GasAccount
		- Assets
			- AssetGas
*/
func VerifyTransferNftTx(api API, flag Variable, nilHash Variable, tx TransferNftTxConstraints, accountsBefore [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// nft index
	IsVariableEqual(api, flag, tx.NftAssetId, accountsBefore[0].NftInfo.NftAssetId)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftIndex)
	// before account nft should be empty
	IsEmptyNftInfo(api, flag, nilHash, accountsBefore[1].NftInfo)
	// from account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[1].AccountIndex)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[1].AssetId)
	// should have enough balance
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

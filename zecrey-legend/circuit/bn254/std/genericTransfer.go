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

type GenericTransferTx struct {
	/*
		- from account index
		- to account index
		- to account name
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- call data hash
		- nft index
	*/
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	ToAccountName     string
	AssetId           uint32
	AssetAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	CallDataHash      []byte
	NftAssetId        int64
	NftIndex          int64
	NftContentHash    []byte
}

type GenericTransferTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	ToAccountName     Variable
	AssetId           Variable
	AssetAmount       Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	CallDataHash      Variable
	NftAccountId      Variable
	NftIndex          Variable
	NftContentHash    Variable
}

func EmptyGenericTransferTxWitness() (witness GenericTransferTxConstraints) {
	return GenericTransferTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		ToAccountName:     ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
		CallDataHash:      ZeroInt,
		NftAccountId:      ZeroInt,
		NftIndex:          ZeroInt,
		NftContentHash:    ZeroInt,
	}
}

func SetGenericTransferTxWitness(tx *GenericTransferTx) (witness GenericTransferTxConstraints) {
	witness = GenericTransferTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		ToAccountIndex:    tx.ToAccountIndex,
		ToAccountName:     tx.ToAccountName,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		CallDataHash:      tx.CallDataHash,
		NftAccountId:      tx.NftAssetId,
		NftIndex:          tx.NftIndex,
		NftContentHash:    tx.NftContentHash,
	}
	return witness
}

func ComputeHashFromGenericTransferTx(tx GenericTransferTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.ToAccountIndex,
		tx.ToAccountName,
		tx.AssetId,
		tx.AssetAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		tx.CallDataHash,
		tx.NftAccountId,
		tx.NftIndex,
		tx.NftContentHash,
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
			- AssetA
			- AssetGas
		- Nft
			- nft index
	- ToAccount
		- Assets
			- AssetA
		- Nft
			- nft index
	- GasAccount
		- Assets
			- AssetGas
*/
func VerifyGenericTransferTx(api API, flag Variable, nilHash Variable, tx GenericTransferTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// nft index
	IsVariableEqual(api, flag, tx.NftAccountId, accountsBefore[0].NftInfo.NftAccountIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsAfter[1].NftInfo.NftIndex)
	// before account nft should be empty
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftContentHash, nilHash)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetAmount, DefaultInt)
	// from account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[1].AssetId)
	// should have enough balance
	isSameAsset := api.IsZero(api.Sub(tx.AssetId, tx.GasFeeAssetId))
	totalDelta := api.Add(tx.AssetAmount, tx.GasFeeAssetAmount)
	assetADelta := api.Select(isSameAsset, totalDelta, tx.AssetAmount)
	assetFeeDelta := api.Select(isSameAsset, totalDelta, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, assetADelta)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, assetFeeDelta)
}

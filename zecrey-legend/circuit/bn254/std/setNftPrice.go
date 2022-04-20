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

type SetNftPriceTx struct {
	/*
		- account index
		- nft token id
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
	*/
	AccountIndex      uint32
	NftAccountIndex   uint32
	NftIndex          uint32
	AssetId           uint32
	AssetAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
}

type SetNftPriceTxConstraints struct {
	AccountIndex      Variable
	NftAccountIndex   Variable
	NftIndex          Variable
	AssetId           Variable
	AssetAmount       Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptySetNftPriceTxWitness() (witness SetNftPriceTxConstraints) {
	return SetNftPriceTxConstraints{
		AccountIndex:      ZeroInt,
		NftAccountIndex:   ZeroInt,
		NftIndex:          ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetSetNftPriceTxWitness(tx *SetNftPriceTx) (witness SetNftPriceTxConstraints) {
	witness = SetNftPriceTxConstraints{
		AccountIndex:      tx.AccountIndex,
		NftAccountIndex:   tx.NftAccountIndex,
		NftIndex:          tx.NftIndex,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromSetNftPriceTx(tx SetNftPriceTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.AccountIndex,
		tx.NftAccountIndex,
		tx.NftIndex,
		tx.AssetId,
		tx.AssetAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifySetNftPriceTx:
	accounts order is:
	- FromAccount
		- Assets:
			- AssetGas
		- Nft
			- nft index
	- GasAccount
		- Assets:
			- AssetGas
*/
func VerifySetNftPriceTx(api API, flag Variable, tx SetNftPriceTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.NftAccountIndex, accountsBefore[0].NftInfo.NftAccountIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.AssetId, accountsAfter[0].NftInfo.AssetId)
	IsVariableEqual(api, flag, tx.AssetAmount, accountsAfter[0].NftInfo.AssetAmount)
	// gas
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[2].AccountIndex)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	// should have enough assets
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

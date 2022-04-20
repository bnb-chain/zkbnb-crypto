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

type BuyNftTx struct {
	/*
		- account index
		- owner account index
		- nft token id
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- nonce
	*/
	AccountIndex         uint32
	OwnerAccountIndex    uint32
	NftAssetId           uint32
	NftIndex             uint64
	NftContentHash       []byte
	AssetId              uint32
	AssetAmount          uint64
	TreasuryFeeRate      uint32
	TreasuryAccountIndex uint32
	GasAccountIndex      uint32
	GasFeeAssetId        uint32
	GasFeeAssetAmount    uint64
}

type BuyNftTxConstraints struct {
	/*
		- account index
		- owner account index
		- nft token id
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- nonce
	*/
	AccountIndex         Variable
	OwnerAccountIndex    Variable
	NftAssetId           Variable
	NftIndex             Variable
	NftContentHash       Variable
	AssetId              Variable
	AssetAmount          Variable
	TreasuryAccountIndex Variable
	TreasuryFeeRate      Variable
	GasAccountIndex      Variable
	GasFeeAssetId        Variable
	GasFeeAssetAmount    Variable
}

func EmptyBuyNftTxWitness() (witness BuyNftTxConstraints) {
	witness = BuyNftTxConstraints{
		AccountIndex:         ZeroInt,
		OwnerAccountIndex:    ZeroInt,
		NftAssetId:           ZeroInt,
		NftIndex:             ZeroInt,
		NftContentHash:       ZeroInt,
		AssetId:              ZeroInt,
		AssetAmount:          ZeroInt,
		TreasuryAccountIndex: ZeroInt,
		TreasuryFeeRate:      ZeroInt,
		GasAccountIndex:      ZeroInt,
		GasFeeAssetId:        ZeroInt,
		GasFeeAssetAmount:    ZeroInt,
	}
	return witness
}

func SetBuyNftTxWitness(tx *BuyNftTx) (witness BuyNftTxConstraints) {
	witness = BuyNftTxConstraints{
		AccountIndex:         tx.AccountIndex,
		OwnerAccountIndex:    tx.OwnerAccountIndex,
		NftAssetId:           tx.NftAssetId,
		NftIndex:             tx.NftIndex,
		NftContentHash:       tx.NftContentHash,
		AssetId:              tx.AssetId,
		AssetAmount:          tx.AssetAmount,
		TreasuryAccountIndex: tx.TreasuryAccountIndex,
		TreasuryFeeRate:      tx.TreasuryFeeRate,
		GasAccountIndex:      tx.GasAccountIndex,
		GasFeeAssetId:        tx.GasFeeAssetId,
		GasFeeAssetAmount:    tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromBuyNftTx(tx BuyNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.AccountIndex,
		tx.OwnerAccountIndex,
		tx.NftAssetId,
		tx.NftIndex,
		tx.NftContentHash,
		tx.AssetId,
		tx.AssetAmount,
		tx.TreasuryAccountIndex,
		tx.TreasuryFeeRate,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyBuyNftTx:
	accounts order is:
	- BuyerAccount
		- Assets
			- AssetA
			- AssetGas
		- Nft
			- empty
	- OwnerAccount
		- Nft
			- nft index
	- TreasuryAccount
		- Assets
			- AssetA
	- GasAccount
		- Assets
			- AssetGas
*/
func VerifyBuyNftTx(api API, flag Variable, nilHash Variable, tx BuyNftTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// from account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	// owner account index
	IsVariableEqual(api, flag, tx.OwnerAccountIndex, accountsBefore[1].AccountIndex)
	// treasury account index
	IsVariableEqual(api, flag, tx.TreasuryAccountIndex, accountsBefore[2].AccountIndex)
	// nft index
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[1].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsAfter[0].NftInfo.NftIndex)
	// buyer nft should be empty
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftContentHash, nilHash)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetAmount, DefaultInt)
	// owner nft asset id and amount
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[1].NftInfo.AssetId)
	IsVariableEqual(api, flag, tx.AssetAmount, accountsBefore[1].NftInfo.AssetAmount)
	// treasury asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	// gas
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[3].AccountIndex)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[3].AssetsInfo[0].AssetId)
	// should have enough assets
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

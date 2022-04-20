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

type MintNftTx struct {
	/*
		- creator account index
		- to account index
		- nft token id
		- nft content hash
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
	*/
	CreatorAccountIndex uint32
	ToAccountIndex      uint32
	NftAccountIndex     uint32
	NftIndex            uint32
	NftContentHash      string
	AssetId             uint32
	AssetAmount         uint64
	GasAccountIndex     uint32
	GasFeeAssetId       uint32
	GasFeeAssetAmount   uint64
}

type MintNftTxConstraints struct {
	CreatorAccountIndex Variable
	ToAccountIndex      Variable
	NftAccountIndex     Variable
	NftIndex            Variable
	NftContentHash      Variable
	GasAccountIndex     Variable
	GasFeeAssetId       Variable
	GasFeeAssetAmount   Variable
}

func EmptyMintNftTxWitness() (witness MintNftTxConstraints) {
	return MintNftTxConstraints{
		CreatorAccountIndex: ZeroInt,
		ToAccountIndex:      ZeroInt,
		NftAccountIndex:     ZeroInt,
		NftIndex:            ZeroInt,
		NftContentHash:      ZeroInt,
		GasAccountIndex:     ZeroInt,
		GasFeeAssetId:       ZeroInt,
		GasFeeAssetAmount:   ZeroInt,
	}
}

func SetMintNftTxWitness(tx *MintNftTx) (witness MintNftTxConstraints) {
	witness = MintNftTxConstraints{
		CreatorAccountIndex: tx.CreatorAccountIndex,
		ToAccountIndex:      tx.ToAccountIndex,
		NftAccountIndex:     tx.NftAccountIndex,
		NftIndex:            tx.NftIndex,
		NftContentHash:      tx.NftContentHash,
		GasAccountIndex:     tx.GasAccountIndex,
		GasFeeAssetId:       tx.GasFeeAssetId,
		GasFeeAssetAmount:   tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromMintNftTx(tx MintNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.CreatorAccountIndex,
		tx.ToAccountIndex,
		tx.NftAccountIndex,
		tx.NftIndex,
		tx.NftContentHash,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyMintNftTx:
	accounts order is:
	- FromAccount
		- Assets
			- AssetGas
		- Nft
			- empty
	- ToAccount
		- Nft
			- empty
	- GasAccount
		- Assets
			- AssetGas
*/
func VerifyMintNftTx(api API, flag Variable, nilHash Variable, tx MintNftTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// nft index
	IsVariableEqual(api, flag, tx.NftAccountIndex, accountsBefore[0].NftInfo.NftAccountIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsAfter[1].NftInfo.NftIndex)
	// before account nft should be empty
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftIndex, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftContentHash, nilHash)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetAmount, DefaultInt)
	// new nft info should be right
	IsVariableEqual(api, flag, tx.NftContentHash, accountsAfter[1].NftInfo.NftContentHash)
	// from account index
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[1].AccountIndex)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	// should have enough balance
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

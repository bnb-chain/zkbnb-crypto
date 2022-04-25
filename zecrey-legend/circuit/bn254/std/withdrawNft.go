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

type WithdrawNftTx struct {
	/*
		- account index
		- nft token id
		- to address
		- proxy address
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- nonce
	*/
	AccountIndex      uint32
	NftAssetId        uint32
	NftIndex          uint32
	NftContentHash    []byte
	ToAddress         string
	ProxyAddress      string
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
}

type WithdrawNftTxConstraints struct {
	AccountIndex      Variable
	NftAssetId        Variable
	NftIndex          Variable
	NftContentHash    Variable
	ToAddress         Variable
	ProxyAddress      Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyWithdrawNftTxWitness() (witness WithdrawNftTxConstraints) {
	return WithdrawNftTxConstraints{
		AccountIndex:      ZeroInt,
		NftAssetId:        ZeroInt,
		NftIndex:          ZeroInt,
		NftContentHash:    ZeroInt,
		ToAddress:         ZeroInt,
		ProxyAddress:      ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetWithdrawNftTxWitness(tx *WithdrawNftTx) (witness WithdrawNftTxConstraints) {
	witness = WithdrawNftTxConstraints{
		AccountIndex:      tx.AccountIndex,
		NftAssetId:        tx.NftAssetId,
		NftIndex:          tx.NftIndex,
		NftContentHash:    tx.NftContentHash,
		ToAddress:         tx.ToAddress,
		ProxyAddress:      tx.ProxyAddress,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromWithdrawNftTx(tx WithdrawNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.AccountIndex,
		tx.NftAssetId,
		tx.NftIndex,
		tx.NftContentHash,
		tx.ToAddress,
		tx.ProxyAddress,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyWithdrawNftTx:
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
func VerifyWithdrawNftTx(api API, flag Variable, nilHash Variable, tx WithdrawNftTxConstraints, accountsBefore [NbAccountsPerTx]AccountConstraints) {
	// verify params
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	// gas
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// should confirm if the user owns the nft
	IsVariableEqual(api, flag, tx.NftAssetId, accountsBefore[0].NftInfo.NftAssetId)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftContentHash)
	// have enough assets
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

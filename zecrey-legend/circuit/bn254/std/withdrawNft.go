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
	AccountIndex      int64
	NftIndex          int64
	NftContentHash    []byte
	NftL1Address      string
	NftL1TokenId      *big.Int
	ToAddress         string
	ProxyAddress      string
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
}

type WithdrawNftTxConstraints struct {
	AccountIndex      Variable
	NftIndex          Variable
	NftContentHash    Variable
	NftL1Address      Variable
	NftL1TokenId      Variable
	ToAddress         Variable
	ProxyAddress      Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyWithdrawNftTxWitness() (witness WithdrawNftTxConstraints) {
	return WithdrawNftTxConstraints{
		AccountIndex:      ZeroInt,
		NftIndex:          ZeroInt,
		NftContentHash:    ZeroInt,
		NftL1Address:      ZeroInt,
		NftL1TokenId:      ZeroInt,
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
		NftIndex:          tx.NftIndex,
		NftContentHash:    tx.NftContentHash,
		NftL1Address:      tx.NftL1Address,
		NftL1TokenId:      tx.NftL1TokenId,
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
		tx.NftIndex,
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
func VerifyWithdrawNftTx(
	api API,
	flag Variable,
	tx *WithdrawNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromWithdrawNft(api, flag, *tx, hFunc)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.AccountIndex, nftBefore.OwnerAccountIndex)
	// have enough assets
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

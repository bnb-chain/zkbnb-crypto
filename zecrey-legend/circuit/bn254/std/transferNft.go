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
	FromAccountIndex  int64
	ToAccountIndex    int64
	NftIndex          int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	CallDataHash      []byte
}

type TransferNftTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	NftIndex          Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	CallDataHash      Variable
}

func EmptyTransferNftTxWitness() (witness TransferNftTxConstraints) {
	return TransferNftTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		NftIndex:          ZeroInt,
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
		NftIndex:          tx.NftIndex,
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
		tx.NftIndex,
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
func VerifyTransferNftTx(
	api API,
	flag Variable,
	tx TransferNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) {
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.FromAccountIndex, nftBefore.OwnerAccountIndex)
	// should have enough balance
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
}

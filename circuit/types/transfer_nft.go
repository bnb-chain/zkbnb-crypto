/*
 * Copyright © 2022 ZkBNB Protocol
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

package types

import "github.com/consensys/gnark/std/hash/poseidon"

type TransferNftTx struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	ToAccountNameHash []byte
	NftIndex          int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	CallDataHash      []byte
}

type TransferNftTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	ToAccountNameHash Variable
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
		ToAccountNameHash: ZeroInt,
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
		ToAccountNameHash: tx.ToAccountNameHash,
		NftIndex:          tx.NftIndex,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		CallDataHash:      tx.CallDataHash,
	}
	return witness
}

func ComputeHashFromTransferNftTx(api API, tx TransferNftTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeTransferNft, tx.FromAccountIndex, nonce, expiredAt, tx.GasFeeAssetId,
		tx.GasFeeAssetAmount, tx.ToAccountIndex, tx.NftIndex, tx.ToAccountNameHash, tx.CallDataHash)
}

func VerifyTransferNftTx(
	api API,
	flag Variable,
	tx *TransferNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	toAccount := 1
	pubData = CollectPubDataFromTransferNft(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[toAccount].AccountIndex)
	// account name
	IsVariableEqual(api, flag, tx.ToAccountNameHash, accountsBefore[toAccount].AccountNameHash)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.FromAccountIndex, nftBefore.OwnerAccountIndex)
	// should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData
}

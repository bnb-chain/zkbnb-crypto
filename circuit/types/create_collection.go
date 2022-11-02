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

type CreateCollectionTx struct {
	AccountIndex      int64
	CollectionId      int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	ExpiredAt         int64
	Nonce             int64
}

type CreateCollectionTxConstraints struct {
	AccountIndex      Variable
	CollectionId      Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	ExpiredAt         Variable
	Nonce             Variable
}

func EmptyCreateCollectionTxWitness() (witness CreateCollectionTxConstraints) {
	return CreateCollectionTxConstraints{
		AccountIndex:      ZeroInt,
		CollectionId:      ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
		ExpiredAt:         ZeroInt,
		Nonce:             ZeroInt,
	}
}

func SetCreateCollectionTxWitness(tx *CreateCollectionTx) (witness CreateCollectionTxConstraints) {
	witness = CreateCollectionTxConstraints{
		AccountIndex:      tx.AccountIndex,
		CollectionId:      tx.CollectionId,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		ExpiredAt:         tx.ExpiredAt,
		Nonce:             tx.Nonce,
	}
	return witness
}

func ComputeHashFromCreateCollectionTx(api API, tx CreateCollectionTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeCreateCollection, tx.AccountIndex, nonce, expiredAt, tx.GasFeeAssetId, tx.GasFeeAssetAmount)
}

func VerifyCreateCollectionTx(
	api API, flag Variable,
	tx *CreateCollectionTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	pubData = CollectPubDataFromCreateCollection(api, *tx)
	// verify params
	IsVariableLessOrEqual(api, flag, tx.CollectionId, 65535)
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	// collection id
	IsVariableEqual(api, flag, tx.CollectionId, accountsBefore[fromAccount].CollectionNonce)
	// should have enough assets
	tx.GasFeeAssetAmount = UnpackAmount(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData
}

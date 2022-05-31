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

func ComputeHashFromCreateCollectionTx(tx CreateCollectionTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.AccountIndex,
		tx.CollectionId,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		expiredAt,
		nonce,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyCreateCollectionTx(
	api API, flag Variable,
	tx *CreateCollectionTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataSizePerTx]Variable) {
	pubData = CollectPubDataFromCreateCollection(api, *tx)
	// verify params
	IsVariableLessOrEqual(api, flag, tx.CollectionId, 65535)
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// collection id
	IsVariableEqual(api, flag, tx.CollectionId, api.Add(accountsBefore[0].CollectionNonce, 1))
	// should have enough assets
	tx.GasFeeAssetAmount = UnpackAmount(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
	return pubData
}

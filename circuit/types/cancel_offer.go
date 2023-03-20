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

type CancelOfferTx struct {
	AccountIndex      int64
	OfferId           int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type CancelOfferTxConstraints struct {
	AccountIndex      Variable
	OfferId           Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyCancelOfferTxWitness() (witness CancelOfferTxConstraints) {
	return CancelOfferTxConstraints{
		AccountIndex:      ZeroInt,
		OfferId:           ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetCancelOfferTxWitness(tx *CancelOfferTx) (witness CancelOfferTxConstraints) {
	witness = CancelOfferTxConstraints{
		AccountIndex:      tx.AccountIndex,
		OfferId:           tx.OfferId,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromCancelOfferTx(api API, tx CancelOfferTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeCancelOffer, tx.AccountIndex, nonce, expiredAt, tx.GasFeeAssetId, tx.GasFeeAssetAmount, tx.OfferId)
}

func VerifyCancelOfferTx(
	api API, flag Variable,
	tx *CancelOfferTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	pubData = CollectPubDataFromCancelOffer(api, *tx)
	// verify params
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	offerIdBits := api.ToBinary(tx.OfferId, 24)
	assetId := api.FromBinary(offerIdBits[7:]...)
	IsVariableEqual(api, flag, assetId, accountsBefore[fromAccount].AssetsInfo[1].AssetId)
	// should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData
}

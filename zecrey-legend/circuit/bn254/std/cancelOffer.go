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

type CancelOfferTx struct {
	AccountIndex      int64
	OfferId           int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
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

func ComputeHashFromCancelOfferTx(tx CancelOfferTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.AccountIndex,
		tx.OfferId,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		nonce,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyCancelOfferTx(
	api API, flag Variable,
	tx *CancelOfferTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromCancelOffer(api, flag, *tx, hFunc)
	// verify params
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	offerId, _ := api.Compiler().ConstantValue(tx.OfferId)
	if offerId == nil {
		offerId = big.NewInt(0)
	}
	assetId := new(big.Int).Div(offerId, big.NewInt(128))
	IsVariableEqual(api, flag, assetId, accountsBefore[0].AssetsInfo[0].AssetId)
	// should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[1].Balance)
}

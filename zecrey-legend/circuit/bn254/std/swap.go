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

type SwapTx struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAAmount      int64
	AssetBId          int64
	AssetBMinAmount   int64
	AssetBAmountDelta int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type SwapTxConstraints struct {
	FromAccountIndex  Variable
	PairIndex         Variable
	AssetAId          Variable
	AssetAAmount      Variable
	AssetBId          Variable
	AssetBMinAmount   Variable
	AssetBAmountDelta Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptySwapTxWitness() (witness SwapTxConstraints) {
	return SwapTxConstraints{
		FromAccountIndex:  ZeroInt,
		PairIndex:         ZeroInt,
		AssetAId:          ZeroInt,
		AssetAAmount:      ZeroInt,
		AssetBId:          ZeroInt,
		AssetBMinAmount:   ZeroInt,
		AssetBAmountDelta: ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetSwapTxWitness(tx *SwapTx) (witness SwapTxConstraints) {
	witness = SwapTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		PairIndex:         tx.PairIndex,
		AssetAId:          tx.AssetAId,
		AssetAAmount:      tx.AssetAAmount,
		AssetBId:          tx.AssetBId,
		AssetBMinAmount:   tx.AssetBMinAmount,
		AssetBAmountDelta: tx.AssetBAmountDelta,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromSwapTx(tx SwapTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.PairIndex,
		tx.AssetAAmount,
		tx.AssetBMinAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		expiredAt,
		nonce,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifySwapTx(
	api API, flag Variable,
	tx *SwapTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints,
) (pubData [PubDataSizePerTx]Variable) {
	pubData = CollectPubDataFromSwap(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// pair index
	IsVariableEqual(api, flag, tx.PairIndex, liquidityBefore.PairIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	isSameAsset := api.IsZero(
		api.And(
			api.IsZero(api.Sub(tx.AssetAId, liquidityBefore.AssetAId)),
			api.IsZero(api.Sub(tx.AssetBId, liquidityBefore.AssetBId)),
		),
	)
	isDifferentAsset := api.IsZero(
		api.And(
			api.IsZero(api.Sub(tx.AssetAId, liquidityBefore.AssetBId)),
			api.IsZero(api.Sub(tx.AssetBId, liquidityBefore.AssetAId)),
		),
	)
	IsVariableEqual(
		api, flag,
		api.Or(
			isSameAsset,
			isDifferentAsset,
		),
		1,
	)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[2].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// should have enough assets
	tx.AssetAAmount = UnpackAmount(api, tx.AssetAAmount)
	tx.AssetBMinAmount = UnpackAmount(api, tx.AssetBMinAmount)
	tx.AssetBAmountDelta = UnpackAmount(api, tx.AssetBAmountDelta)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetBMinAmount, tx.AssetBAmountDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetAAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[2].Balance)
	// pool info
	isSameAsset = api.And(flag, isSameAsset)
	isDifferentAsset = api.And(flag, isSameAsset)
	IsVariableEqual(api, flag, liquidityBefore.FeeRate, liquidityBefore.FeeRate)
	IsVariableLessOrEqual(api, flag, liquidityBefore.FeeRate, RateBase)
	assetAAmount := api.Select(isSameAsset, tx.AssetAAmount, tx.AssetBAmountDelta)
	assetBAmount := api.Select(isSameAsset, tx.AssetBAmountDelta, tx.AssetAAmount)
	// verify AMM
	r := api.Mul(api.Mul(liquidityBefore.AssetA, liquidityBefore.AssetB), RateBase)
	l := api.Mul(
		api.Sub(
			api.Mul(RateBase, api.Add(assetAAmount, liquidityBefore.AssetA)),
			api.Mul(liquidityBefore.FeeRate, assetAAmount),
		),
		api.Add(assetBAmount, liquidityBefore.AssetB),
	)
	IsVariableLessOrEqual(api, flag, r, l)
	return pubData
}

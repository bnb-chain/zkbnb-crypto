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

type RemoveLiquidityTx struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAMinAmount   int64
	AssetBId          int64
	AssetBMinAmount   int64
	LpAmount          int64
	KLast             int64
	TreasuryAmount    int64
	AssetAAmountDelta int64
	AssetBAmountDelta int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type RemoveLiquidityTxConstraints struct {
	FromAccountIndex  Variable
	PairIndex         Variable
	AssetAId          Variable
	AssetAMinAmount   Variable
	AssetBId          Variable
	AssetBMinAmount   Variable
	LpAmount          Variable
	KLast             Variable
	TreasuryAmount    Variable
	AssetAAmountDelta Variable
	AssetBAmountDelta Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyRemoveLiquidityTxWitness() (witness RemoveLiquidityTxConstraints) {
	return RemoveLiquidityTxConstraints{
		FromAccountIndex:  ZeroInt,
		PairIndex:         ZeroInt,
		AssetAId:          ZeroInt,
		AssetAMinAmount:   ZeroInt,
		AssetBId:          ZeroInt,
		AssetBMinAmount:   ZeroInt,
		LpAmount:          ZeroInt,
		KLast:             ZeroInt,
		TreasuryAmount:    ZeroInt,
		AssetAAmountDelta: ZeroInt,
		AssetBAmountDelta: ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetRemoveLiquidityTxWitness(tx *RemoveLiquidityTx) (witness RemoveLiquidityTxConstraints) {
	witness = RemoveLiquidityTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		PairIndex:         tx.PairIndex,
		AssetAId:          tx.AssetAId,
		AssetAMinAmount:   tx.AssetAMinAmount,
		AssetBId:          tx.AssetBId,
		AssetBMinAmount:   tx.AssetBMinAmount,
		LpAmount:          tx.LpAmount,
		KLast:             tx.KLast,
		TreasuryAmount:    tx.TreasuryAmount,
		AssetAAmountDelta: tx.AssetAAmountDelta,
		AssetBAmountDelta: tx.AssetBAmountDelta,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromRemoveLiquidityTx(tx RemoveLiquidityTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.PairIndex,
		tx.AssetAMinAmount,
		tx.AssetBMinAmount,
		tx.LpAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		expiredAt,
		nonce,
		ChainId,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyRemoveLiquidityTx(
	api API, flag Variable,
	tx *RemoveLiquidityTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints,
) (pubData [PubDataSizePerTx]Variable, err error) {
	pubData = CollectPubDataFromRemoveLiquidity(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, liquidityBefore.TreasuryAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[2].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[2].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetAId, liquidityBefore.AssetAId)
	IsVariableEqual(api, flag, tx.AssetBId, liquidityBefore.AssetBId)
	// should have enough lp
	IsVariableLessOrEqual(api, flag, tx.LpAmount, accountsBefore[0].AssetsInfo[3].LpAmount)
	// enough balance
	tx.AssetAMinAmount = UnpackAmount(api, tx.AssetAMinAmount)
	tx.AssetAAmountDelta = UnpackAmount(api, tx.AssetAAmountDelta)
	tx.AssetBMinAmount = UnpackAmount(api, tx.AssetBMinAmount)
	tx.AssetBAmountDelta = UnpackAmount(api, tx.AssetBAmountDelta)
	tx.LpAmount = UnpackAmount(api, tx.LpAmount)
	tx.TreasuryAmount = UnpackAmount(api, tx.TreasuryAmount)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[3].Balance)
	// TODO verify LP
	kCurrent := api.Mul(liquidityBefore.AssetA, liquidityBefore.AssetB)
	IsVariableLessOrEqual(api, flag, liquidityBefore.KLast, kCurrent)
	IsVariableLessOrEqual(api, flag, liquidityBefore.TreasuryRate, liquidityBefore.FeeRate)
	sLps, err := api.Compiler().NewHint(ComputeSLp, 1, liquidityBefore.AssetA, liquidityBefore.AssetB, liquidityBefore.KLast, liquidityBefore.FeeRate, liquidityBefore.TreasuryRate)
	if err != nil {
		return pubData, err
	}
	sLp := sLps[0]
	IsVariableEqual(api, flag, tx.TreasuryAmount, sLp)
	poolLpVar := api.Sub(liquidityBefore.LpAmount, sLp)
	IsVariableLessOrEqual(api, flag, api.Mul(tx.AssetAAmountDelta, poolLpVar), api.Mul(tx.LpAmount, liquidityBefore.AssetA))
	IsVariableLessOrEqual(api, flag, api.Mul(tx.AssetBAmountDelta, poolLpVar), api.Mul(tx.LpAmount, liquidityBefore.AssetB))
	IsVariableLessOrEqual(api, flag, tx.AssetAMinAmount, tx.AssetAAmountDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetBMinAmount, tx.AssetBAmountDelta)
	return pubData, nil
}

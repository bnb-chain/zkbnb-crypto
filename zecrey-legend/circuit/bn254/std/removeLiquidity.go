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

import (
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"math/big"
)

type RemoveLiquidityTx struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAMinAmount   int64
	AssetBId          int64
	AssetBMinAmount   int64
	LpAmount          int64
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
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyRemoveLiquidityTx(
	api API, flag Variable,
	tx *RemoveLiquidityTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromRemoveLiquidity(api, flag, *tx, hFunc)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[3].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetAId, liquidityBefore.AssetAId)
	IsVariableEqual(api, flag, tx.AssetBId, liquidityBefore.AssetBId)
	// should have enough lp
	IsVariableLessOrEqual(api, flag, tx.LpAmount, accountsBefore[0].AssetsInfo[2].LpAmount)
	// enough balance
	tx.AssetAMinAmount = UnpackAmount(api, tx.AssetAMinAmount)
	tx.AssetAAmountDelta = UnpackAmount(api, tx.AssetAAmountDelta)
	tx.AssetBMinAmount = UnpackAmount(api, tx.AssetBMinAmount)
	tx.AssetBAmountDelta = UnpackAmount(api, tx.AssetBAmountDelta)
	tx.LpAmount = UnpackAmount(api, tx.LpAmount)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[3].Balance)
	// TODO verify LP
	sLp := ComputeSLp(api, flag, liquidityBefore.AssetA, liquidityBefore.AssetB, liquidityBefore.KLast, liquidityBefore.FeeRate, liquidityBefore.TreasuryRate)
	poolLpVar := api.Sub(liquidityBefore.LpAmount, sLp)
	assetA, _ := api.Compiler().ConstantValue(liquidityBefore.AssetA)
	if assetA == nil {
		assetA = big.NewInt(0)
	}
	assetB, _ := api.Compiler().ConstantValue(liquidityBefore.AssetB)
	if assetB == nil {
		assetB = big.NewInt(0)
	}
	lpAmount, _ := api.Compiler().ConstantValue(tx.LpAmount)
	if lpAmount == nil {
		lpAmount = big.NewInt(0)
	}
	poolLp, _ := api.Compiler().ConstantValue(poolLpVar)
	if poolLp == nil {
		poolLp = big.NewInt(0)
	}
	var (
		assetADelta, assetBDelta *big.Int
	)
	if poolLp.Cmp(big.NewInt(0)) == 0 {
		assetADelta = big.NewInt(0)
		assetBDelta = big.NewInt(0)
	} else {
		assetADelta = ffmath.Div(ffmath.Multiply(lpAmount, assetA), poolLp)
		assetBDelta = ffmath.Div(ffmath.Multiply(lpAmount, assetB), poolLp)
	}
	IsVariableEqual(api, flag, tx.AssetAAmountDelta, assetADelta)
	IsVariableEqual(api, flag, tx.AssetBAmountDelta, assetBDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetAMinAmount, tx.AssetAAmountDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetBMinAmount, tx.AssetBAmountDelta)
}

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
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
)

type AddLiquidityTx struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAAmount      int64
	AssetBId          int64
	AssetBAmount      int64
	LpAmount          int64
	KLast             int64
	TreasuryAmount    int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type AddLiquidityTxConstraints struct {
	FromAccountIndex  Variable
	PairIndex         Variable
	AssetAId          Variable
	AssetAAmount      Variable
	AssetBId          Variable
	AssetBAmount      Variable
	LpAmount          Variable
	KLast             Variable
	TreasuryAmount    Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyAddLiquidityTxWitness() (witness AddLiquidityTxConstraints) {
	witness = AddLiquidityTxConstraints{
		FromAccountIndex:  ZeroInt,
		PairIndex:         ZeroInt,
		AssetAId:          ZeroInt,
		AssetAAmount:      ZeroInt,
		AssetBId:          ZeroInt,
		AssetBAmount:      ZeroInt,
		LpAmount:          ZeroInt,
		KLast:             ZeroInt,
		TreasuryAmount:    ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
	return witness
}

func SetAddLiquidityTxWitness(tx *AddLiquidityTx) (witness AddLiquidityTxConstraints) {
	witness = AddLiquidityTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		PairIndex:         tx.PairIndex,
		AssetAId:          tx.AssetAId,
		AssetAAmount:      tx.AssetAAmount,
		AssetBId:          tx.AssetBId,
		AssetBAmount:      tx.AssetBAmount,
		LpAmount:          tx.LpAmount,
		KLast:             tx.KLast,
		TreasuryAmount:    tx.TreasuryAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromAddLiquidityTx(tx AddLiquidityTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.PairIndex,
		tx.AssetAAmount,
		tx.AssetBAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		expiredAt,
		nonce,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyAddLiquidityTx(
	api API, flag Variable,
	tx *AddLiquidityTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints,
) (pubData [PubDataSizePerTx]Variable, err error) {
	pubData = CollectPubDataFromAddLiquidity(api, *tx)
	// check params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, liquidityBefore.TreasuryAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[2].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.AssetAId, liquidityBefore.AssetAId)
	IsVariableEqual(api, flag, tx.AssetBId, liquidityBefore.AssetBId)
	IsVariableEqual(api, flag, tx.PairIndex, accountsBefore[1].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[2].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	IsVariableLessOrEqual(api, flag, 0, tx.AssetAAmount)
	IsVariableLessOrEqual(api, flag, 0, tx.AssetBAmount)
	// check if the user has enough balance
	tx.AssetAAmount = UnpackAmount(api, tx.AssetAAmount)
	tx.AssetBAmount = UnpackAmount(api, tx.AssetBAmount)
	tx.LpAmount = UnpackAmount(api, tx.LpAmount)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.AssetBAmount, accountsBefore[0].AssetsInfo[1].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[2].Balance)
	// verify treasury amount
	kCurrent := api.Mul(liquidityBefore.AssetA, liquidityBefore.AssetB)
	IsVariableLessOrEqual(api, flag, liquidityBefore.KLast, kCurrent)
	IsVariableLessOrEqual(api, flag, liquidityBefore.TreasuryRate, liquidityBefore.FeeRate)
	sLps, err := api.Compiler().NewHint(ComputeSLp, 1, liquidityBefore.AssetA, liquidityBefore.AssetB, liquidityBefore.KLast, liquidityBefore.FeeRate, liquidityBefore.TreasuryRate)
	if err != nil {
		return pubData, err
	}
	sLp := sLps[0]
	IsVariableEqual(api, flag, tx.TreasuryAmount, sLp)
	// TODO verify ratio
	l := api.Mul(liquidityBefore.AssetA, tx.AssetBAmount)
	r := api.Mul(liquidityBefore.AssetB, tx.AssetAAmount)
	maxDelta := std.Max(api, liquidityBefore.AssetA, liquidityBefore.AssetB)
	l = std.Max(api, l, r)
	r = std.Min(api, l, r)
	lrDelta := api.Sub(l, r)
	IsVariableLessOrEqual(api, flag, lrDelta, maxDelta)
	// TODO verify lp amount
	isZero := api.IsZero(liquidityBefore.AssetA)
	isZero = api.And(isZero, flag)
	lpAmountSquare := api.Mul(tx.AssetAAmount, tx.AssetBAmount)
	IsVariableLessOrEqual(api, isZero, api.Mul(tx.LpAmount, tx.LpAmount), lpAmountSquare)
	notZero := api.IsZero(isZero)
	IsVariableEqual(api, notZero, api.Mul(tx.LpAmount, liquidityBefore.AssetA), api.Mul(tx.AssetAAmount, liquidityBefore.LpAmount))
	return pubData, nil
}

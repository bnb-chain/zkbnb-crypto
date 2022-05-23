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
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
	"math/big"
)

type AddLiquidityTx struct {
	/*
		- from account index
		- to account index
		- pair index
		- asset a id
		- asset a amount
		- asset b id
		- asset b amount
		- gas account index
		- gas fee asset id
		- gas fee amount
		- nonce
	*/
	FromAccountIndex     int64
	PairIndex            int64
	AssetAId             int64
	AssetAAmount         int64
	AssetBId             int64
	AssetBAmount         int64
	LpAmount             int64
	PoolAAmount          *big.Int
	PoolBAmount          *big.Int
	TreasuryAccountIndex int64
	TreasuryRate         int64
	GasAccountIndex      int64
	GasFeeAssetId        int64
	GasFeeAssetAmount    int64
}

type AddLiquidityTxConstraints struct {
	FromAccountIndex     Variable
	PairIndex            Variable
	AssetAId             Variable
	AssetAAmount         Variable
	AssetBId             Variable
	AssetBAmount         Variable
	LpAmount             Variable
	PoolAAmount          Variable
	PoolBAmount          Variable
	TreasuryAccountIndex Variable
	TreasuryRate         Variable
	GasAccountIndex      Variable
	GasFeeAssetId        Variable
	GasFeeAssetAmount    Variable
}

func EmptyAddLiquidityTxWitness() (witness AddLiquidityTxConstraints) {
	witness = AddLiquidityTxConstraints{
		FromAccountIndex:     ZeroInt,
		PairIndex:            ZeroInt,
		AssetAId:             ZeroInt,
		AssetAAmount:         ZeroInt,
		AssetBId:             ZeroInt,
		AssetBAmount:         ZeroInt,
		LpAmount:             ZeroInt,
		PoolAAmount:          ZeroInt,
		PoolBAmount:          ZeroInt,
		TreasuryAccountIndex: ZeroInt,
		TreasuryRate:         ZeroInt,
		GasAccountIndex:      ZeroInt,
		GasFeeAssetId:        ZeroInt,
		GasFeeAssetAmount:    ZeroInt,
	}
	return witness
}

func SetAddLiquidityTxWitness(tx *AddLiquidityTx) (witness AddLiquidityTxConstraints) {
	witness = AddLiquidityTxConstraints{
		FromAccountIndex:     tx.FromAccountIndex,
		PairIndex:            tx.PairIndex,
		AssetAId:             tx.AssetAId,
		AssetAAmount:         tx.AssetAAmount,
		AssetBId:             tx.AssetBId,
		AssetBAmount:         tx.AssetBAmount,
		LpAmount:             tx.LpAmount,
		PoolAAmount:          tx.PoolAAmount,
		PoolBAmount:          tx.PoolBAmount,
		TreasuryAccountIndex: tx.TreasuryAccountIndex,
		TreasuryRate:         tx.TreasuryRate,
		GasAccountIndex:      tx.GasAccountIndex,
		GasFeeAssetId:        tx.GasFeeAssetId,
		GasFeeAssetAmount:    tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromAddLiquidityTx(tx AddLiquidityTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.PairIndex,
		tx.AssetAId,
		tx.AssetAAmount,
		tx.AssetBId,
		tx.AssetBAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyAddLiquidityTx:
	accounts order is:
	- FromAccount
		- Assets:
			- AssetA
			- AssetB
			- LpAmount
			- AssetGas
	- GasAccount
		- Assets
			- AssetGas
	- FromAccount
		- Assets
			- AssetA
			- AssetB
			- AssetGas
*/
func VerifyAddLiquidityTx(
	api API, flag Variable,
	tx *AddLiquidityTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromAddLiquidity(api, flag, *tx, hFunc)
	// check params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.TreasuryAccountIndex, accountsBefore[1].AccountIndex)
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
	IsVariableEqual(api, flag, tx.PoolAAmount, liquidityBefore.AssetA)
	IsVariableEqual(api, flag, tx.PoolBAmount, liquidityBefore.AssetB)
	// TODO verify ratio
	deltaXVar := std.Max(api, tx.AssetAAmount, tx.AssetBAmount)
	deltaYVar := std.Min(api, tx.AssetAAmount, tx.AssetBAmount)
	poolXVar := std.Max(api, tx.PoolAAmount, tx.PoolBAmount)
	poolYVar := std.Min(api, tx.PoolAAmount, tx.PoolBAmount)
	deltaX, _ := api.Compiler().ConstantValue(deltaXVar)
	if deltaX == nil {
		deltaX = big.NewInt(0)
	}
	deltaY, _ := api.Compiler().ConstantValue(deltaYVar)
	if deltaY == nil {
		deltaY = big.NewInt(0)
	}
	poolX, _ := api.Compiler().ConstantValue(poolXVar)
	if poolX == nil {
		poolX = big.NewInt(0)
	}
	poolY, _ := api.Compiler().ConstantValue(poolYVar)
	if poolY == nil {
		poolY = big.NewInt(0)
	}
	var (
		l, r *big.Int
	)
	if deltaY.Cmp(big.NewInt(0)) == 0 {
		l = big.NewInt(0)
	} else {
		l = ffmath.Div(deltaX, deltaY)
	}
	if poolY.Cmp(big.NewInt(0)) == 0 {
		r = big.NewInt(0)
	} else {
		r = ffmath.Div(poolX, poolY)
	}
	var (
		ratio Variable
	)
	if r.Cmp(big.NewInt(0)) == 0 {
		ratio = 1
	} else if l.String() == r.String() {
		ratio = 1
	} else {
		ratio = 0
	}
	IsVariableEqual(api, flag, ratio, 1)
	// compute real lp
	sLp := ComputeSLp(api, flag, tx.PoolAAmount, tx.PoolBAmount, liquidityBefore.KLast, liquidityBefore.FeeRate, tx.TreasuryRate)
	poolLp := api.Sub(liquidityBefore.LpAmount, sLp)
	l, _ = api.Compiler().ConstantValue(api.Mul(poolLp, tx.AssetAAmount))
	if l == nil {
		l = big.NewInt(0)
	}
	r, _ = api.Compiler().ConstantValue(tx.PoolAAmount)
	if r == nil {
		r = big.NewInt(0)
	}
	var lpAmountCheck *big.Int
	if r.Cmp(big.NewInt(0)) == 0 {
		lpAmountCheck = big.NewInt(0)
	} else {
		lpAmountCheck = ffmath.Div(l, r)
	}
	IsVariableEqual(api, flag, tx.LpAmount, lpAmountCheck)
}

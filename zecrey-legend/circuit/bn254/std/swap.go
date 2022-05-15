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

type SwapTx struct {
	/*
		- from account index
		- to account index
		- pair index
		- asset a id
		- asset a amount
		- asset b id
		- asset b min amount
		- fee rate
		- treasury rate
		- gas account index
		- gas fee asset id
		- gas fee asset amount
	*/
	FromAccountIndex       int64
	PairIndex              int64
	AssetAId               int64
	AssetAAmount           int64
	AssetBId               int64
	AssetBMinAmount        int64
	AssetBAmountDelta      int64
	PoolAAmount            *big.Int
	PoolBAmount            *big.Int
	FeeRate                int64
	TreasuryAccountIndex   int64
	TreasuryRate           int64
	TreasuryFeeAmountDelta int64
	GasAccountIndex        int64
	GasFeeAssetId          int64
	GasFeeAssetAmount      int64
}

type SwapTxConstraints struct {
	FromAccountIndex       Variable
	PairIndex              Variable
	AssetAId               Variable
	AssetAAmount           Variable
	AssetBId               Variable
	AssetBMinAmount        Variable
	AssetBAmountDelta      Variable
	PoolAAmount            Variable
	PoolBAmount            Variable
	TreasuryFeeAmountDelta Variable
	FeeRate                Variable
	TreasuryAccountIndex   Variable
	TreasuryRate           Variable
	GasAccountIndex        Variable
	GasFeeAssetId          Variable
	GasFeeAssetAmount      Variable
}

func EmptySwapTxWitness() (witness SwapTxConstraints) {
	return SwapTxConstraints{
		FromAccountIndex:       ZeroInt,
		PairIndex:              ZeroInt,
		AssetAId:               ZeroInt,
		AssetAAmount:           ZeroInt,
		AssetBId:               ZeroInt,
		AssetBMinAmount:        ZeroInt,
		AssetBAmountDelta:      ZeroInt,
		PoolAAmount:            ZeroInt,
		PoolBAmount:            ZeroInt,
		TreasuryFeeAmountDelta: ZeroInt,
		FeeRate:                ZeroInt,
		TreasuryAccountIndex:   ZeroInt,
		TreasuryRate:           ZeroInt,
		GasAccountIndex:        ZeroInt,
		GasFeeAssetId:          ZeroInt,
		GasFeeAssetAmount:      ZeroInt,
	}
}

func SetSwapTxWitness(tx *SwapTx) (witness SwapTxConstraints) {
	witness = SwapTxConstraints{
		FromAccountIndex:       tx.FromAccountIndex,
		PairIndex:              tx.PairIndex,
		AssetAId:               tx.AssetAId,
		AssetAAmount:           tx.AssetAAmount,
		AssetBId:               tx.AssetBId,
		AssetBMinAmount:        tx.AssetBMinAmount,
		AssetBAmountDelta:      tx.AssetBAmountDelta,
		PoolAAmount:            tx.PoolAAmount,
		PoolBAmount:            tx.PoolBAmount,
		TreasuryFeeAmountDelta: tx.TreasuryFeeAmountDelta,
		FeeRate:                tx.FeeRate,
		TreasuryAccountIndex:   tx.TreasuryAccountIndex,
		TreasuryRate:           tx.TreasuryRate,
		GasAccountIndex:        tx.GasAccountIndex,
		GasFeeAssetId:          tx.GasFeeAssetId,
		GasFeeAssetAmount:      tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromSwapTx(tx SwapTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.PairIndex,
		tx.AssetAId,
		tx.AssetAAmount,
		tx.AssetBId,
		tx.AssetBMinAmount,
		tx.FeeRate,
		tx.TreasuryAccountIndex,
		tx.TreasuryRate,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifySwapTx:
	accounts order is:
	- FromAccount
		- Assets:
			- AssetA
			- AssetB
			- AssetGas
	- ToAccount
		- Liquidity
			- AssetA
			- AssetB
	- TreasuryAccount
		- Assets
			- AssetA
	- GasAccount
		- Assets:
			- AssetGas
*/
func VerifySwapTx(
	api API, flag Variable,
	tx *SwapTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromSwap(api, flag, *tx, hFunc)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.TreasuryAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[2].AccountIndex)
	// pair index
	IsVariableEqual(api, flag, tx.PairIndex, liquidityBefore.PairIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[1].AssetsInfo[0].AssetId)
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
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	// should have enough assets
	tx.AssetAAmount = UnpackAmount(api, tx.AssetAAmount)
	tx.AssetBMinAmount = UnpackAmount(api, tx.AssetBMinAmount)
	tx.AssetBAmountDelta = UnpackAmount(api, tx.AssetBAmountDelta)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	tx.TreasuryFeeAmountDelta = UnpackFee(api, tx.TreasuryFeeAmountDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetBMinAmount, tx.AssetBAmountDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetAAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[2].Balance)
	// pool info
	isSameAsset = api.And(flag, isSameAsset)
	isDifferentAsset = api.And(flag, isSameAsset)
	IsVariableLessOrEqual(api, isSameAsset, tx.PoolAAmount, liquidityBefore.AssetA)
	IsVariableLessOrEqual(api, isSameAsset, tx.PoolBAmount, liquidityBefore.AssetB)
	IsVariableLessOrEqual(api, isDifferentAsset, tx.PoolAAmount, liquidityBefore.AssetB)
	IsVariableLessOrEqual(api, isDifferentAsset, tx.PoolBAmount, liquidityBefore.AssetA)
	// verify AMM
	k := api.Mul(tx.PoolAAmount, tx.PoolBAmount)
	// TODO check treasury fee amount
	treasuryAmount := api.Div(api.Mul(tx.AssetAAmount, tx.TreasuryRate), 10000)
	IsVariableEqual(api, flag, tx.TreasuryFeeAmountDelta, treasuryAmount)
	poolADelta := api.Sub(tx.AssetAAmount, tx.TreasuryFeeAmountDelta)
	kPrime := api.Mul(api.Add(tx.PoolAAmount, poolADelta), api.Sub(tx.PoolBAmount, tx.AssetBAmountDelta))
	api.AssertIsLessOrEqual(k, kPrime)
}

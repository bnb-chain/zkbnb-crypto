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
	FromAccountIndex       uint32
	ToAccountIndex         uint32
	PairIndex              uint32
	AssetAId               uint32
	AssetAAmount           uint64
	AssetBId               uint32
	AssetBMinAmount        uint64
	AssetBAmountDelta      uint64
	PoolAAmount            uint64
	PoolBAmount            uint64
	FeeRate                uint32
	TreasuryAccountIndex   uint32
	TreasuryRate           uint32
	TreasuryFeeAmountDelta uint64
	GasAccountIndex        uint32
	GasFeeAssetId          uint32
	GasFeeAssetAmount      uint64
}

type SwapTxConstraints struct {
	FromAccountIndex       Variable
	ToAccountIndex         Variable
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
		ToAccountIndex:         ZeroInt,
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
		ToAccountIndex:         tx.ToAccountIndex,
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
		tx.ToAccountIndex,
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
func VerifySwapTx(api API, flag Variable, tx SwapTxConstraints, accountsBefore [NbAccountsPerTx]AccountConstraints) {
	// verify params
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.TreasuryAccountIndex, accountsBefore[2].AccountIndex)
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[1].LiquidityInfo.AssetAId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[1].LiquidityInfo.AssetBId)
	// gas
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[3].AccountIndex)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[3].AssetsInfo[0].AssetId)
	// should have enough assets
	isSameAsset := api.IsZero(api.Sub(tx.AssetAId, tx.GasFeeAssetId))
	totalDelta := api.Add(tx.AssetAAmount, tx.GasFeeAssetAmount)
	assetADelta := api.Select(isSameAsset, totalDelta, tx.AssetAAmount)
	assetFeeDelta := api.Select(isSameAsset, totalDelta, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAAmount, assetADelta)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, assetFeeDelta)
	IsVariableLessOrEqual(api, flag, tx.AssetBMinAmount, tx.AssetBAmountDelta)
	// verify AMM
	k := api.Mul(tx.PoolAAmount, tx.PoolBAmount)
	// TODO check treasury fee amount
	poolADelta := api.Sub(tx.AssetAAmount, tx.TreasuryFeeAmountDelta)
	kPrime := api.Mul(api.Add(tx.PoolAAmount, poolADelta), api.Sub(tx.PoolBAmount, tx.AssetBAmountDelta))
	api.AssertIsLessOrEqual(k, kPrime)

}

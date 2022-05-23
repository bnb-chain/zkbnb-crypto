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

package block

import "github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"

type LiquidityDeltaConstraints struct {
	AssetAId             Variable
	AssetBId             Variable
	AssetADelta          Variable
	AssetBDelta          Variable
	LpDelta              Variable
	KLast                Variable
	FeeRate              Variable
	TreasuryAccountIndex Variable
	TreasuryRate         Variable
}

func EmptyLiquidityDeltaConstraints() LiquidityDeltaConstraints {
	return LiquidityDeltaConstraints{
		AssetAId:             std.ZeroInt,
		AssetBId:             std.ZeroInt,
		AssetADelta:          std.ZeroInt,
		AssetBDelta:          std.ZeroInt,
		LpDelta:              std.ZeroInt,
		KLast:                std.ZeroInt,
		FeeRate:              std.ZeroInt,
		TreasuryAccountIndex: std.ZeroInt,
		TreasuryRate:         std.ZeroInt,
	}
}

func UpdateLiquidity(
	api API,
	liquidity LiquidityConstraints,
	liquidityDelta LiquidityDeltaConstraints,
) (liquidityAfter LiquidityConstraints) {
	liquidityAfter = liquidity
	liquidityAfter.AssetAId = liquidityDelta.AssetAId
	liquidityAfter.AssetBId = liquidityDelta.AssetBId
	liquidityAfter.AssetA = api.Add(liquidity.AssetA, liquidityDelta.AssetADelta)
	liquidityAfter.AssetB = api.Add(liquidity.AssetB, liquidityDelta.AssetBDelta)
	liquidityAfter.LpAmount = api.Add(liquidity.LpAmount, liquidityDelta.LpDelta)
	liquidityAfter.KLast = liquidityDelta.KLast
	liquidityAfter.FeeRate = liquidityDelta.FeeRate
	liquidityAfter.TreasuryAccountIndex = liquidityDelta.TreasuryAccountIndex
	liquidityAfter.TreasuryRate = liquidityDelta.TreasuryRate
	return liquidityAfter
}

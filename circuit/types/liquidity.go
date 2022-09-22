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

import (
	"math/big"
)

type Liquidity struct {
	PairIndex            int64
	AssetAId             int64
	AssetA               *big.Int
	AssetBId             int64
	AssetB               *big.Int
	LpAmount             *big.Int
	KLast                *big.Int
	FeeRate              int64
	TreasuryAccountIndex int64
	TreasuryRate         int64
}

func EmptyLiquidity(pairIndex int64) *Liquidity {
	zero := big.NewInt(0)
	return &Liquidity{
		PairIndex:            pairIndex,
		AssetAId:             0,
		AssetA:               zero,
		AssetBId:             0,
		AssetB:               zero,
		LpAmount:             zero,
		KLast:                zero,
		FeeRate:              0,
		TreasuryAccountIndex: 0,
		TreasuryRate:         0,
	}
}

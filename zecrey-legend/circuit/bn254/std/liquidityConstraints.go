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
	"errors"
	"log"
)

type LiquidityConstraints struct {
	PairIndex Variable
	AssetAId  Variable
	AssetA    Variable
	AssetBId  Variable
	AssetB    Variable
	LpAmount  Variable
}

func CheckEmptyLiquidityNode(api API, flag Variable, liquidity LiquidityConstraints) {
	IsVariableEqual(api, flag, liquidity.AssetAId, ZeroInt)
	IsVariableEqual(api, flag, liquidity.AssetA, ZeroInt)
	IsVariableEqual(api, flag, liquidity.AssetBId, ZeroInt)
	IsVariableEqual(api, flag, liquidity.AssetB, ZeroInt)
	IsVariableEqual(api, flag, liquidity.LpAmount, ZeroInt)
}

/*
	SetLiquidityWitness: set liquidity witness
*/
func SetLiquidityWitness(liquidity *Liquidity) (witness LiquidityConstraints, err error) {
	if liquidity == nil {
		log.Println("[SetLiquidityWitness] invalid params")
		return witness, errors.New("[SetLiquidityWitness] invalid params")
	}
	// set witness
	witness = LiquidityConstraints{
		PairIndex: liquidity.PairIndex,
		AssetAId:  liquidity.AssetAId,
		AssetA:    liquidity.AssetA,
		AssetBId:  liquidity.AssetBId,
		AssetB:    liquidity.AssetB,
		LpAmount:  liquidity.LpAmount,
	}
	return witness, nil
}

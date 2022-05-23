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

type UpdatePairRateTx struct {
	PairIndex            int64
	FeeRate              int64
	TreasuryAccountIndex int64
	TreasuryRate         int64
}

type UpdatePairRateTxConstraints struct {
	PairIndex            Variable
	FeeRate              Variable
	TreasuryAccountIndex Variable
	TreasuryRate         Variable
}

func EmptyUpdatePairRateTxWitness() (witness UpdatePairRateTxConstraints) {
	return UpdatePairRateTxConstraints{
		PairIndex:            ZeroInt,
		FeeRate:              ZeroInt,
		TreasuryAccountIndex: ZeroInt,
		TreasuryRate:         ZeroInt,
	}
}

func SetUpdatePairRateTxWitness(tx *UpdatePairRateTx) (witness UpdatePairRateTxConstraints) {
	witness = UpdatePairRateTxConstraints{
		PairIndex:            tx.PairIndex,
		FeeRate:              tx.FeeRate,
		TreasuryAccountIndex: tx.TreasuryAccountIndex,
		TreasuryRate:         tx.TreasuryRate,
	}
	return witness
}

func VerifyUpdatePairRateTx(
	api API, flag Variable,
	tx UpdatePairRateTxConstraints,
	liquidityBefore LiquidityConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromUpdatePairRate(api, flag, tx, hFunc)
	// verify params
	IsVariableEqual(api, flag, tx.PairIndex, liquidityBefore.PairIndex)
	IsVariableLessOrEqual(api, flag, tx.TreasuryRate, tx.FeeRate)
}

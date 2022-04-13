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
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	PairIndex         uint32
	AssetAId          uint32
	AssetAAmount      uint64
	AssetBId          uint32
	AssetBMinAmount   uint64
	FeeRate           uint32
	TreasuryRate      uint32
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
}

type SwapTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	PairIndex         Variable
	AssetAId          Variable
	AssetAAmount      Variable
	AssetBId          Variable
	AssetBMinAmount   Variable
	FeeRate           Variable
	TreasuryRate      Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptySwapTxWitness() (witness SwapTxConstraints) {
	return SwapTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		PairIndex:         ZeroInt,
		AssetAId:          ZeroInt,
		AssetAAmount:      ZeroInt,
		AssetBId:          ZeroInt,
		AssetBMinAmount:   ZeroInt,
		FeeRate:           ZeroInt,
		TreasuryRate:      ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetSwapTxWitness(tx *SwapTx) (witness SwapTxConstraints) {
	witness = SwapTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		ToAccountIndex:    tx.ToAccountIndex,
		PairIndex:         tx.PairIndex,
		AssetAId:          tx.AssetAId,
		AssetAAmount:      tx.AssetAAmount,
		AssetBId:          tx.AssetBId,
		AssetBMinAmount:   tx.AssetBMinAmount,
		FeeRate:           tx.FeeRate,
		TreasuryRate:      tx.TreasuryRate,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
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
		tx.TreasuryRate,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

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

type RemoveLiquidityTx struct {
	/*
		- from account index
		- to account index
		- asset a id
		- asset a min amount
		- asset b id
		- asset b min amount
		- lp amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
	*/
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	AssetAId          uint32
	AssetAMinAmount   uint64
	AssetBId          uint32
	AssetBMinAmount   uint64
	LpAmount          uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
}

type RemoveLiquidityTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	AssetAId          Variable
	AssetAMinAmount   Variable
	AssetBId          Variable
	AssetBMinAmount   Variable
	LpAmount          Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyRemoveLiquidityTxWitness() (witness RemoveLiquidityTxConstraints) {
	return RemoveLiquidityTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		AssetAId:          ZeroInt,
		AssetAMinAmount:   ZeroInt,
		AssetBId:          ZeroInt,
		AssetBMinAmount:   ZeroInt,
		LpAmount:          ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetRemoveLiquidityTxWitness(tx *RemoveLiquidityTx) (witness RemoveLiquidityTxConstraints) {
	witness = RemoveLiquidityTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		ToAccountIndex:    tx.ToAccountIndex,
		AssetAId:          tx.AssetAId,
		AssetAMinAmount:   tx.AssetAMinAmount,
		AssetBId:          tx.AssetBId,
		AssetBMinAmount:   tx.AssetBMinAmount,
		LpAmount:          tx.LpAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromRemoveLiquidityTx(tx RemoveLiquidityTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.ToAccountIndex,
		tx.AssetAId,
		tx.AssetAMinAmount,
		tx.AssetBId,
		tx.AssetBMinAmount,
		tx.LpAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

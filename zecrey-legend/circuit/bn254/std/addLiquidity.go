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
	FromAccountIndex  uint32
	PairIndex         uint32
	AssetAId          uint32
	AssetAAmount      uint64
	AssetBId          uint32
	AssetBAmount      uint64
	LpAmount          uint64
	PoolAAmount       uint64
	PoolBAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
}

type AddLiquidityTxConstraints struct {
	/*
		- from account index
		- pair index
		- asset a id
		- asset a amount
		- asset b id
		- asset b amount
		- gas account index
		- gas fee asset id
		- gas fee amount
	*/
	FromAccountIndex  Variable
	PairIndex         Variable
	AssetAId          Variable
	AssetAAmount      Variable
	AssetBId          Variable
	AssetBAmount      Variable
	LpAmount          Variable
	PoolAAmount       Variable
	PoolBAmount       Variable
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
		PoolAAmount:       ZeroInt,
		PoolBAmount:       ZeroInt,
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
		PoolAAmount:       tx.PoolAAmount,
		PoolBAmount:       tx.PoolBAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
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
			- AssetGas
		- Liquidity:
			- LpAmount
	- ToAccount
		- Liquidity
			- AssetA
			- AssetB
	- GasAccount
		- Assets
			- AssetGas
	- FromAccount
		- Assets
			- AssetA
			- AssetB
			- AssetGas
*/
func VerifyAddLiquidityTx(api API, flag Variable, tx AddLiquidityTxConstraints, accountsBefore [NbAccountsPerTx]AccountConstraints, liquidityBefore LiquidityConstraints) {
	// check params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetAId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetBId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.AssetAId, liquidityBefore.AssetAId)
	IsVariableEqual(api, flag, tx.AssetBId, liquidityBefore.AssetBId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[2].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// check if the user has enough balance
	IsVariableLessOrEqual(api, flag, tx.AssetAAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.AssetBAmount, accountsBefore[0].AssetsInfo[1].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[2].Balance)
	IsVariableEqual(api, flag, tx.PoolAAmount, liquidityBefore.AssetA)
	IsVariableEqual(api, flag, tx.PoolBAmount, liquidityBefore.AssetB)
	// verify LP
	Delta_LPCheck := api.Mul(tx.AssetAAmount, tx.AssetBAmount)
	LPCheck := api.Mul(tx.LpAmount, tx.LpAmount)
	api.AssertIsLessOrEqual(LPCheck, Delta_LPCheck)
	// TODO verify AMM info
	l := api.Mul(tx.PoolBAmount, tx.AssetAAmount)
	r := api.Mul(tx.PoolAAmount, tx.AssetBAmount)
	api.AssertIsEqual(l, r)
}

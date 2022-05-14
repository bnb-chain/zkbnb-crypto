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

type WithdrawTx struct {
	/*
		- account index
		- owner account index
		- nft token id
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
	*/
	FromAccountIndex  uint32
	AssetId           uint32
	AssetAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	ToAddress         string
}

type WithdrawTxConstraints struct {
	FromAccountIndex  Variable
	AssetId           Variable
	AssetAmount       Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	ToAddress         Variable
}

func EmptyWithdrawTxWitness() (witness WithdrawTxConstraints) {
	return WithdrawTxConstraints{
		FromAccountIndex:  ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
		ToAddress:         ZeroInt,
	}
}

func SetWithdrawTxWitness(tx *WithdrawTx) (witness WithdrawTxConstraints) {
	witness = WithdrawTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		ToAddress:         tx.ToAddress,
	}
	return witness
}

func ComputeHashFromWithdrawTx(tx WithdrawTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.AssetId,
		tx.AssetAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		tx.ToAddress,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyWithdrawTx:
	accounts order is:
	- FromAccount
		- Assets:
			- AssetA
			- AssetGas
	- GasAccount
		- Assets:
			- AssetGas
*/
func VerifyWithdrawTx(
	api API, flag Variable,
	tx *WithdrawTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromWithdraw(api, flag, *tx, hFunc)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[1].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// should have enough assets
	tx.AssetAmount = UnpackAmount(api, tx.AssetAmount)
	tx.GasFeeAssetAmount = UnpackAmount(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[1].Balance)
}

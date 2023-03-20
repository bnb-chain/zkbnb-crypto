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
	"github.com/consensys/gnark/std/hash/poseidon"
	"math/big"
)

type WithdrawTx struct {
	FromAccountIndex  int64
	AssetId           int64
	AssetAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	ToAddress         *big.Int
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

func ComputeHashFromWithdrawTx(api API, tx WithdrawTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeWithdraw, tx.FromAccountIndex, nonce, expiredAt,
		tx.GasFeeAssetId, tx.GasFeeAssetAmount, tx.AssetId, tx.AssetAmount, tx.ToAddress)
}

func VerifyWithdrawTx(
	api API, flag Variable,
	tx *WithdrawTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	pubData = CollectPubDataFromWithdraw(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[fromAccount].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[1].AssetId)
	// should have enough assets
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[1].Balance)
	return pubData
}

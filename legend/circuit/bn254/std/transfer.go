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
	"github.com/consensys/gnark/frontend"
)

type TransferTx struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	ToAccountNameHash []byte
	AssetId           int64
	AssetAmount       int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
	CallDataHash      []byte
}

type TransferTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	ToAccountNameHash Variable
	AssetId           Variable
	AssetAmount       Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	CallDataHash      Variable
}

func EmptyTransferTxWitness() (witness TransferTxConstraints) {
	return TransferTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		ToAccountNameHash: ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
		CallDataHash:      ZeroInt,
	}
}

func SetTransferTxWitness(tx *TransferTx) (witness TransferTxConstraints) {
	witness = TransferTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		ToAccountIndex:    tx.ToAccountIndex,
		ToAccountNameHash: tx.ToAccountNameHash,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		CallDataHash:      tx.CallDataHash,
	}
	return witness
}

func SetTransferTxValuesWitness(tx *TransferTx, ExpireAt int64, Nonce int64) (witnesses ValuesConstraints) {
	witnesses = ValuesConstraints{[TxValueConstraintLimit]frontend.Variable{}}
	for i := 0; i < len(witnesses.Values); i++ {
		witnesses.Values[i] = 0
	}
	witnesses.Values[0] = tx.FromAccountIndex
	witnesses.Values[1] = tx.ToAccountIndex
	for i := range tx.ToAccountNameHash {
		witnesses.Values[2+i] = tx.ToAccountNameHash[i]
	}
	witnesses.Values[34] = tx.AssetId
	witnesses.Values[35] = tx.AssetAmount
	witnesses.Values[36] = tx.GasAccountIndex
	witnesses.Values[37] = tx.GasFeeAssetId
	witnesses.Values[38] = tx.GasFeeAssetAmount

	for i := range tx.CallDataHash {
		witnesses.Values[39+i] = tx.CallDataHash[i]
	}
	witnesses.Values[71] = ExpireAt
	witnesses.Values[72] = Nonce
	witnesses.Values[73] = ChainId
	return witnesses
}

func ComputeHashFromTransferTx(tx TransferTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.ToAccountIndex,
		tx.ToAccountNameHash,
		tx.AssetId,
		tx.AssetAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		tx.CallDataHash,
		expiredAt,
		nonce,
		ChainId,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyTransferTx(
	api API, flag Variable,
	tx *TransferTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataSizePerTx]Variable) {
	// collect pubdata
	pubData = CollectPubDataFromTransfer(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[2].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.ToAccountNameHash, accountsBefore[1].AccountNameHash)
	// asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	// should have enough balance
	tx.AssetAmount = UnpackAmount(api, tx.AssetAmount)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	//tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[1].Balance)
	return pubData
}

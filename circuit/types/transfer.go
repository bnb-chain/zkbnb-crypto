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

import "github.com/consensys/gnark/std/hash/poseidon"

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

func ComputeHashFromTransferTx(api API, tx TransferTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeTransfer, tx.FromAccountIndex, nonce, expiredAt, tx.GasFeeAssetId,
		tx.GasFeeAssetAmount, tx.ToAccountIndex, tx.AssetId, tx.AssetAmount, tx.ToAccountNameHash, tx.CallDataHash,
	)
}

func VerifyTransferTx(
	api API, flag Variable,
	tx *TransferTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	toAccount := 1

	// collect pubdata
	pubData = CollectPubDataFromTransfer(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.FromAccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[toAccount].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.ToAccountNameHash, accountsBefore[toAccount].AccountNameHash)
	// asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[toAccount].AssetsInfo[0].AssetId)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[1].AssetId)
	// should have enough balance
	tx.AssetAmount = UnpackAmount(api, tx.AssetAmount)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[1].Balance)
	return pubData
}

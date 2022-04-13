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

import "math/big"

type GenericTransferTx struct {
	/*
		- from account index
		- to account index
		- to account name
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- call data hash
		- nft index
	*/
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	ToAccountName     string
	AssetId           uint32
	AssetAmount       *big.Int
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	CallDataHash      []byte
	NftIndex          uint32
}

type GenericTransferTxConstraints struct {
	FromAccountIndex  Variable
	ToAccountIndex    Variable
	ToAccountName     Variable
	AssetId           Variable
	AssetAmount       Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
	CallDataHash      Variable
	NftIndex          Variable
}

func EmptyGenericTransferTxWitness() (witness GenericTransferTxConstraints) {
	return GenericTransferTxConstraints{
		FromAccountIndex:  ZeroInt,
		ToAccountIndex:    ZeroInt,
		ToAccountName:     ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
		CallDataHash:      ZeroInt,
		NftIndex:          ZeroInt,
	}
}

func SetGenericTransferTxWitness(tx *GenericTransferTx) (witness GenericTransferTxConstraints) {
	witness = GenericTransferTxConstraints{
		FromAccountIndex:  tx.FromAccountIndex,
		ToAccountIndex:    tx.ToAccountIndex,
		ToAccountName:     tx.ToAccountName,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
		CallDataHash:      tx.CallDataHash,
		NftIndex:          tx.NftIndex,
	}
	return witness
}

func ComputeHashFromGenericTransferTx(tx GenericTransferTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.FromAccountIndex,
		tx.ToAccountIndex,
		tx.ToAccountName,
		tx.AssetId,
		tx.AssetAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
		tx.CallDataHash,
		tx.NftIndex,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

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

type MintNftTx struct {
	/*
		- creator account index
		- to account index
		- nft token id
		- nft content hash
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
	*/
	CreatorAccountIndex uint32
	ToAccountIndex      uint32
	NftIndex            uint32
	NftContentHash      string
	AssetId             uint32
	AssetAmount         uint64
	GasAccountIndex     uint32
	GasFeeAssetId       uint32
	GasFeeAssetAmount   uint64
}

type MintNftTxConstraints struct {
	CreatorAccountIndex Variable
	ToAccountIndex      Variable
	NftIndex            Variable
	NftContentHash      Variable
	AssetId             Variable
	AssetAmount         Variable
	GasAccountIndex     Variable
	GasFeeAssetId       Variable
	GasFeeAssetAmount   Variable
}

func EmptyMintNftTxWitness() (witness MintNftTxConstraints) {
	return MintNftTxConstraints{
		CreatorAccountIndex: ZeroInt,
		ToAccountIndex:      ZeroInt,
		NftIndex:            ZeroInt,
		NftContentHash:      ZeroInt,
		AssetId:             ZeroInt,
		AssetAmount:         ZeroInt,
		GasAccountIndex:     ZeroInt,
		GasFeeAssetId:       ZeroInt,
		GasFeeAssetAmount:   ZeroInt,
	}
}

func SetMintNftTxWitness(tx *MintNftTx) (witness MintNftTxConstraints) {
	witness = MintNftTxConstraints{
		CreatorAccountIndex: tx.CreatorAccountIndex,
		ToAccountIndex:      tx.ToAccountIndex,
		NftIndex:            tx.NftIndex,
		NftContentHash:      tx.NftContentHash,
		AssetId:             tx.AssetId,
		AssetAmount:         tx.AssetAmount,
		GasAccountIndex:     tx.GasAccountIndex,
		GasFeeAssetId:       tx.GasFeeAssetId,
		GasFeeAssetAmount:   tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromMintNftTx(tx MintNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.CreatorAccountIndex,
		tx.ToAccountIndex,
		tx.NftIndex,
		tx.NftContentHash,
		tx.AssetId,
		tx.AssetAmount,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

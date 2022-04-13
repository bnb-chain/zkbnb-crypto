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

type BuyNftTx struct {
	/*
		- account index
		- owner account index
		- nft token id
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- nonce
	*/
	AccountIndex      uint32
	OwnerAccountIndex uint32
	NftIndex          uint32
	AssetId           uint32
	AssetAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
}

type BuyNftTxConstraints struct {
	/*
		- account index
		- owner account index
		- nft token id
		- asset id
		- asset amount
		- gas account index
		- gas fee asset id
		- gas fee asset amount
		- nonce
	*/
	AccountIndex      Variable
	OwnerAccountIndex Variable
	NftIndex          Variable
	AssetId           Variable
	AssetAmount       Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyBuyNftTxWitness() (witness BuyNftTxConstraints) {
	witness = BuyNftTxConstraints{
		AccountIndex:      ZeroInt,
		OwnerAccountIndex: ZeroInt,
		NftIndex:          ZeroInt,
		AssetId:           ZeroInt,
		AssetAmount:       ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
	return witness
}

func SetBuyNftTxWitness(tx *BuyNftTx) (witness BuyNftTxConstraints) {
	witness = BuyNftTxConstraints{
		AccountIndex:      tx.AccountIndex,
		OwnerAccountIndex: tx.OwnerAccountIndex,
		NftIndex:          tx.NftIndex,
		AssetId:           tx.AssetId,
		AssetAmount:       tx.AssetAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromBuyNftTx(tx BuyNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.AccountIndex,
		tx.OwnerAccountIndex,
		tx.NftIndex,
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

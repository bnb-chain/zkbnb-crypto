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

type MintNftTx struct {
	CreatorAccountIndex int64
	ToAccountIndex      int64
	ToAccountNameHash   []byte
	NftIndex            int64
	NftContentHash      []byte
	CreatorTreasuryRate int64
	GasAccountIndex     int64
	GasFeeAssetId       int64
	GasFeeAssetAmount   int64
	CollectionId        int64
	ExpiredAt           int64
}

type MintNftTxConstraints struct {
	CreatorAccountIndex Variable
	ToAccountIndex      Variable
	ToAccountNameHash   Variable
	NftIndex            Variable
	NftContentHash      Variable
	CreatorTreasuryRate Variable
	GasAccountIndex     Variable
	GasFeeAssetId       Variable
	GasFeeAssetAmount   Variable
	CollectionId        Variable
	ExpiredAt           Variable
}

func EmptyMintNftTxWitness() (witness MintNftTxConstraints) {
	return MintNftTxConstraints{
		CreatorAccountIndex: ZeroInt,
		ToAccountIndex:      ZeroInt,
		ToAccountNameHash:   ZeroInt,
		NftIndex:            ZeroInt,
		NftContentHash:      ZeroInt,
		CreatorTreasuryRate: ZeroInt,
		GasAccountIndex:     ZeroInt,
		GasFeeAssetId:       ZeroInt,
		GasFeeAssetAmount:   ZeroInt,
		CollectionId:        ZeroInt,
		ExpiredAt:           ZeroInt,
	}
}

func SetMintNftTxWitness(tx *MintNftTx) (witness MintNftTxConstraints) {
	witness = MintNftTxConstraints{
		CreatorAccountIndex: tx.CreatorAccountIndex,
		ToAccountIndex:      tx.ToAccountIndex,
		ToAccountNameHash:   tx.ToAccountNameHash,
		NftIndex:            tx.NftIndex,
		NftContentHash:      tx.NftContentHash,
		CreatorTreasuryRate: tx.CreatorTreasuryRate,
		GasAccountIndex:     tx.GasAccountIndex,
		GasFeeAssetId:       tx.GasFeeAssetId,
		GasFeeAssetAmount:   tx.GasFeeAssetAmount,
		CollectionId:        tx.CollectionId,
		ExpiredAt:           tx.ExpiredAt,
	}
	return witness
}

func ComputeHashFromMintNftTx(api API, tx MintNftTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeMintNft, tx.CreatorAccountIndex, nonce, expiredAt,
		tx.GasFeeAssetId, tx.GasFeeAssetAmount, tx.ToAccountIndex,
		tx.CreatorTreasuryRate, tx.CollectionId, tx.ToAccountNameHash, tx.NftContentHash)
}

func VerifyMintNftTx(
	api API, flag Variable,
	tx *MintNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, nftBefore NftConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	toAccount := 1

	pubData = CollectPubDataFromMintNft(api, *tx)
	// verify params
	// check empty nft
	CheckEmptyNftNode(api, flag, nftBefore)
	// account index
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.ToAccountIndex, accountsBefore[toAccount].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.ToAccountNameHash, accountsBefore[toAccount].AccountNameHash)
	// content hash
	isZero := api.IsZero(tx.NftContentHash)
	IsVariableEqual(api, flag, isZero, 0)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	// should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	// collection id should be less than creator's collection nonce
	IsVariableLess(api, flag, tx.CollectionId, accountsBefore[fromAccount].CollectionNonce)
	return pubData
}

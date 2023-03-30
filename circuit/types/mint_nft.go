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
)

type MintNftTx struct {
	CreatorAccountIndex int64
	ToAccountIndex      int64
	ToL1Address         []byte
	NftIndex            int64
	NftContentHash      []byte
	RoyaltyRate         int64
	GasAccountIndex     int64
	GasFeeAssetId       int64
	GasFeeAssetAmount   int64
	CollectionId        int64
	ExpiredAt           int64
	NftContentType      int64
}

type MintNftTxConstraints struct {
	CreatorAccountIndex Variable
	ToAccountIndex      Variable
	ToL1Address         Variable
	NftIndex            Variable
	NftContentHash      [2]Variable
	RoyaltyRate         Variable
	GasAccountIndex     Variable
	GasFeeAssetId       Variable
	GasFeeAssetAmount   Variable
	CollectionId        Variable
	ExpiredAt           Variable
	NftContentType      Variable
}

func EmptyMintNftTxWitness() (witness MintNftTxConstraints) {
	return MintNftTxConstraints{
		CreatorAccountIndex: ZeroInt,
		ToAccountIndex:      ZeroInt,
		ToL1Address:         ZeroInt,
		NftIndex:            ZeroInt,
		NftContentHash:      [2]Variable{ZeroInt, ZeroInt},
		RoyaltyRate:         ZeroInt,
		GasAccountIndex:     ZeroInt,
		GasFeeAssetId:       ZeroInt,
		GasFeeAssetAmount:   ZeroInt,
		CollectionId:        ZeroInt,
		ExpiredAt:           ZeroInt,
		NftContentType:      ZeroInt,
	}
}

func SetMintNftTxWitness(tx *MintNftTx) (witness MintNftTxConstraints) {
	witness = MintNftTxConstraints{
		CreatorAccountIndex: tx.CreatorAccountIndex,
		ToAccountIndex:      tx.ToAccountIndex,
		ToL1Address:         tx.ToL1Address,
		NftIndex:            tx.NftIndex,
		NftContentHash:      GetNftContentHashFromBytes(tx.NftContentHash),
		RoyaltyRate:         tx.RoyaltyRate,
		GasAccountIndex:     tx.GasAccountIndex,
		GasFeeAssetId:       tx.GasFeeAssetId,
		GasFeeAssetAmount:   tx.GasFeeAssetAmount,
		CollectionId:        tx.CollectionId,
		ExpiredAt:           tx.ExpiredAt,
		NftContentType:      tx.NftContentType,
	}
	return witness
}

func ComputeHashFromMintNftTx(api API, tx MintNftTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeMintNft, tx.CreatorAccountIndex, nonce, expiredAt,
		tx.GasFeeAssetId, tx.GasFeeAssetAmount, tx.ToAccountIndex,
		tx.RoyaltyRate, tx.CollectionId, tx.ToL1Address, tx.NftContentType)
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
	// account address
	IsVariableEqual(api, flag, tx.ToL1Address, accountsBefore[toAccount].L1Address)
	// content hash
	isZero := api.Or(api.IsZero(tx.NftContentHash[0]), api.IsZero(tx.NftContentHash[1]))
	IsVariableEqual(api, flag, isZero, 0)
	// gas asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	// should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	// collection id should be less than creator's collection nonce
	IsVariableLess(api, flag, tx.CollectionId, accountsBefore[fromAccount].CollectionNonce)
	//NftContentType
	IsVariableLessOrEqual(api, flag, 0, tx.NftContentType)
	return pubData
}

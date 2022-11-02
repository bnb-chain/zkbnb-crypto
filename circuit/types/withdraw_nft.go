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

type WithdrawNftTx struct {
	AccountIndex           int64
	CreatorAccountIndex    int64
	CreatorAccountNameHash []byte
	CreatorTreasuryRate    int64
	NftIndex               int64
	NftContentHash         []byte
	ToAddress              string
	GasAccountIndex        int64
	GasFeeAssetId          int64
	GasFeeAssetAmount      int64
	CollectionId           int64
}

type WithdrawNftTxConstraints struct {
	AccountIndex           Variable
	CreatorAccountIndex    Variable
	CreatorAccountNameHash Variable
	CreatorTreasuryRate    Variable
	NftIndex               Variable
	NftContentHash         Variable
	ToAddress              Variable
	GasAccountIndex        Variable
	GasFeeAssetId          Variable
	GasFeeAssetAmount      Variable
	CollectionId           Variable
}

func EmptyWithdrawNftTxWitness() (witness WithdrawNftTxConstraints) {
	return WithdrawNftTxConstraints{
		AccountIndex:           ZeroInt,
		CreatorAccountIndex:    ZeroInt,
		CreatorAccountNameHash: ZeroInt,
		CreatorTreasuryRate:    ZeroInt,
		NftIndex:               ZeroInt,
		NftContentHash:         ZeroInt,
		ToAddress:              ZeroInt,
		GasAccountIndex:        ZeroInt,
		GasFeeAssetId:          ZeroInt,
		GasFeeAssetAmount:      ZeroInt,
		CollectionId:           ZeroInt,
	}
}

func SetWithdrawNftTxWitness(tx *WithdrawNftTx) (witness WithdrawNftTxConstraints) {
	witness = WithdrawNftTxConstraints{
		AccountIndex:           tx.AccountIndex,
		CreatorAccountIndex:    tx.CreatorAccountIndex,
		CreatorAccountNameHash: tx.CreatorAccountNameHash,
		CreatorTreasuryRate:    tx.CreatorTreasuryRate,
		NftIndex:               tx.NftIndex,
		NftContentHash:         tx.NftContentHash,
		ToAddress:              tx.ToAddress,
		GasAccountIndex:        tx.GasAccountIndex,
		GasFeeAssetId:          tx.GasFeeAssetId,
		GasFeeAssetAmount:      tx.GasFeeAssetAmount,
		CollectionId:           tx.CollectionId,
	}
	return witness
}

func ComputeHashFromWithdrawNftTx(api API, tx WithdrawNftTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeWithdrawNft, tx.AccountIndex, nonce, expiredAt, tx.GasFeeAssetId, tx.GasFeeAssetAmount, tx.NftIndex, tx.ToAddress)
}

func VerifyWithdrawNftTx(
	api API,
	flag Variable,
	tx *WithdrawNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	creatorAccount := 1
	pubData = CollectPubDataFromWithdrawNft(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[creatorAccount].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.CreatorAccountNameHash, accountsBefore[creatorAccount].AccountNameHash)
	// collection id
	IsVariableEqual(api, flag, tx.CollectionId, nftBefore.CollectionId)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, nftBefore.CreatorAccountIndex)
	IsVariableEqual(api, flag, tx.CreatorTreasuryRate, nftBefore.CreatorTreasuryRate)
	IsVariableEqual(api, flag, tx.AccountIndex, nftBefore.OwnerAccountIndex)
	IsVariableEqual(api, flag, tx.NftContentHash, nftBefore.NftContentHash)
	// have enough assets
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData
}

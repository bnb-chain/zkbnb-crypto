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
	AccountIndex        int64
	CreatorAccountIndex int64
	CreatorL1Address    []byte
	RoyaltyRate         int64
	NftIndex            int64
	NftContentHash      []byte
	ToAddress           string
	GasAccountIndex     int64
	GasFeeAssetId       int64
	GasFeeAssetAmount   int64
	CollectionId        int64
	NftContentType      int64
}

type WithdrawNftTxConstraints struct {
	AccountIndex        Variable
	CreatorAccountIndex Variable
	CreatorL1Address    Variable
	RoyaltyRate         Variable
	NftIndex            Variable
	NftContentHash      [2]Variable
	ToAddress           Variable
	GasAccountIndex     Variable
	GasFeeAssetId       Variable
	GasFeeAssetAmount   Variable
	CollectionId        Variable
	NftContentType      Variable
}

func EmptyWithdrawNftTxWitness() (witness WithdrawNftTxConstraints) {
	return WithdrawNftTxConstraints{
		AccountIndex:        ZeroInt,
		CreatorAccountIndex: ZeroInt,
		CreatorL1Address:    ZeroInt,
		RoyaltyRate:         ZeroInt,
		NftIndex:            ZeroInt,
		NftContentHash:      [2]Variable{ZeroInt, ZeroInt},
		ToAddress:           ZeroInt,
		GasAccountIndex:     ZeroInt,
		GasFeeAssetId:       ZeroInt,
		GasFeeAssetAmount:   ZeroInt,
		CollectionId:        ZeroInt,
		NftContentType:      ZeroInt,
	}
}

func SetWithdrawNftTxWitness(tx *WithdrawNftTx) (witness WithdrawNftTxConstraints) {
	witness = WithdrawNftTxConstraints{
		AccountIndex:        tx.AccountIndex,
		CreatorAccountIndex: tx.CreatorAccountIndex,
		CreatorL1Address:    tx.CreatorL1Address,
		RoyaltyRate:         tx.RoyaltyRate,
		NftIndex:            tx.NftIndex,
		NftContentHash:      GetNftContentHashFromBytes(tx.NftContentHash),
		ToAddress:           tx.ToAddress,
		GasAccountIndex:     tx.GasAccountIndex,
		GasFeeAssetId:       tx.GasFeeAssetId,
		GasFeeAssetAmount:   tx.GasFeeAssetAmount,
		CollectionId:        tx.CollectionId,
		NftContentType:      tx.NftContentType,
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
	IsVariableEqual(api, flag, tx.CreatorL1Address, accountsBefore[creatorAccount].L1Address)
	// collection id
	IsVariableEqual(api, flag, tx.CollectionId, nftBefore.CollectionId)
	//NftContentType
	IsVariableEqual(api, flag, tx.NftContentType, nftBefore.NftContentType)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, nftBefore.CreatorAccountIndex)
	IsVariableEqual(api, flag, tx.RoyaltyRate, nftBefore.RoyaltyRate)
	IsVariableEqual(api, flag, tx.AccountIndex, nftBefore.OwnerAccountIndex)
	IsVariableEqual(api, flag, tx.NftContentHash[0], nftBefore.NftContentHash[0])
	IsVariableEqual(api, flag, tx.NftContentHash[1], nftBefore.NftContentHash[1])
	// have enough assets
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData
}

func VerifyDeltaWithdrawNftTx(api API, flag Variable, tx WithdrawNftTxConstraints) {
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.AccountIndex), tx.AccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.CreatorAccountIndex), tx.CreatorAccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.CollectionId), tx.CollectionId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftContentType), tx.NftContentType)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.GasFeeAssetId), tx.GasFeeAssetId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.GasFeeAssetAmount), tx.GasFeeAssetAmount)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftIndex), tx.NftIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.RoyaltyRate), tx.RoyaltyRate)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftContentHash[0]), tx.NftContentHash[0])
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftContentHash[1]), tx.NftContentHash[1])
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.ToAddress), tx.ToAddress)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.CreatorL1Address), tx.CreatorL1Address)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.GasAccountIndex), tx.GasAccountIndex)
}

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
	"math/big"
)

type WithdrawNftTx struct {
	AccountIndex           int64
	CreatorAccountIndex    int64
	CreatorAccountNameHash []byte
	CreatorTreasuryRate    int64
	NftIndex               int64
	NftContentHash         []byte
	NftL1Address           string
	NftL1TokenId           *big.Int
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
	NftL1Address           Variable
	NftL1TokenId           Variable
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
		NftL1Address:           ZeroInt,
		NftL1TokenId:           ZeroInt,
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
		NftL1Address:           tx.NftL1Address,
		NftL1TokenId:           tx.NftL1TokenId,
		ToAddress:              tx.ToAddress,
		GasAccountIndex:        tx.GasAccountIndex,
		GasFeeAssetId:          tx.GasFeeAssetId,
		GasFeeAssetAmount:      tx.GasFeeAssetAmount,
		CollectionId:           tx.CollectionId,
	}
	return witness
}

func ComputeHashFromWithdrawNftTx(api API, tx WithdrawNftTxConstraints, nonce Variable, expiredAt Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		PackInt64Variables(api, ChainId, tx.AccountIndex, nonce, expiredAt),
		PackInt64Variables(api, tx.GasAccountIndex, tx.GasFeeAssetId, tx.GasFeeAssetAmount),
		tx.NftIndex,
		tx.ToAddress,
	)
	hashVal = hFunc.Sum()
	return hashVal
}

func VerifyWithdrawNftTx(
	api API,
	flag Variable,
	tx *WithdrawNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) (pubData [PubDataSizePerTx]Variable) {
	pubData = CollectPubDataFromWithdrawNft(api, *tx)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[2].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.CreatorAccountNameHash, accountsBefore[1].AccountNameHash)
	// collection id
	IsVariableEqual(api, flag, tx.CollectionId, nftBefore.CollectionId)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, nftBefore.CreatorAccountIndex)
	IsVariableEqual(api, flag, tx.CreatorTreasuryRate, nftBefore.CreatorTreasuryRate)
	IsVariableEqual(api, flag, tx.AccountIndex, nftBefore.OwnerAccountIndex)
	IsVariableEqual(api, flag, tx.NftContentHash, nftBefore.NftContentHash)
	IsVariableEqual(api, flag, tx.NftL1TokenId, nftBefore.NftL1TokenId)
	IsVariableEqual(api, flag, tx.NftL1Address, nftBefore.NftL1Address)
	// have enough assets
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
	return pubData
}

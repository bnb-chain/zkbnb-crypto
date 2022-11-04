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

type FullExitNftTx struct {
	AccountIndex           int64
	AccountNameHash        []byte
	CreatorAccountIndex    int64
	CreatorAccountNameHash []byte
	CreatorTreasuryRate    int64
	NftIndex               int64
	CollectionId           int64
	NftContentHash         []byte
}

type FullExitNftTxConstraints struct {
	AccountIndex           Variable
	AccountNameHash        Variable
	CreatorAccountIndex    Variable
	CreatorAccountNameHash Variable
	CreatorTreasuryRate    Variable
	NftIndex               Variable
	CollectionId           Variable
	NftContentHash         Variable
}

func EmptyFullExitNftTxWitness() (witness FullExitNftTxConstraints) {
	return FullExitNftTxConstraints{
		AccountIndex:           ZeroInt,
		AccountNameHash:        ZeroInt,
		CreatorAccountIndex:    ZeroInt,
		CreatorAccountNameHash: ZeroInt,
		CreatorTreasuryRate:    ZeroInt,
		NftIndex:               ZeroInt,
		CollectionId:           ZeroInt,
		NftContentHash:         ZeroInt,
	}
}

func SetFullExitNftTxWitness(tx *FullExitNftTx) (witness FullExitNftTxConstraints) {
	witness = FullExitNftTxConstraints{
		AccountIndex:           tx.AccountIndex,
		AccountNameHash:        tx.AccountNameHash,
		CreatorAccountIndex:    tx.CreatorAccountIndex,
		CreatorAccountNameHash: tx.CreatorAccountNameHash,
		CreatorTreasuryRate:    tx.CreatorTreasuryRate,
		NftIndex:               tx.NftIndex,
		CollectionId:           tx.CollectionId,
		NftContentHash:         tx.NftContentHash,
	}
	return witness
}

func VerifyFullExitNftTx(
	api API, flag Variable,
	tx FullExitNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	fromAccount := 0
	creatorAccount := 1

	pubData = CollectPubDataFromFullExitNft(api, tx)
	// verify params
	IsVariableEqual(api, flag, tx.AccountNameHash, accountsBefore[fromAccount].AccountNameHash)
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[creatorAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountNameHash, accountsBefore[creatorAccount].AccountNameHash)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, nftBefore.CreatorAccountIndex)
	IsVariableEqual(api, flag, tx.CreatorTreasuryRate, nftBefore.CreatorTreasuryRate)
	isOwner := api.And(api.IsZero(api.Sub(tx.AccountIndex, nftBefore.OwnerAccountIndex)), flag)
	IsVariableEqual(api, isOwner, tx.NftContentHash, nftBefore.NftContentHash)
	tx.NftContentHash = api.Select(isOwner, tx.NftContentHash, 0)
	return pubData
}

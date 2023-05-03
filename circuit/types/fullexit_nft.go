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
	AccountIndex        int64
	L1Address           []byte
	CreatorAccountIndex int64
	CreatorL1Address    []byte
	RoyaltyRate         int64
	NftIndex            int64
	CollectionId        int64
	NftContentHash      []byte
	NftContentType      int64
}

type FullExitNftTxConstraints struct {
	AccountIndex        Variable
	L1Address           Variable
	CreatorAccountIndex Variable
	CreatorL1Address    Variable
	RoyaltyRate         Variable
	NftIndex            Variable
	CollectionId        Variable
	NftContentHash      [2]Variable
	NftContentType      Variable
}

func EmptyFullExitNftTxWitness() (witness FullExitNftTxConstraints) {
	return FullExitNftTxConstraints{
		AccountIndex:        ZeroInt,
		L1Address:           ZeroInt,
		CreatorAccountIndex: ZeroInt,
		CreatorL1Address:    ZeroInt,
		RoyaltyRate:         ZeroInt,
		NftIndex:            ZeroInt,
		CollectionId:        ZeroInt,
		NftContentHash:      [2]Variable{ZeroInt, ZeroInt},
		NftContentType:      ZeroInt,
	}
}

func SetFullExitNftTxWitness(tx *FullExitNftTx) (witness FullExitNftTxConstraints) {
	witness = FullExitNftTxConstraints{
		AccountIndex:        tx.AccountIndex,
		L1Address:           tx.L1Address,
		CreatorAccountIndex: tx.CreatorAccountIndex,
		CreatorL1Address:    tx.CreatorL1Address,
		RoyaltyRate:         tx.RoyaltyRate,
		NftIndex:            tx.NftIndex,
		CollectionId:        tx.CollectionId,
		NftContentHash:      GetNftContentHashFromBytes(tx.NftContentHash),
		NftContentType:      tx.NftContentType,
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

	txInfoL1Address := api.Select(flag, tx.L1Address, ZeroInt)
	beforeL1Address := api.Select(flag, accountsBefore[fromAccount].L1Address, ZeroInt)
	isFullExitSuccess := api.IsZero(api.Cmp(txInfoL1Address, beforeL1Address))
	isOwner := api.And(isFullExitSuccess, api.And(api.IsZero(api.Sub(tx.AccountIndex, nftBefore.OwnerAccountIndex)), flag))

	tx.CreatorAccountIndex = api.Select(isOwner, tx.CreatorAccountIndex, ZeroInt)
	tx.NftContentHash[0] = api.Select(isOwner, tx.NftContentHash[0], ZeroInt)
	tx.NftContentHash[1] = api.Select(isOwner, tx.NftContentHash[1], ZeroInt)
	tx.RoyaltyRate = api.Select(isOwner, tx.RoyaltyRate, ZeroInt)
	tx.CollectionId = api.Select(isOwner, tx.CollectionId, ZeroInt)
	tx.NftContentType = api.Select(isOwner, tx.NftContentType, ZeroInt)

	pubData = CollectPubDataFromFullExitNft(api, tx)
	// verify params
	IsVariableEqual(api, isOwner, tx.L1Address, accountsBefore[fromAccount].L1Address)
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.NftIndex, nftBefore.NftIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[creatorAccount].AccountIndex)
	IsVariableEqual(api, flag, tx.CreatorL1Address, accountsBefore[creatorAccount].L1Address)
	IsVariableEqual(api, isOwner, tx.CreatorAccountIndex, nftBefore.CreatorAccountIndex)
	IsVariableEqual(api, isOwner, tx.RoyaltyRate, nftBefore.RoyaltyRate)
	IsVariableEqual(api, isOwner, tx.NftContentHash[0], nftBefore.NftContentHash[0])
	IsVariableEqual(api, isOwner, tx.NftContentHash[1], nftBefore.NftContentHash[1])
	//NftContentType
	IsVariableEqual(api, flag, tx.NftContentType, nftBefore.NftContentType)
	return pubData
}

func VerifyDeltaFullExitNftTx(api API, flag Variable, tx FullExitNftTxConstraints) {
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.AccountIndex), tx.AccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.L1Address), tx.L1Address)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.CreatorAccountIndex), tx.CreatorAccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.CreatorL1Address), tx.CreatorL1Address)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.RoyaltyRate), tx.RoyaltyRate)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftIndex), tx.NftIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.CollectionId), tx.CollectionId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftContentHash[0]), tx.NftContentHash[0])
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftContentHash[1]), tx.NftContentHash[1])
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.NftContentType), tx.NftContentType)
}

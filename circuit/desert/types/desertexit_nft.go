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

import "github.com/bnb-chain/zkbnb-crypto/circuit/types"

type ExitNftTx struct {
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

type ExitNftTxConstraints struct {
	AccountIndex        types.Variable
	L1Address           types.Variable
	CreatorAccountIndex types.Variable
	CreatorL1Address    types.Variable
	RoyaltyRate         types.Variable
	NftIndex            types.Variable
	CollectionId        types.Variable
	NftContentHash      [2]types.Variable
	NftContentType      types.Variable
}

func EmptyExitNftTxWitness() (witness ExitNftTxConstraints) {
	return ExitNftTxConstraints{
		AccountIndex:        types.ZeroInt,
		L1Address:           types.ZeroInt,
		CreatorAccountIndex: types.ZeroInt,
		CreatorL1Address:    types.ZeroInt,
		RoyaltyRate:         types.ZeroInt,
		NftIndex:            types.ZeroInt,
		CollectionId:        types.ZeroInt,
		NftContentHash:      [2]types.Variable{types.ZeroInt, types.ZeroInt},
		NftContentType:      types.ZeroInt,
	}
}

func SetExitNftTxWitness(tx *ExitNftTx) (witness ExitNftTxConstraints) {
	witness = ExitNftTxConstraints{
		AccountIndex:        tx.AccountIndex,
		L1Address:           tx.L1Address,
		CreatorAccountIndex: tx.CreatorAccountIndex,
		CreatorL1Address:    tx.CreatorL1Address,
		RoyaltyRate:         tx.RoyaltyRate,
		NftIndex:            tx.NftIndex,
		CollectionId:        tx.CollectionId,
		NftContentHash:      types.GetNftContentHashFromBytes(tx.NftContentHash),
		NftContentType:      tx.NftContentType,
	}
	return witness
}

func VerifyExitNftTx(
	api types.API, flag types.Variable,
	tx ExitNftTxConstraints,
	accounts [NbAccountsPerTx]AccountConstraints,
	nft types.NftConstraints,
) (pubData [types.PubDataBitsSizePerTx]types.Variable) {
	fromAccount := 0
	creatorAccount := 1
	pubData = CollectPubDataFromExitNft(api, tx)
	// verify params
	types.IsVariableEqual(api, flag, tx.L1Address, accounts[fromAccount].L1Address)
	types.IsVariableEqual(api, flag, tx.AccountIndex, accounts[fromAccount].AccountIndex)
	types.IsVariableEqual(api, flag, tx.NftIndex, nft.NftIndex)
	types.IsVariableEqual(api, flag, tx.CreatorAccountIndex, accounts[creatorAccount].AccountIndex)
	types.IsVariableEqual(api, flag, tx.CreatorL1Address, accounts[creatorAccount].L1Address)
	types.IsVariableEqual(api, flag, tx.CreatorAccountIndex, nft.CreatorAccountIndex)
	types.IsVariableEqual(api, flag, tx.RoyaltyRate, nft.RoyaltyRate)
	types.IsVariableEqual(api, flag, tx.NftContentHash[0], nft.NftContentHash[0])
	types.IsVariableEqual(api, flag, tx.NftContentHash[1], nft.NftContentHash[1])
	//NftContentType
	types.IsVariableEqual(api, flag, tx.NftContentType, nft.NftContentType)
	return pubData
}

func VerifyDeltaExitNftTx(api types.API, flag types.Variable, tx ExitNftTxConstraints) {
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.AccountIndex), tx.AccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.L1Address), tx.L1Address)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.CreatorAccountIndex), tx.CreatorAccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.CreatorL1Address), tx.CreatorL1Address)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.RoyaltyRate), tx.RoyaltyRate)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.NftIndex), tx.NftIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.CollectionId), tx.CollectionId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.NftContentHash[0]), tx.NftContentHash[0])
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.NftContentHash[1]), tx.NftContentHash[1])
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.NftContentType), tx.NftContentType)
}

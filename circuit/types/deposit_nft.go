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

type DepositNftTx struct {
	AccountIndex        int64
	NftIndex            int64
	AccountNameHash     []byte
	NftContentHash      []byte
	CreatorAccountIndex int64
	CreatorTreasuryRate int64
	CollectionId        int64
}

type DepositNftTxConstraints struct {
	AccountIndex        Variable
	AccountNameHash     Variable
	NftIndex            Variable
	NftContentHash      Variable
	CreatorAccountIndex Variable
	CreatorTreasuryRate Variable
	CollectionId        Variable
}

func EmptyDepositNftTxWitness() (witness DepositNftTxConstraints) {
	return DepositNftTxConstraints{
		AccountIndex:        ZeroInt,
		AccountNameHash:     ZeroInt,
		NftIndex:            ZeroInt,
		NftContentHash:      ZeroInt,
		CreatorAccountIndex: ZeroInt,
		CreatorTreasuryRate: ZeroInt,
		CollectionId:        ZeroInt,
	}
}

func SetDepositNftTxWitness(tx *DepositNftTx) (witness DepositNftTxConstraints) {
	witness = DepositNftTxConstraints{
		AccountIndex:        tx.AccountIndex,
		AccountNameHash:     tx.AccountNameHash,
		NftIndex:            tx.NftIndex,
		NftContentHash:      tx.NftContentHash,
		CreatorAccountIndex: tx.CreatorAccountIndex,
		CreatorTreasuryRate: tx.CreatorTreasuryRate,
		CollectionId:        tx.CollectionId,
	}
	return witness
}

func VerifyDepositNftTx(
	api API,
	flag Variable,
	tx DepositNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	pubData = CollectPubDataFromDepositNft(api, tx)

	// verify params
	// check empty nft
	CheckEmptyNftNode(api, flag, nftBefore)
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.AccountNameHash, accountsBefore[0].AccountNameHash)
	return pubData
}

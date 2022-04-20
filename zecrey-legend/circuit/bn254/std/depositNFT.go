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

type DepositNftTx struct {
	AccountName    string
	NftIndex       uint64
	NftAssetId     uint64
	NftTokenId     uint64
	NftContentHash string
	NftL1Address   string
}

type DepositNftTxConstraints struct {
	AccountName    Variable
	NftIndex       Variable
	NftAssetId     Variable
	NftTokenId     Variable
	NftContentHash Variable
	NftL1Address   Variable
}

func EmptyDepositNftTxWitness() (witness DepositNftTxConstraints) {
	return DepositNftTxConstraints{
		AccountName:    ZeroInt,
		NftIndex:       ZeroInt,
		NftAssetId:     ZeroInt,
		NftTokenId:     ZeroInt,
		NftContentHash: ZeroInt,
		NftL1Address:   ZeroInt,
	}
}

func SetDepositNftTxWitness(tx *DepositNftTx) (witness DepositNftTxConstraints) {
	witness = DepositNftTxConstraints{
		AccountName:    tx.AccountName,
		NftIndex:       tx.NftIndex,
		NftAssetId:     tx.NftAssetId,
		NftTokenId:     tx.NftTokenId,
		NftContentHash: tx.NftContentHash,
		NftL1Address:   tx.NftL1Address,
	}
	return witness
}

/*
	VerifyDepositNftTx:
	accounts order is:
	- FromAccount
		- Nft
			- nft index
*/
func VerifyDepositNftTx(api API, flag Variable, nilHash Variable, tx DepositNftTxConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// nft index
	IsVariableEqual(api, flag, tx.NftAssetId, accountsBefore[0].NftInfo.NftAccountIndex)
	// before account nft should be empty
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftIndex, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftContentHash, nilHash)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetAmount, DefaultInt)
	// new nft should be right
	IsVariableEqual(api, flag, tx.NftIndex, accountsAfter[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftContentHash, accountsAfter[0].NftInfo.NftContentHash)
	IsVariableEqual(api, flag, tx.NftTokenId, accountsAfter[0].NftInfo.L1TokenId)
	IsVariableEqual(api, flag, tx.NftL1Address, accountsAfter[0].NftInfo.L1Address)
}

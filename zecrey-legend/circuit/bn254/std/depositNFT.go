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

import "math/big"

type DepositNftTx struct {
	AccountIndex    int64
	AccountNameHash []byte
	NftIndex        int64
	NftContentHash  []byte
	NftL1Address    *big.Int
	NftL1TokenId    *big.Int
}

type DepositNftTxConstraints struct {
	AccountIndex    Variable
	AccountNameHash Variable
	NftIndex        Variable
	NftContentHash  Variable
	NftL1Address    Variable
	NftL1TokenId    Variable
}

func EmptyDepositNftTxWitness() (witness DepositNftTxConstraints) {
	return DepositNftTxConstraints{
		AccountIndex:    ZeroInt,
		AccountNameHash: ZeroInt,
		NftIndex:        ZeroInt,
		NftContentHash:  ZeroInt,
		NftL1Address:    ZeroInt,
		NftL1TokenId:    ZeroInt,
	}
}

func SetDepositNftTxWitness(tx *DepositNftTx) (witness DepositNftTxConstraints) {
	witness = DepositNftTxConstraints{
		AccountIndex:    tx.AccountIndex,
		AccountNameHash: tx.AccountNameHash,
		NftIndex:        tx.NftIndex,
		NftContentHash:  tx.NftContentHash,
		NftL1Address:    tx.NftL1Address,
		NftL1TokenId:    tx.NftL1TokenId,
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
func VerifyDepositNftTx(
	api API,
	flag Variable,
	tx DepositNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
) {
	// verify params
	// check empty nft
	CheckEmptyNftNode(api, flag, nftBefore)
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	// account name hash
	IsVariableEqual(api, flag, tx.AccountNameHash, accountsBefore[0].AccountNameHash)
}

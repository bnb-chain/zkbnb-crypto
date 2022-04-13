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
	NftTokenId     uint64
	NftContentHash string
	NftL1Address   string
}

type DepositNftTxConstraints struct {
	AccountName    Variable
	NftTokenId     Variable
	NftContentHash Variable
	NftL1Address   Variable
}

func EmptyDepositNftTxWitness() (witness DepositNftTxConstraints) {
	return DepositNftTxConstraints{
		AccountName:    ZeroInt,
		NftTokenId:     ZeroInt,
		NftContentHash: ZeroInt,
		NftL1Address:   ZeroInt,
	}
}

func SetDepositNftTxWitness(tx *DepositNftTx) (witness DepositNftTxConstraints) {
	witness = DepositNftTxConstraints{
		AccountName:    tx.AccountName,
		NftTokenId:     tx.NftTokenId,
		NftContentHash: tx.NftContentHash,
		NftL1Address:   tx.NftL1Address,
	}
	return witness
}

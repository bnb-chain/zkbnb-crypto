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

type DepositTx struct {
	AccountIndex    int64
	AccountNameHash []byte
	AssetId         int64
	AssetAmount     *big.Int
}

type DepositTxConstraints struct {
	AccountIndex    Variable
	AccountNameHash Variable
	AssetId         Variable
	AssetAmount     Variable
}

func EmptyDepositTxWitness() (witness DepositTxConstraints) {
	return DepositTxConstraints{
		AccountIndex:    ZeroInt,
		AccountNameHash: ZeroInt,
		AssetId:         ZeroInt,
		AssetAmount:     ZeroInt,
	}
}

func SetDepositTxWitness(tx *DepositTx) (witness DepositTxConstraints) {
	witness = DepositTxConstraints{
		AccountIndex:    tx.AccountIndex,
		AccountNameHash: tx.AccountNameHash,
		AssetId:         tx.AssetId,
		AssetAmount:     tx.AssetAmount,
	}
	return witness
}

func VerifyDepositTx(
	api API, flag Variable,
	tx DepositTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	pubData = CollectPubDataFromDeposit(api, tx)
	// verify params
	IsVariableEqual(api, flag, tx.AccountNameHash, accountsBefore[0].AccountNameHash)
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	return pubData
}

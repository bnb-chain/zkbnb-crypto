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

type DepositTx struct {
	AccountName string
	AssetId     uint32
	AssetAmount *big.Int
}

type DepositTxConstraints struct {
	AccountName Variable
	AssetId     Variable
	AssetAmount Variable
}

func EmptyDepositTxWitness() (witness DepositTxConstraints) {
	return DepositTxConstraints{
		AccountName: ZeroInt,
		AssetId:     ZeroInt,
		AssetAmount: ZeroInt,
	}
}

func SetDepositTxWitness(tx *DepositTx) (witness DepositTxConstraints) {
	witness = DepositTxConstraints{
		AccountName: tx.AccountName,
		AssetId:     tx.AssetId,
		AssetAmount: tx.AssetAmount,
	}
	return witness
}

/*
	VerifyDepositTx:
	accounts order is:
	- FromAccount
		- Assets
			- AssetA
 */
func VerifyDepositTx(api API, flag Variable, tx DepositTxConstraints, accountsBefore [NbAccountsPerTx]AccountConstraints) {
	// verify params
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
}

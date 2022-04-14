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

import (
	"log"
	"math/big"
)

type DepositOrLockTxConstraints struct {
	ChainId       Variable
	AssetId       Variable
	AccountIndex  Variable
	AccountName   Variable
	NativeAddress Variable
	Amount        Variable
	IsEnabled     Variable
}

type DepositOrLockTx struct {
	ChainId       uint64
	AssetId       uint64
	AccountIndex  uint64
	AccountName   *big.Int
	NativeAddress *big.Int
	Amount        uint64
}

func SetEmptyDepositOrLockWitness() (witness DepositOrLockTxConstraints) {
	witness.ChainId = ZeroInt
	witness.AssetId = ZeroInt
	witness.AccountIndex = ZeroInt
	witness.AccountName = ZeroInt
	witness.NativeAddress = ZeroInt
	witness.Amount = ZeroInt
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

func SetDepositOrLockWitness(tx *DepositOrLockTx, isEnabled bool) (witness DepositOrLockTxConstraints, err error) {
	if tx == nil {
		log.Println("[SetDepositOrLockWitness] invalid params")
		return witness, err
	}
	witness.ChainId = tx.ChainId
	witness.AssetId = tx.AssetId
	witness.AccountIndex = tx.AccountIndex
	witness.AccountName = tx.AccountName
	witness.NativeAddress = tx.NativeAddress
	witness.Amount = tx.Amount
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

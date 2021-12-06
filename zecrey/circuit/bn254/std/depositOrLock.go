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
	witness.ChainId.Assign(ZeroInt)
	witness.AssetId.Assign(ZeroInt)
	witness.AccountIndex.Assign(ZeroInt)
	witness.AccountName.Assign(ZeroInt)
	witness.NativeAddress.Assign(ZeroInt)
	witness.Amount.Assign(ZeroInt)
	return witness
}

func SetDepositOrLockWitness(tx *DepositOrLockTx, isEnabled bool) (witness DepositOrLockTxConstraints, err error) {
	if tx == nil {
		log.Println("[SetDepositOrLockWitness] invalid params")
		return witness, err
	}
	witness.ChainId.Assign(tx.ChainId)
	witness.AssetId.Assign(tx.AssetId)
	witness.AccountIndex.Assign(tx.AccountIndex)
	witness.AccountName.Assign(tx.AccountName)
	witness.NativeAddress.Assign(tx.NativeAddress)
	witness.Amount.Assign(tx.Amount)
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

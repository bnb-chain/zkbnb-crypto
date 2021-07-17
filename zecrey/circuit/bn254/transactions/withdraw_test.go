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

package transactions

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestVerifyWithdrawTx(t *testing.T) {
	assert := groth16.NewAssert(t)
	var circuit, witness WithdrawTxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	tx := prepareWithdrawTx()
	witness, err = SetWithdrawTxWitness(tx)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
}

func prepareWithdrawTx() *WithdrawTx {
	accounts, sks, balances, hashState := MockAccountTree(8)
	pos := 2
	accountBeforeWithdraw := accounts[pos]
	sk := sks[pos]
	// withdraw amount
	receiveAddr := "0xb1c297bBb2DC33F3c68920F02e88d2746b2F456d"
	amount := big.NewInt(int64(6))
	fee := big.NewInt(0)
	relation, err := zecrey.NewWithdrawRelation(accountBeforeWithdraw.Balance, accountBeforeWithdraw.PubKey, balances[pos], amount, sk, accountBeforeWithdraw.TokenId, receiveAddr, fee)
	if err != nil {
		panic(err)
	}
	proof, err := zecrey.ProveWithdraw(relation)
	if err != nil {
		panic(err)
	}
	// update balance
	newBalance := &zecrey.ElGamalEnc{
		CL: accountBeforeWithdraw.Balance.CL,
		CR: curve.Add(accountBeforeWithdraw.Balance.CR, relation.CRStar),
	}

	// accountBeforeWithdraw after deposit
	var accountAfterWithdraw Account
	accountAfterWithdraw = *accountBeforeWithdraw
	accountAfterWithdraw.Balance = newBalance

	// fee related
	feePos := uint64(0)
	var feeAccountBefore, feeAccountAfter Account
	feeAccountBefore = *accounts[feePos]
	feeAccountAfter = *accounts[feePos]
	feeNewBalance := &zecrey.ElGamalEnc{
		CL: feeAccountAfter.Balance.CL,
		CR: curve.Add(feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, fee)),
	}
	feeAccountAfter.Balance = feeNewBalance

	// create deposit tx
	tx, _, _ := mockWithdrawTx(true, proof, accounts, hashState, accountBeforeWithdraw, &accountAfterWithdraw, uint64(pos), fee, &feeAccountBefore, &feeAccountAfter, feePos)
	return tx
}

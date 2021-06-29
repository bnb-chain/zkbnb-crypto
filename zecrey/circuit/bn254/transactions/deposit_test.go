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
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestVerifyDepositTransaction(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness DepositTxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	tx := prepareTx()
	witness, err = SetDepositTxWitness(tx)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
}

func prepareTx() *DepositTx {
	// get keypair
	_, pk := twistedElgamal.GenKeyPair()
	// balance
	b := big.NewInt(0)
	// random value
	r := curve.RandomValue()
	// encryption
	balance, _ := twistedElgamal.Enc(b, r, pk)
	// account before deposit
	tokenId := uint32(1)
	accountBeforeDeposit := &Account{
		Index:   uint32(1),
		TokenId: tokenId,
		Balance: balance,
		PubKey:  pk,
	}
	// deposit amount
	amount := big.NewInt(int64(6))
	// update balance
	CRDelta := curve.ScalarMul(curve.H, amount)
	newBalance := &zecrey.ElGamalEnc{
		CL: balance.CL,
		CR: curve.Add(balance.CR, CRDelta),
	}
	// account after deposit
	var accountAfterDeposit Account
	accountAfterDeposit = *accountBeforeDeposit
	accountAfterDeposit.Balance = newBalance
	// create deposit tx
	tx := mockDepositTx(true, tokenId, pk, amount, accountBeforeDeposit, &accountAfterDeposit)
	return tx
}

func mockDepositTx(isEnabled bool, tokenId uint32, pk *zecrey.Point, amount *big.Int, acc1, acc2 *Account) *DepositTx {
	tx := &DepositTx{
		IsEnabled: isEnabled,
		// token id
		TokenId: tokenId,
		// Public key
		PublicKey: pk,
		// deposit amount
		Amount: amount,
		// old Account Info
		AccountBeforeDeposit: acc1,
		// new Account Info
		AccountAfterDeposit: acc2,
		// generator
		H: zecrey.H,
	}
	return tx
}

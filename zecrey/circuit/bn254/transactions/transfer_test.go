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

func TestVerifyTransferTx(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness TransferTxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	tx := prepareTransferTx()
	witness, err = SetTransferTxWitness(tx)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
}

func prepareTransferTx() *TransferTx {
	accounts, sks, balances, hashState := MockAccountTree(8)
	pos1 := uint64(1)
	pos2 := uint64(6)
	pos3 := uint64(2)
	poses := [NbTransferCount]uint64{pos1, pos2, pos3}
	accountBeforeTransfer1 := accounts[pos1]
	accountBeforeTransfer2 := accounts[pos2]
	accountBeforeTransfer3 := accounts[pos3]
	acc1 := [NbTransferCount]*Account{accountBeforeTransfer1, accountBeforeTransfer2, accountBeforeTransfer3}
	var acc2 [NbTransferCount]*Account
	sk1 := sks[pos1]
	b1 := big.NewInt(-6)
	b2 := big.NewInt(1)
	b3 := big.NewInt(4)
	fee := big.NewInt(1)
	tokenId := uint32(1)
	relation, err := zecrey.NewTransferProofRelation(tokenId, fee)
	if err != nil {
		panic(err)
	}

	relation.AddStatement(accountBeforeTransfer1.Balance, accountBeforeTransfer1.PubKey, balances[pos1], b1, sk1)
	relation.AddStatement(accountBeforeTransfer2.Balance, accountBeforeTransfer2.PubKey, nil, b2, nil)
	relation.AddStatement(accountBeforeTransfer3.Balance, accountBeforeTransfer3.PubKey, nil, b3, nil)
	proof, err := zecrey.ProveTransfer(relation)
	if err != nil {
		panic(err)
	}
	for i := 0; i < NbTransferCount; i++ {
		// update balance
		newBalance, err := twistedElgamal.EncAdd(accounts[poses[i]].Balance, relation.Statements[i].CDelta)
		if err != nil {
			panic(err)
		}
		// accountBeforeWithdraw after deposit
		var accountAfterTransfer Account
		accountAfterTransfer = *accounts[poses[i]]
		accountAfterTransfer.Balance = newBalance
		acc2[i] = &accountAfterTransfer
	}

	// fee related
	feePos := uint64(0)
	var feeAccountBefore, feeAccountAfter Account
	feeAccountBefore = *accounts[feePos]
	feeAccountAfter = *accounts[feePos]
	newBalance := &zecrey.ElGamalEnc{
		CL: feeAccountAfter.Balance.CL,
		CR: curve.Add(feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, fee)),
	}
	feeAccountAfter.Balance = newBalance
	// create deposit tx
	tx, _, _ := mockTransferTx(true, proof, accounts, hashState, acc1, acc2, poses, &feeAccountBefore, &feeAccountAfter, feePos, fee)
	return tx
}

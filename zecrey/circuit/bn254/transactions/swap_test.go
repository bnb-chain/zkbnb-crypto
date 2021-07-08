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

func TestVerifySwapTx(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness SwapTxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	txT1, txT2 := prepareSwapTx()
	// chain one
	witness, err = SetSwapTxWitness(txT1)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
	// chain two
	fmt.Println("start t2")
	witness, err = SetSwapTxWitness(txT2)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)

}

func prepareSwapTx() (*SwapTx, *SwapTx) {
	// mock two merkle trees
	accountsT1, accountsT2, sks, balancesT1, balancesT2, hashStateT1, hashStateT2 := mockTwoAccountTree(8)
	// two index array
	feePos := uint64(0)
	feeT1 := big.NewInt(1)
	// feeT1 related
	var T1feeAccountBefore, T1feeAccountAfter Account
	T1feeAccountBefore = *accountsT1[feePos]
	T1feeAccountAfter = *accountsT1[feePos]
	T1feeNewBalance := &zecrey.ElGamalEnc{
		CL: T1feeAccountAfter.Balance.CL,
		CR: curve.Add(T1feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, feeT1)),
	}
	T1feeAccountAfter.Balance = T1feeNewBalance

	// feeT1 related
	feeT2 := big.NewInt(0)
	var T2feeAccountBefore, T2feeAccountAfter Account
	T2feeAccountBefore = *accountsT1[feePos]
	T2feeAccountAfter = *accountsT1[feePos]
	T2feeNewBalance := &zecrey.ElGamalEnc{
		CL: T2feeAccountAfter.Balance.CL,
		CR: curve.Add(T2feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, feeT2)),
	}
	T2feeAccountAfter.Balance = T2feeNewBalance

	poses := [NbSwapCount]uint64{1, 3}
	// before swap first chain accounts
	accountBeforeSwap1 := accountsT1[poses[0]]
	accountBeforeSwap2 := accountsT1[poses[1]]
	accBeforeT1 := [NbSwapCount]*Account{accountBeforeSwap1, accountBeforeSwap2}
	// before swap second chain accounts
	// inverse index
	accountBeforeSwap3 := accountsT2[poses[1]]
	accountBeforeSwap4 := accountsT2[poses[0]]
	accBeforeT2 := [NbSwapCount]*Account{accountBeforeSwap3, accountBeforeSwap4}
	// create swap proof
	swapProof := mockSwapProof(accountsT1, accountsT2, sks, balancesT1, balancesT2, poses, feeT1)
	// acc after swap
	var accountAfterSwap1, accountAfterSwap2, accountAfterSwap3, accountAfterSwap4 Account
	accountAfterSwap1 = *accountBeforeSwap1
	accountAfterSwap2 = *accountBeforeSwap2
	accountAfterSwap3 = *accountBeforeSwap3
	accountAfterSwap4 = *accountBeforeSwap4
	accountAfterSwap1.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap1.Balance, swapProof.ProofPart1.CStar)
	accountAfterSwap2.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap2.Balance, swapProof.ProofPart1.ReceiverCStar)
	accountAfterSwap3.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap3.Balance, swapProof.ProofPart2.CStar)
	accountAfterSwap4.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap4.Balance, swapProof.ProofPart2.ReceiverCStar)

	accAfterT1 := [NbSwapCount]*Account{&accountAfterSwap1, &accountAfterSwap2}
	accAfterT2 := [NbSwapCount]*Account{&accountAfterSwap3, &accountAfterSwap4}

	inversePoses := [NbSwapCount]uint64{poses[1], poses[0]}
	// create deposit tx
	txT1, _, _ := mockSwapTx(true, true, swapProof, accountsT1, hashStateT1, accBeforeT1, accAfterT1, poses, feeT1, &T1feeAccountBefore, &T1feeAccountAfter, feePos)
	txT2, _, _ := mockSwapTx(true, false, swapProof, accountsT2, hashStateT2, accBeforeT2, accAfterT2, inversePoses, feeT2, &T2feeAccountBefore, &T2feeAccountAfter, feePos)
	return txT1, txT2
}

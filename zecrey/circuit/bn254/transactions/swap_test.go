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
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"math/big"
	"testing"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/hash/bn254/zmimc"
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

func mockSwapProof(accountsT1 []*Account, accountsT2 []*Account, sks []*big.Int, poses [NbSwapCount]uint64) *zecrey.SwapProof {
	// get accounts
	accT1A := accountsT1[poses[0]]
	accT2A := accountsT2[poses[0]]
	skA := sks[poses[0]]
	accT1B := accountsT1[poses[1]]
	accT2B := accountsT2[poses[1]]
	skB := sks[poses[1]]
	// from/to amount
	bStarFrom := big.NewInt(1)
	bStarTo := big.NewInt(8)
	// from/to tokenId
	fromTokenId := uint32(1)
	toTokenId := uint32(2)
	relationPart1, err := zecrey.NewSwapRelationPart1(accT1A.Balance, accT1B.Balance, accT1A.PubKey, accT1B.PubKey, bStarFrom, bStarTo, skA, fromTokenId, toTokenId)
	if err != nil {
		panic(err)
	}
	swapProofPart1, err := zecrey.ProveSwapPart1(relationPart1, true)
	if err != nil {
		panic(err)
	}
	part1Res, err := swapProofPart1.Verify()
	if err != nil || !part1Res {
		panic(err)
	}
	relationPart2, err := zecrey.NewSwapRelationPart2(accT2B.Balance, accT2A.Balance, accT2B.PubKey, accT2A.PubKey, skB, fromTokenId, toTokenId, swapProofPart1)
	if err != nil {
		panic(err)
	}
	swapProof, err := zecrey.ProveSwapPart2(relationPart2, swapProofPart1)
	if err != nil {
		panic(err)
	}
	return swapProof
}

func prepareSwapTx() (*SwapTx, *SwapTx) {
	// mock two merkle trees
	accountsT1, accountsT2, sks, hashStateT1, hashStateT2 := mockTwoAccountTree(8)
	// two index array
	poses := [NbSwapCount]uint64{0, 3}
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
	swapProof := mockSwapProof(accountsT1, accountsT2, sks, poses)
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
	txT1, _, _ := mockSwapTx(true, true, swapProof, accountsT1, hashStateT1, accBeforeT1, accAfterT1, poses)
	txT2, _, _ := mockSwapTx(true, false, swapProof, accountsT2, hashStateT2, accBeforeT2, accAfterT2, inversePoses)
	return txT1, txT2
}

func mockSwapTx(isEnabled, isFirstProof bool, proof *zecrey.SwapProof, accounts []*Account, hashState []byte, acc1, acc2 [NbSwapCount]*Account, poses [NbSwapCount]uint64) (*SwapTx, []*Account, []byte) {
	tx := &SwapTx{
		IsEnabled:    isEnabled,
		IsFirstProof: isFirstProof,
		Proof:        proof,
	}
	// old merkle proofs
	var buf bytes.Buffer
	h := zmimc.Hmimc
	// old merkle proof
	for i := 0; i < NbSwapCount; i++ {
		buf.Reset()
		buf.Write(hashState)
		h.Reset()
		merkleRootBefore, proofInclusionTransferBefore, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), poses[i])
		if err != nil {
			panic(err)
		}
		merkleProofHelperTransferBefore := merkle.GenerateProofHelper(proofInclusionTransferBefore, poses[i], numLeaves)
		tx.AccountMerkleProofsBefore[i] = setFixedMerkleProofs(proofInclusionTransferBefore)
		tx.AccountHelperMerkleProofsBefore[i] = setFixedMerkleProofsHelper(merkleProofHelperTransferBefore)
		tx.OldAccountRoot = merkleRootBefore
		tx.AccountBefore[i] = acc1[i]
		tx.AccountAfter[i] = acc2[i]
	}
	for i := 0; i < NbSwapCount; i++ {
		accounts, hashState = mockUpdateAccount(accounts, hashState, int(poses[i]), acc2[i])
	}
	for i := 0; i < NbSwapCount; i++ {
		// new merkle proofs
		buf.Reset()
		buf.Write(hashState)
		h.Reset()
		merkleRootAfter, proofInclusionTransferAfter, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), poses[i])
		if err != nil {
			panic(err)
		}
		merkleProofHelperTransferAfter := merkle.GenerateProofHelper(proofInclusionTransferAfter, poses[i], numLeaves)
		tx.AccountMerkleProofsAfter[i] = setFixedMerkleProofs(proofInclusionTransferAfter)
		tx.AccountHelperMerkleProofsAfter[i] = setFixedMerkleProofsHelper(merkleProofHelperTransferAfter)
		tx.NewAccountRoot = merkleRootAfter
	}

	return tx, accounts, hashState
}

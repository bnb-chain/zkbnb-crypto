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
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/hash/bn254/zmimc"
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
	accounts, sks, hashState := mockAccountTree(4)
	pos := 2
	accountBeforeWithdraw := accounts[2]
	sk := sks[2]
	// withdraw amount
	receiveAddr := "0xb1c297bBb2DC33F3c68920F02e88d2746b2F456d"
	amount := big.NewInt(int64(6))
	relation, err := zecrey.NewWithdrawRelation(accountBeforeWithdraw.Balance, accountBeforeWithdraw.PubKey, ffmath.Neg(amount), sk, accountBeforeWithdraw.TokenId, receiveAddr)
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
	// create deposit tx
	tx := mockWithdrawTx(true, proof, accounts, hashState, accountBeforeWithdraw, &accountAfterWithdraw, uint64(pos))
	return tx
}

func setFixedMerkleProofs(proof [][]byte) [AccountMerkleLevels][]byte {
	var res [AccountMerkleLevels][]byte
	for i := 0; i < AccountMerkleLevels; i++ {
		res[i] = proof[i]
	}
	return res
}

func setFixedMerkleProofsHelper(proof []int) [AccountMerkleLevels - 1]int {
	var res [AccountMerkleLevels - 1]int
	for i := 0; i < AccountMerkleLevels-1; i++ {
		res[i] = proof[i]
	}
	return res
}

func mockWithdrawTx(isEnabled bool, proof *zecrey.WithdrawProof, accounts []*Account, hashState []byte, acc1, acc2 *Account, pos uint64) *WithdrawTx {
	// old merkle proofs
	var buf bytes.Buffer
	buf.Write(hashState)
	h := zmimc.Hmimc
	h.Reset()
	merkleRootBefore, proofInclusionWithdrawBefore, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), pos)
	if err != nil {
		panic(err)
	}
	merkleProofHelperWithdrawBefore := merkle.GenerateProofHelper(proofInclusionWithdrawBefore, pos, numLeaves)
	accounts, hashState = mockUpdateAccount(accounts, hashState, int(pos), acc2)
	// new merkle proofs
	buf.Reset()
	buf.Write(hashState)
	h.Reset()
	merkleRootAfter, proofInclusionWithdrawAfter, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), pos)
	if err != nil {
		panic(err)
	}
	merkleProofHelperWithdrawAfter := merkle.GenerateProofHelper(proofInclusionWithdrawAfter, pos, numLeaves)

	tx := &WithdrawTx{
		IsEnabled: isEnabled,
		// withdraw proof
		Proof: proof,
		// before withdraw merkle proof
		AccountMerkleProofsBefore:       setFixedMerkleProofs(proofInclusionWithdrawBefore),
		AccountHelperMerkleProofsBefore: setFixedMerkleProofsHelper(merkleProofHelperWithdrawBefore),

		// after withdraw merkle proof
		AccountMerkleProofsAfter:       setFixedMerkleProofs(proofInclusionWithdrawAfter),
		AccountHelperMerkleProofsAfter: setFixedMerkleProofsHelper(merkleProofHelperWithdrawAfter),

		// old Account Info
		AccountBeforeWithdraw: acc1,
		// new Account Info
		AccountAfterWithdraw: acc2,

		// old account root
		OldAccountRoot: merkleRootBefore,
		// new account root
		NewAccountRoot: merkleRootAfter,
	}
	return tx
}

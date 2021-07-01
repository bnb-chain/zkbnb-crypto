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
	accounts, sks, hashState := mockAccountTree(8)
	pos1 := uint64(0)
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
	b3 := big.NewInt(5)
	tokenId := uint32(1)
	relation, err := zecrey.NewPTransferProofRelation(tokenId)
	if err != nil {
		panic(err)
	}

	relation.AddStatement(accountBeforeTransfer1.Balance, accountBeforeTransfer1.PubKey, b1, sk1)
	relation.AddStatement(accountBeforeTransfer2.Balance, accountBeforeTransfer2.PubKey, b2, nil)
	relation.AddStatement(accountBeforeTransfer3.Balance, accountBeforeTransfer3.PubKey, b3, nil)
	proof, err := zecrey.ProvePTransfer(relation)
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

	// create deposit tx
	tx := mockTransferTx(true, proof, accounts, hashState, acc1, acc2, poses)
	return tx
}

func mockTransferTx(isEnabled bool, proof *zecrey.PTransferProof, accounts []*Account, hashState []byte, acc1, acc2 [NbTransferCount]*Account, poses [NbTransferCount]uint64) *TransferTx {
	tx := &TransferTx{
		IsEnabled: isEnabled,
		Proof:     proof,
	}
	// old merkle proofs
	var buf bytes.Buffer
	h := zmimc.Hmimc
	// old merkle proof
	for i := 0; i < NbTransferCount; i++ {
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
		tx.AccountBeforeTransfer[i] = acc1[i]
		tx.AccountAfterTransfer[i] = acc2[i]
	}
	for i := 0; i < NbTransferCount; i++ {
		accounts, hashState = mockUpdateAccount(accounts, hashState, int(poses[i]), acc2[i])
	}
	for i := 0; i < NbTransferCount; i++ {
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

	return tx
}

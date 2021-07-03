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
	"zecrey-crypto/hash/bn254/zmimc"
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
	tx := prepareDepositTx()
	witness, err = SetDepositTxWitness(tx)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
}

func prepareDepositTx() *DepositTx {
	accounts, _, hashState := mockAccountTree(8)
	pos := 3
	accountBeforeDeposit := accounts[pos]
	// deposit amount
	amount := big.NewInt(int64(6))
	// update balance
	CRDelta := curve.ScalarMul(curve.H, amount)
	newBalance := &zecrey.ElGamalEnc{
		CL: accountBeforeDeposit.Balance.CL,
		CR: curve.Add(accountBeforeDeposit.Balance.CR, CRDelta),
	}
	// account after deposit
	var accountAfterDeposit Account
	accountAfterDeposit = *accountBeforeDeposit
	accountAfterDeposit.Balance = newBalance
	// create deposit tx
	tx, _, _ := mockDepositTx(true, accountBeforeDeposit.TokenId, accounts, hashState, accountBeforeDeposit.PubKey, amount, accountBeforeDeposit, &accountAfterDeposit, uint64(pos))
	return tx
}

func mockDepositTx(isEnabled bool, tokenId uint32, accounts []*Account, hashState []byte, pk *zecrey.Point, amount *big.Int, acc1, acc2 *Account, pos uint64) (*DepositTx, []*Account, []byte) {
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
	tx := &DepositTx{
		IsEnabled: isEnabled,
		// token id
		TokenId: tokenId,
		// Public key
		PublicKey: pk,
		// deposit amount
		Amount: amount,
		// old Account Info
		AccountBefore: acc1,
		// new Account Info
		AccountAfter: acc2,
		// generator
		H: zecrey.H,

		// before deposit merkle proof
		AccountMerkleProofsBefore:       setFixedMerkleProofs(proofInclusionWithdrawBefore),
		AccountHelperMerkleProofsBefore: setFixedMerkleProofsHelper(merkleProofHelperWithdrawBefore),

		// after deposit merkle proof
		AccountMerkleProofsAfter:       setFixedMerkleProofs(proofInclusionWithdrawAfter),
		AccountHelperMerkleProofsAfter: setFixedMerkleProofsHelper(merkleProofHelperWithdrawAfter),

		// old account root
		OldAccountRoot: merkleRootBefore,
		// new account root
		NewAccountRoot: merkleRootAfter,
	}
	return tx, accounts, hashState
}

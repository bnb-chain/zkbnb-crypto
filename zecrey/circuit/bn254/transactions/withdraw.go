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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"zecrey-crypto/zecrey/circuit/bn254/std"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type WithdrawTxConstraints struct {
	// is enabled
	IsEnabled Variable
	// withdraw proof
	Proof std.WithdrawProofConstraints
	// before withdraw merkle proof
	AccountMerkleProofsBefore       [AccountMerkleLevels]Variable
	AccountHelperMerkleProofsBefore [AccountMerkleLevels - 1]Variable

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [AccountMerkleLevels]Variable
	AccountHelperMerkleProofsAfter [AccountMerkleLevels - 1]Variable

	// old Account Info
	AccountBeforeWithdraw AccountConstraints
	// new Account Info
	AccountAfterWithdraw AccountConstraints

	// old account root
	OldAccountRoot Variable
	// new account root
	NewAccountRoot Variable
}

func (circuit *WithdrawTxConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC("ZecreyMIMCSeed", curveID)

	VerifyWithdrawTx(cs, *circuit, params, hFunc)

	return nil
}

/*
	VerifyWithdrawTx: verify withdraw transaction
	1. check account index
	2. check token id
	3. check public key
	4. check merkle proof: before & after
	5. update balance
	6. check updated balance
	7. verify withdraw proof
*/
func VerifyWithdrawTx(cs *ConstraintSystem, tx WithdrawTxConstraints, params twistededwards.EdCurve, hFunc MiMC) {
	// universal check
	// check index
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeWithdraw.Index, tx.AccountAfterWithdraw.Index)
	// check token id
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeWithdraw.TokenId, tx.AccountAfterWithdraw.TokenId)
	// check public key
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeWithdraw.PubKey, tx.AccountAfterWithdraw.PubKey)
	// check merkle proof
	std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[:], tx.AccountHelperMerkleProofsBefore[:])
	std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[:], tx.AccountHelperMerkleProofsAfter[:])
	// update balance first
	// get CRDelta
	var newCR Point
	// update balance
	newCR.AddGeneric(cs, &tx.AccountBeforeWithdraw.Balance.CR, &tx.Proof.CRStar, params)
	tx.AccountBeforeWithdraw.Balance.CR = newCR
	// check updated balance
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBeforeWithdraw.Balance, tx.AccountAfterWithdraw.Balance)
	// verify withdraw proof
	std.VerifyWithdrawProof(cs, tx.Proof, params)
}

/*
	WithdrawTx: withdraw transaction
	TODO only for test
*/
type WithdrawTx struct {
	// is enabled
	IsEnabled bool
	// withdraw proof
	Proof *zecrey.WithdrawProof
	// before withdraw merkle proof
	AccountMerkleProofsBefore       [AccountMerkleLevels][]byte
	AccountHelperMerkleProofsBefore [AccountMerkleLevels - 1]int

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [AccountMerkleLevels][]byte
	AccountHelperMerkleProofsAfter [AccountMerkleLevels - 1]int

	// old Account Info
	AccountBefore *Account
	// new Account Info
	AccountAfter *Account

	// old account root
	OldAccountRoot []byte
	// new account root
	NewAccountRoot []byte
}

/*
	SetWithdrawTxWitness: set witness for withdraw transaction
*/
func SetWithdrawTxWitness(tx *WithdrawTx) (witness WithdrawTxConstraints, err error) {
	// set merkle proofs witness
	witness.AccountMerkleProofsBefore = std.SetMerkleProofsWitness(tx.AccountMerkleProofsBefore)
	witness.AccountHelperMerkleProofsBefore = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsBefore)
	witness.AccountMerkleProofsAfter = std.SetMerkleProofsWitness(tx.AccountMerkleProofsAfter)
	witness.AccountHelperMerkleProofsAfter = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsAfter)

	// set account witness
	witness.AccountBeforeWithdraw, err = SetAccountWitness(tx.AccountBefore)
	witness.AccountAfterWithdraw, err = SetAccountWitness(tx.AccountAfter)

	// set account root witness
	witness.OldAccountRoot.Assign(tx.OldAccountRoot)
	witness.NewAccountRoot.Assign(tx.NewAccountRoot)

	// set proof
	witness.Proof, err = std.SetWithdrawProofWitness(tx.Proof, tx.IsEnabled)

	witness.IsEnabled = std.SetBoolWitness(tx.IsEnabled)
	return witness, nil
}

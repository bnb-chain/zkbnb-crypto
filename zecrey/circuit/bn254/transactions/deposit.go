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
	"math/big"
	"zecrey-crypto/zecrey/circuit/bn254/std"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	DepositTxConstraints: deposit transaction
*/
type DepositTxConstraints struct {
	// enable deposit or not
	IsEnabled Variable
	// token id
	AssetId Variable
	// Public key
	PublicKey Point
	// deposit amount
	Amount Variable
	// old Account Info
	AccountBeforeDeposit AccountConstraints
	// new Account Info
	AccountAfterDeposit AccountConstraints
	// generator
	H Point

	// before deposit merkle proof
	AccountMerkleProofsBefore       []Variable
	AccountHelperMerkleProofsBefore []Variable

	// after deposit merkle proof
	AccountMerkleProofsAfter       []Variable
	AccountHelperMerkleProofsAfter []Variable

	// old account root
	OldAccountRoot Variable
	// new account root
	NewAccountRoot Variable
}

func (circuit *DepositTxConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC("ZecreyMIMCSeed", curveID, cs)
	VerifyDepositTx(cs, *circuit, params, hFunc)

	return nil
}

/*
	VerifyDepositTx: verify deposit transaction
	1. check token id
	2. check public key
	3. check index
	4. update balance
	5. check new balance
*/
func VerifyDepositTx(cs *ConstraintSystem, tx DepositTxConstraints, params twistededwards.EdCurve, hFunc MiMC) {
	// universal check
	// check token id
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AssetId, tx.AccountBeforeDeposit.AssetId)
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AssetId, tx.AccountAfterDeposit.AssetId)
	// check public key
	std.IsPointEqual(cs, tx.IsEnabled, tx.PublicKey, tx.AccountBeforeDeposit.PubKey)
	std.IsPointEqual(cs, tx.IsEnabled, tx.PublicKey, tx.AccountAfterDeposit.PubKey)
	// check index
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeDeposit.Index, tx.AccountAfterDeposit.Index)
	// check merkle proof
	std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[:], tx.AccountHelperMerkleProofsBefore[:])
	std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[:], tx.AccountHelperMerkleProofsAfter[:])

	// get CRDelta
	var newCR Point
	newCR.ScalarMulNonFixedBase(cs, &tx.H, tx.Amount, params)
	// update balance
	newCR.AddGeneric(cs, &tx.AccountBeforeDeposit.Balance.CR, &newCR, params)
	tx.AccountBeforeDeposit.Balance.CR = newCR
	// check new balance
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBeforeDeposit.Balance, tx.AccountAfterDeposit.Balance)
}

/*
	DepositTxConstraints: deposit transaction
	TODO only for test
*/
type DepositTx struct {
	IsEnabled bool
	// token id
	TokenId uint32
	// Public key
	PublicKey *zecrey.Point
	// deposit amount
	Amount *big.Int
	// old Account Info
	AccountBefore *Account
	// new Account Info
	AccountAfter *Account
	// generator
	H *zecrey.Point

	// before deposit merkle proof
	AccountMerkleProofsBefore       [][]byte
	AccountHelperMerkleProofsBefore []int

	// after deposit merkle proof
	AccountMerkleProofsAfter       [][]byte
	AccountHelperMerkleProofsAfter []int

	// old account root
	OldAccountRoot []byte
	// new account root
	NewAccountRoot []byte
}

func SetDepositTxWitness(tx *DepositTx) (witness DepositTxConstraints, err error) {
	witness.AssetId.Assign(int(tx.TokenId))
	witness.PublicKey, err = std.SetPointWitness(tx.PublicKey)
	if err != nil {
		return witness, err
	}
	witness.Amount.Assign(tx.Amount)
	witness.AccountBeforeDeposit, err = SetAccountWitness(tx.AccountBefore)
	if err != nil {
		return witness, err
	}
	witness.AccountAfterDeposit, err = SetAccountWitness(tx.AccountAfter)
	if err != nil {
		return witness, err
	}
	witness.H, err = std.SetPointWitness(tx.H)
	if err != nil {
		return witness, err
	}

	// set merkle proofs witness
	witness.AccountMerkleProofsBefore = std.SetMerkleProofsWitness(tx.AccountMerkleProofsBefore, AccountMerkleLevels)
	witness.AccountHelperMerkleProofsBefore = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsBefore, AccountMerkleLevels-1)
	witness.AccountMerkleProofsAfter = std.SetMerkleProofsWitness(tx.AccountMerkleProofsAfter, AccountMerkleLevels)
	witness.AccountHelperMerkleProofsAfter = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsAfter, AccountMerkleLevels-1)

	// set account root witness
	witness.OldAccountRoot.Assign(tx.OldAccountRoot)
	witness.NewAccountRoot.Assign(tx.NewAccountRoot)

	witness.IsEnabled = std.SetBoolWitness(tx.IsEnabled)
	return witness, nil
}

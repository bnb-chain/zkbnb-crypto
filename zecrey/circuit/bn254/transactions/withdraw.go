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

type WithdrawTxConstraints struct {
	// is enabled
	IsEnabled Variable
	// withdraw proof
	Proof std.WithdrawProofConstraints
	// before withdraw merkle proof
	AccountMerkleProofsBefore       [NbWithdrawCountAndFee][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsBefore [NbWithdrawCountAndFee][AccountMerkleLevels - 1]Variable

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [NbWithdrawCountAndFee][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsAfter [NbWithdrawCountAndFee][AccountMerkleLevels - 1]Variable

	// old Account Info
	AccountBefore AccountConstraints
	// new Account Info
	AccountAfter AccountConstraints

	// fee related
	Fee              Variable
	FeeAccountBefore AccountConstraints
	FeeAccountAfter  AccountConstraints

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
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBefore.Index, tx.AccountAfter.Index)
	// check token id
	std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBefore.TokenId, tx.AccountAfter.TokenId)
	// check public key
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBefore.PubKey, tx.AccountAfter.PubKey)
	// check merkle proof
	for i := 0; i < NbWithdrawCountAndFee; i++ {
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[i][:], tx.AccountHelperMerkleProofsBefore[i][:])
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[i][:], tx.AccountHelperMerkleProofsAfter[i][:])
	}
	// fee related check
	std.IsVariableEqual(cs, tx.IsEnabled, tx.Fee, tx.Proof.Fee)
	std.IsVariableEqual(cs, tx.IsEnabled, tx.FeeAccountBefore.Index, tx.FeeAccountAfter.Index)
	std.IsVariableEqual(cs, tx.IsEnabled, tx.FeeAccountBefore.TokenId, tx.FeeAccountAfter.TokenId)
	std.IsPointEqual(cs, tx.IsEnabled, tx.FeeAccountBefore.PubKey, tx.FeeAccountAfter.PubKey)
	// update fee account
	// TODO need to optimize
	var fee Point
	fee.ScalarMulNonFixedBase(cs, &tx.Proof.H, tx.Fee, params)
	tx.FeeAccountBefore.Balance.CR = *tx.FeeAccountBefore.Balance.CR.AddGeneric(cs, &tx.FeeAccountBefore.Balance.CR, &fee, params)
	// check if the balance is equal
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.FeeAccountBefore.Balance, tx.FeeAccountAfter.Balance)

	// update balance first
	// get CRDelta
	var newCR Point
	// update balance
	newCR.AddGeneric(cs, &tx.AccountBefore.Balance.CR, &tx.Proof.CRStar, params)
	tx.AccountBefore.Balance.CR = newCR
	// check updated balance
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBefore.Balance, tx.AccountAfter.Balance)
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
	AccountMerkleProofsBefore       [NbWithdrawCountAndFee][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsBefore [NbWithdrawCountAndFee][AccountMerkleLevels - 1]int

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [NbWithdrawCountAndFee][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsAfter [NbWithdrawCountAndFee][AccountMerkleLevels - 1]int

	// old Account Info
	AccountBefore *Account
	// new Account Info
	AccountAfter *Account

	// fee related
	Fee              *big.Int
	FeeAccountBefore *Account
	FeeAccountAfter  *Account

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
	for i := 0; i < NbWithdrawCountAndFee; i++ {
		witness.AccountMerkleProofsBefore[i] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsBefore[i])
		witness.AccountHelperMerkleProofsBefore[i] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsBefore[i])
		witness.AccountMerkleProofsAfter[i] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsAfter[i])
		witness.AccountHelperMerkleProofsAfter[i] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsAfter[i])
	}

	// set account witness
	witness.AccountBefore, err = SetAccountWitness(tx.AccountBefore)
	witness.AccountAfter, err = SetAccountWitness(tx.AccountAfter)

	// set account root witness
	witness.OldAccountRoot.Assign(tx.OldAccountRoot)
	witness.NewAccountRoot.Assign(tx.NewAccountRoot)

	// set fee related
	witness.Fee.Assign(tx.Fee)
	witness.FeeAccountBefore, err = SetAccountWitness(tx.FeeAccountBefore)
	if err != nil {
		return witness, err
	}
	witness.FeeAccountAfter, err = SetAccountWitness(tx.FeeAccountAfter)
	if err != nil {
		return witness, err
	}

	// set proof
	witness.Proof, err = std.SetWithdrawProofWitness(tx.Proof, tx.IsEnabled)

	witness.IsEnabled = std.SetBoolWitness(tx.IsEnabled)
	return witness, nil
}

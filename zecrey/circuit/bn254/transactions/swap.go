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

type SwapTxConstraints struct {
	// is enabled
	IsEnabled Variable
	// withdraw proof
	Proof std.SwapProofConstraints
	// is first proof
	IsFirstProof Variable
	// before withdraw merkle proof
	AccountMerkleProofsBefore       [NbSwapCountAndFee][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsBefore [NbSwapCountAndFee][AccountMerkleLevels - 1]Variable

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [NbSwapCountAndFee][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsAfter [NbSwapCountAndFee][AccountMerkleLevels - 1]Variable

	// old Account Info
	AccountBefore [NbSwapCount]AccountConstraints
	// new Account Info
	AccountAfter [NbSwapCount]AccountConstraints

	// fee
	Fee              Variable
	FeeAccountBefore AccountConstraints
	FeeAccountAfter  AccountConstraints

	// old account root
	OldAccountRoot Variable
	// new account root
	NewAccountRoot Variable
}

func (circuit *SwapTxConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC("ZecreyMIMCSeed", curveID)

	VerifySwapTx(cs, *circuit, params, hFunc)

	return nil
}

/*
	VerifySwapTx: verify swap transaction
	1. check public key match
	2. check balance match
	3. check index
	4. check token id
	5. check merkle proof
	6. check updated balance
	7. verify swap proof
*/
func VerifySwapTx(cs *ConstraintSystem, tx SwapTxConstraints, params twistededwards.EdCurve, hFunc MiMC) {
	// check public key match
	pk, receiverPk := selectPk(cs, tx.IsFirstProof, tx.Proof)
	// before
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBefore[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBefore[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBefore[1].PubKey, receiverPk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBefore[1].PubKey, receiverPk)
	// after
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfter[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfter[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfter[1].PubKey, receiverPk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfter[1].PubKey, receiverPk)
	// check balance match
	isFirstProof := cs.And(tx.IsEnabled, tx.IsFirstProof)
	std.IsElGamalEncEqual(cs, isFirstProof, tx.AccountBefore[0].Balance, tx.Proof.ProofPart1.C)
	std.IsElGamalEncEqual(cs, isFirstProof, tx.AccountBefore[1].Balance, tx.Proof.ProofPart1.ReceiverC)
	isSecondProof := cs.Sub(cs.Constant(1), tx.IsFirstProof)
	isSecondProof = cs.And(tx.IsEnabled, isSecondProof)
	std.IsElGamalEncEqual(cs, isSecondProof, tx.AccountBefore[0].Balance, tx.Proof.ProofPart2.C)
	std.IsElGamalEncEqual(cs, isSecondProof, tx.AccountBefore[1].Balance, tx.Proof.ProofPart2.ReceiverC)
	// universal check
	for i := 0; i < NbSwapCount; i++ {
		// check index
		std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBefore[i].Index, tx.AccountAfter[i].Index)
		// check token id
		std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBefore[i].TokenId, tx.AccountAfter[i].TokenId)
		// check public key
		std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBefore[i].PubKey, tx.AccountAfter[i].PubKey)
		// check merkle proof
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[i][:], tx.AccountHelperMerkleProofsBefore[i][:])
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[i][:], tx.AccountHelperMerkleProofsAfter[i][:])
	}
	// fee account
	// check index
	std.IsVariableEqual(cs, isFirstProof, tx.FeeAccountBefore.Index, tx.FeeAccountAfter.Index)
	// check token id
	std.IsVariableEqual(cs, isFirstProof, tx.FeeAccountBefore.TokenId, tx.FeeAccountAfter.TokenId)
	// check public key
	std.IsPointEqual(cs, isFirstProof, tx.FeeAccountBefore.PubKey, tx.FeeAccountAfter.PubKey)
	// check fee
	secondFee := cs.Select(isSecondProof, tx.Proof.ProofPart1.Fee, tx.Fee)
	std.IsVariableEqual(cs, tx.IsEnabled, secondFee, tx.Proof.ProofPart1.Fee)
	std.IsVariableEqual(cs, tx.IsEnabled, secondFee, tx.Proof.ProofPart2.Fee)
	// check merkle proof
	// if it is the first proof, do not check anything
	std.VerifyMerkleProof(cs, isFirstProof, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[NbSwapCount][:], tx.AccountHelperMerkleProofsBefore[NbSwapCount][:])
	std.VerifyMerkleProof(cs, isFirstProof, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[NbSwapCount][:], tx.AccountHelperMerkleProofsAfter[NbSwapCount][:])

	// update fee account
	realFee := cs.Select(isFirstProof, tx.Fee, cs.Constant(0))
	// TODO need to optimize
	var fee Point
	fee.ScalarMulNonFixedBase(cs, &tx.Proof.ProofPart1.H, realFee, params)
	tx.FeeAccountBefore.Balance.CR = *tx.FeeAccountBefore.Balance.CR.AddGeneric(cs, &tx.FeeAccountBefore.Balance.CR, &fee, params)
	// check if the balance is equal
	std.IsElGamalEncEqual(cs, isFirstProof, tx.FeeAccountBefore.Balance, tx.FeeAccountAfter.Balance)

	// select CStar
	CStar, ReceiverCStar := selectCStar(cs, tx.IsFirstProof, tx.Proof)
	// update balance
	tx.AccountBefore[0].Balance = std.EncAdd(cs, tx.AccountBefore[0].Balance, CStar, params)
	tx.AccountBefore[1].Balance = std.EncAdd(cs, tx.AccountBefore[1].Balance, ReceiverCStar, params)
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBefore[0].Balance, tx.AccountAfter[0].Balance)
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBefore[1].Balance, tx.AccountAfter[1].Balance)
	// verify swap proof
	std.VerifySwapProof(cs, tx.Proof, params)
}

/*
	SwapTx: swap transaction
	TODO only for test
*/
type SwapTx struct {
	// is enabled
	IsEnabled bool
	// withdraw proof
	Proof *zecrey.SwapProof
	// is first proof
	IsFirstProof bool
	// before withdraw merkle proof
	AccountMerkleProofsBefore       [NbSwapCountAndFee][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsBefore [NbSwapCountAndFee][AccountMerkleLevels - 1]int

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [NbSwapCountAndFee][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsAfter [NbSwapCountAndFee][AccountMerkleLevels - 1]int

	// old Account Info
	AccountBefore [NbSwapCount]*Account
	// new Account Info
	AccountAfter [NbSwapCount]*Account

	// fee
	Fee              *big.Int
	FeeAccountBefore *Account
	FeeAccountAfter  *Account

	// old account root
	OldAccountRoot []byte
	// new account root
	NewAccountRoot []byte
}

/*
	SetSwapTxWitness: set witness for swap transaction
*/
func SetSwapTxWitness(tx *SwapTx) (witness SwapTxConstraints, err error) {
	if tx == nil {
		return witness, std.ErrInvalidSetParams
	}
	for i := 0; i < NbSwapCount; i++ {
		// set merkle proofs witness
		witness.AccountMerkleProofsBefore[i] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsBefore[i])
		witness.AccountHelperMerkleProofsBefore[i] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsBefore[i])
		witness.AccountMerkleProofsAfter[i] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsAfter[i])
		witness.AccountHelperMerkleProofsAfter[i] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsAfter[i])

		// set account witness
		witness.AccountBefore[i], err = SetAccountWitness(tx.AccountBefore[i])
		witness.AccountAfter[i], err = SetAccountWitness(tx.AccountAfter[i])
	}
	// set merkle proofs witness
	witness.AccountMerkleProofsBefore[NbSwapCount] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsBefore[NbSwapCount])
	witness.AccountHelperMerkleProofsBefore[NbSwapCount] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsBefore[NbSwapCount])
	witness.AccountMerkleProofsAfter[NbSwapCount] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsAfter[NbSwapCount])
	witness.AccountHelperMerkleProofsAfter[NbSwapCount] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsAfter[NbSwapCount])

	witness.Fee.Assign(tx.Fee)
	witness.FeeAccountBefore, err = SetAccountWitness(tx.FeeAccountBefore)
	if err != nil {
		return witness, err
	}
	witness.FeeAccountAfter, err = SetAccountWitness(tx.FeeAccountAfter)
	if err != nil {
		return witness, err
	}

	// set account root witness
	witness.OldAccountRoot.Assign(tx.OldAccountRoot)
	witness.NewAccountRoot.Assign(tx.NewAccountRoot)

	// set proof
	witness.Proof, err = std.SetSwapProofWitness(tx.Proof, tx.IsEnabled)
	if err != nil {
		return witness, err
	}

	witness.IsEnabled = std.SetBoolWitness(tx.IsEnabled)
	witness.IsFirstProof = std.SetBoolWitness(tx.IsFirstProof)
	return witness, nil
}

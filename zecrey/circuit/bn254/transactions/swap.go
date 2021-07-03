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

type SwapTxConstraints struct {
	// is enabled
	IsEnabled Variable
	// withdraw proof
	Proof std.SwapProofConstraints
	// is first proof
	IsFirstProof Variable
	// before withdraw merkle proof
	AccountMerkleProofsBefore       [NbSwapCount][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsBefore [NbSwapCount][AccountMerkleLevels - 1]Variable

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [NbSwapCount][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsAfter [NbSwapCount][AccountMerkleLevels - 1]Variable

	// old Account Info
	AccountBeforeSwap [NbSwapCount]AccountConstraints
	// new Account Info
	AccountAfterSwap [NbSwapCount]AccountConstraints

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
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[1].PubKey, receiverPk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[1].PubKey, receiverPk)
	// after
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfterSwap[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfterSwap[0].PubKey, pk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfterSwap[1].PubKey, receiverPk)
	std.IsPointEqual(cs, tx.IsEnabled, tx.AccountAfterSwap[1].PubKey, receiverPk)
	// check balance match
	isFirstProof := cs.And(tx.IsEnabled, tx.IsFirstProof)
	std.IsElGamalEncEqual(cs, isFirstProof, tx.AccountBeforeSwap[0].Balance, tx.Proof.ProofPart1.C)
	std.IsElGamalEncEqual(cs, isFirstProof, tx.AccountBeforeSwap[1].Balance, tx.Proof.ProofPart1.ReceiverC)
	isSecondProof := cs.Sub(cs.Constant(1), tx.IsFirstProof)
	isSecondProof = cs.And(tx.IsEnabled, isSecondProof)
	std.IsElGamalEncEqual(cs, isSecondProof, tx.AccountBeforeSwap[0].Balance, tx.Proof.ProofPart2.C)
	std.IsElGamalEncEqual(cs, isSecondProof, tx.AccountBeforeSwap[1].Balance, tx.Proof.ProofPart2.ReceiverC)
	// universal check
	for i := 0; i < NbSwapCount; i++ {
		// check index
		std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[i].Index, tx.AccountAfterSwap[i].Index)
		// check token id
		std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[i].TokenId, tx.AccountAfterSwap[i].TokenId)
		// check public key
		std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[i].PubKey, tx.AccountAfterSwap[i].PubKey)
		// check merkle proof
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[i][:], tx.AccountHelperMerkleProofsBefore[i][:])
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[i][:], tx.AccountHelperMerkleProofsAfter[i][:])
	}
	// select CStar
	CStar, ReceiverCStar := selectCStar(cs, tx.IsFirstProof, tx.Proof)
	// update balance
	tx.AccountBeforeSwap[0].Balance = std.EncAdd(cs, tx.AccountBeforeSwap[0].Balance, CStar, params)
	tx.AccountBeforeSwap[1].Balance = std.EncAdd(cs, tx.AccountBeforeSwap[1].Balance, ReceiverCStar, params)
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[0].Balance, tx.AccountAfterSwap[0].Balance)
	std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBeforeSwap[1].Balance, tx.AccountAfterSwap[1].Balance)

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
	AccountMerkleProofsBefore       [NbSwapCount][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsBefore [NbSwapCount][AccountMerkleLevels - 1]int

	// after withdraw merkle proof
	AccountMerkleProofsAfter       [NbSwapCount][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsAfter [NbSwapCount][AccountMerkleLevels - 1]int

	// old Account Info
	AccountBefore [NbSwapCount]*Account
	// new Account Info
	AccountAfter [NbSwapCount]*Account

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
		witness.AccountBeforeSwap[i], err = SetAccountWitness(tx.AccountBefore[i])
		witness.AccountAfterSwap[i], err = SetAccountWitness(tx.AccountAfter[i])
	}
	// set account root witness
	witness.OldAccountRoot.Assign(tx.OldAccountRoot)
	witness.NewAccountRoot.Assign(tx.NewAccountRoot)

	// set proof
	witness.Proof, err = std.SetSwapProofWitness(tx.Proof, tx.IsEnabled)

	witness.IsEnabled = std.SetBoolWitness(tx.IsEnabled)
	witness.IsFirstProof = std.SetBoolWitness(tx.IsFirstProof)
	return witness, nil
}

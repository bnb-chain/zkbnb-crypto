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
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"zecrey-crypto/zecrey/circuit/bn254/std"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type TransferTxConstraints struct {
	// is enabled
	IsEnabled Variable
	// withdraw proof
	Proof std.PTransferProofConstraints
	// before transfer merkle proof
	AccountMerkleProofsBefore       [NbTransferCount][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsBefore [NbTransferCount][AccountMerkleLevels - 1]Variable

	// after transfer merkle proof
	AccountMerkleProofsAfter       [NbTransferCount][AccountMerkleLevels]Variable
	AccountHelperMerkleProofsAfter [NbTransferCount][AccountMerkleLevels - 1]Variable

	// old Account Info
	AccountBeforeTransfer [NbTransferCount]AccountConstraints
	// new Account Info
	AccountAfterTransfer [NbTransferCount]AccountConstraints

	// old account root
	OldAccountRoot Variable
	// new account root
	NewAccountRoot Variable
}

func (circuit *TransferTxConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC("ZecreyMIMCSeed", curveID)

	VerifyTransferTx(cs, *circuit, params, hFunc)

	return nil
}

/*
	VerifyTransferTx: verify transfer transaction
	1. check account index
	2. check token id
	3. check public key
	4. check merkle proof: before & after
	5. check updated balance
	6. verify withdraw proof
*/
func VerifyTransferTx(cs *ConstraintSystem, tx TransferTxConstraints, params twistededwards.EdCurve, hFunc MiMC) {
	// universal check
	for i := 0; i < NbTransferCount; i++ {
		// check index
		std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeTransfer[i].Index, tx.AccountAfterTransfer[i].Index)
		// check token id
		std.IsVariableEqual(cs, tx.IsEnabled, tx.AccountBeforeTransfer[i].TokenId, tx.AccountAfterTransfer[i].TokenId)
		// check public key
		std.IsPointEqual(cs, tx.IsEnabled, tx.AccountBeforeTransfer[i].PubKey, tx.AccountAfterTransfer[i].PubKey)
		// check merkle proof
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.OldAccountRoot, tx.AccountMerkleProofsBefore[i][:], tx.AccountHelperMerkleProofsBefore[i][:])
		std.VerifyMerkleProof(cs, tx.IsEnabled, hFunc, tx.NewAccountRoot, tx.AccountMerkleProofsAfter[i][:], tx.AccountHelperMerkleProofsAfter[i][:])
		// update balance first
		tx.AccountBeforeTransfer[i].Balance = std.EncAdd(cs, tx.AccountBeforeTransfer[i].Balance, tx.Proof.SubProofs[i].CDelta, params)
		// check updated balance
		std.IsElGamalEncEqual(cs, tx.IsEnabled, tx.AccountBeforeTransfer[i].Balance, tx.AccountAfterTransfer[i].Balance)
	}
	// verify transfer proof
	std.VerifyPTransferProof(cs, tx.Proof, params)
}

/*
	TransferTx: transfer transaction
	TODO only for test
*/
type TransferTx struct {
	// is enabled
	IsEnabled bool
	// withdraw proof
	Proof *zecrey.PTransferProof
	// before transfer merkle proof
	AccountMerkleProofsBefore       [NbTransferCount][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsBefore [NbTransferCount][AccountMerkleLevels - 1]int

	// after transfer merkle proof
	AccountMerkleProofsAfter       [NbTransferCount][AccountMerkleLevels][]byte
	AccountHelperMerkleProofsAfter [NbTransferCount][AccountMerkleLevels - 1]int

	// old Account Info
	AccountBefore [NbTransferCount]*Account
	// new Account Info
	AccountAfter [NbTransferCount]*Account

	// old account root
	OldAccountRoot []byte
	// new account root
	NewAccountRoot []byte
}

/*
	SetTransferTxWitness: set witness for transfer transaction
*/
func SetTransferTxWitness(tx *TransferTx) (witness TransferTxConstraints, err error) {
	if len(tx.Proof.SubProofs) != NbTransferCount {
		return witness, errors.New("err: invalid params")
	}
	for i := 0; i < NbTransferCount; i++ {
		// set merkle proofs witness
		witness.AccountMerkleProofsBefore[i] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsBefore[i])
		witness.AccountHelperMerkleProofsBefore[i] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsBefore[i])
		witness.AccountMerkleProofsAfter[i] = std.SetMerkleProofsWitness(tx.AccountMerkleProofsAfter[i])
		witness.AccountHelperMerkleProofsAfter[i] = std.SetMerkleProofsHelperWitness(tx.AccountHelperMerkleProofsAfter[i])

		// set account witness
		witness.AccountBeforeTransfer[i], err = SetAccountWitness(tx.AccountBefore[i])
		witness.AccountAfterTransfer[i], err = SetAccountWitness(tx.AccountAfter[i])

	}
	// set account root witness
	witness.OldAccountRoot.Assign(tx.OldAccountRoot)
	witness.NewAccountRoot.Assign(tx.NewAccountRoot)

	// set proof
	witness.Proof, err = std.SetPTransferProofWitness(tx.Proof, tx.IsEnabled)

	witness.IsEnabled = std.SetBoolWitness(tx.IsEnabled)
	return witness, nil
}

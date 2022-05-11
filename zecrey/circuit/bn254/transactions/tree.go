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
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
)

type MixedArray struct {
	/*
		hFunc.Write(
					tx.AccountsInfoAfter[i].BuyerAccountIndex,
					tx.AccountsInfoAfter[i].AccountNameHash,
				)
				std.WritePointIntoBuf(&hFunc, tx.AccountsInfoAfter[i].AccountPk)
				hFunc.Write(tx.AccountsInfoAfter[i].StateRoot)
	*/
	AccountIndex Variable
	AccountName  Variable
	AccountPk    Point
	StateRoot    Variable
	CheckRoot    Variable
}

// define tests for verifying the withdraw proof
func (circuit MixedArray) Define(api API) error {
	// first check if C = c_1 \oplus c_2
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hFunc.Write(circuit.AccountIndex)
	hFunc.Write(circuit.AccountName)
	std.WritePointIntoBuf(&hFunc, circuit.AccountPk)
	hFunc.Write(circuit.StateRoot)
	root := hFunc.Sum()
	api.AssertIsEqual(root, circuit.CheckRoot)
	return nil
}

func SetFixedAccountMerkleProofsWitness(oWitness []Variable) (witness [AccountMerkleLevels]Variable, err error) {
	if len(oWitness) != AccountMerkleLevels {
		return witness, errors.New("[SetFixedAccountMerkleProofsWitness] invalid size")
	}
	for i := 0; i < AccountMerkleLevels; i++ {
		witness[i] = oWitness
	}
	return witness, nil
}

func SetFixedAccountMerkleProofsHelperWitness(oWitness []Variable) (witness [AccountMerkleHelperLevels]Variable, err error) {
	if len(oWitness) != AccountMerkleHelperLevels {
		return witness, errors.New("[SetFixedAccountMerkleProofsHelperWitness] invalid size")
	}
	for i := 0; i < AccountMerkleHelperLevels; i++ {
		witness[i] = oWitness
	}
	return witness, nil
}

func SetFixedAssetMerkleProofsWitness(oWitness []Variable) (witness [AssetMerkleLevels]Variable, err error) {
	if len(oWitness) != AssetMerkleLevels {
		return witness, errors.New("[SetFixedAssetMerkleProofsWitness] invalid size")
	}
	for i := 0; i < AssetMerkleLevels; i++ {
		witness[i] = oWitness
	}
	return witness, nil
}

func SetFixedAssetMerkleProofsHelperWitness(oWitness []Variable) (witness [AssetMerkleHelperLevels]Variable, err error) {
	if len(oWitness) != AssetMerkleHelperLevels {
		return witness, errors.New("[SetFixedAssetMerkleProofsHelperWitness] invalid size")
	}
	for i := 0; i < AssetMerkleHelperLevels; i++ {
		witness[i] = oWitness
	}
	return witness, nil
}

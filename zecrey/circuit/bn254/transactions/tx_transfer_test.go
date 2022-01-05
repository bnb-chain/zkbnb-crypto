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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/mockAccount"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"testing"
)

func TestTxConstraints_Define_Transfer(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())

	// test transfer
	fee := uint64(1)
	relation, err := zecrey.NewTransferProofRelation(mockAccount.AssetAId, fee)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(mockAccount.GavinCA, mockAccount.GavinPk, 0, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(mockAccount.SherCA, mockAccount.SherPk, mockAccount.SherAssetABalance, -5, mockAccount.SherSk)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(mockAccount.JasonCA, mockAccount.JasonPk, 0, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := zecrey.ProveTransfer(relation)
	if err != nil {
		t.Fatal(err)
	}

	oTx := &Tx{
		TxType:                                      TxTypeTransfer,
		OProof:                                      proof,
		AccountRootBefore:                           nil,
		AccountsInfoBefore:                          [4]*Account{},
		MerkleProofsAccountAssetsBefore:             [4][3][17][]byte{},
		MerkleProofsHelperAccountAssetsBefore:       [4][3][16]int{},
		MerkleProofsAccountLockedAssetsBefore:       [4][17][]byte{},
		MerkleProofsHelperAccountLockedAssetsBefore: [4][16]int{},
		MerkleProofsAccountLiquidityBefore:          [4][17][]byte{},
		MerkleProofsHelperAccountLiquidityBefore:    [4][16]int{},
		MerkleProofsAccountBefore:                   [4][33][]byte{},
		MerkleProofsHelperAccountBefore:             [4][32]int{},
		AccountRootAfter:                            nil,
		AccountsInfoAfter:                           [4]*Account{},
		MerkleProofsAccountAssetsAfter:              [4][3][17][]byte{},
		MerkleProofsHelperAccountAssetsAfter:        [4][3][16]int{},
		MerkleProofsAccountLockedAssetsAfter:        [4][17][]byte{},
		MerkleProofsHelperAccountLockedAssetsAfter:  [4][16]int{},
		MerkleProofsAccountLiquidityAfter:           [4][17][]byte{},
		MerkleProofsHelperAccountLiquidityAfter:     [4][16]int{},
		MerkleProofsAccountAfter:                    [4][33][]byte{},
		MerkleProofsHelperAccountAfter:              [4][32]int{},
	}
	witness, err = SetTxWitness(oTx)
	if err != nil {
		t.Fatal(err)
	}

	//assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

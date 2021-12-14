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
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
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
	sk1, pk1 := twistedElgamal.GenKeyPair()
	b1 := uint64(8)
	r1 := curve.RandomValue()
	_, pk2 := twistedElgamal.GenKeyPair()
	b2 := big.NewInt(2)
	r2 := curve.RandomValue()
	_, pk3 := twistedElgamal.GenKeyPair()
	b3 := big.NewInt(3)
	r3 := curve.RandomValue()
	b1Enc, err := twistedElgamal.Enc(big.NewInt(int64(b1)), r1, pk1)
	b2Enc, err := twistedElgamal.Enc(b2, r2, pk2)
	b3Enc, err := twistedElgamal.Enc(b3, r3, pk3)
	if err != nil {
		t.Fatal(err)
	}
	fee := uint64(1)
	relation, err := zecrey.NewTransferProofRelation(1, fee)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b2Enc, pk2, 0, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b1Enc, pk1, b1, -5, sk1)
	if err != nil {
		t.Fatal(err)
	}
	err = relation.AddStatement(b3Enc, pk3, 0, 2, nil)
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
		MerkleProofsAccountAssetsBefore:             [4][3][16][]byte{},
		MerkleProofsHelperAccountAssetsBefore:       [4][3][15]int{},
		MerkleProofsAccountLockedAssetsBefore:       [4][16][]byte{},
		MerkleProofsHelperAccountLockedAssetsBefore: [4][15]int{},
		MerkleProofsAccountLiquidityBefore:          [4][16][]byte{},
		MerkleProofsHelperAccountLiquidityBefore:    [4][15]int{},
		MerkleProofsAccountBefore:                   [4][32][]byte{},
		MerkleProofsHelperAccountBefore:             [4][31]int{},
		AccountRootAfter:                            nil,
		AccountsInfoAfter:                           [4]*Account{},
		MerkleProofsAccountAssetsAfter:              [4][16][]byte{},
		MerkleProofsHelperAccountAssetsAfter:        [4][15]int{},
		MerkleProofsAccountLockedAssetsAfter:        [4][16][]byte{},
		MerkleProofsHelperAccountLockedAssetsAfter:  [4][15]int{},
		MerkleProofsAccountLiquidityAfter:           [4][16][]byte{},
		MerkleProofsHelperAccountLiquidityAfter:     [4][15]int{},
		MerkleProofsAccountAfter:                    [4][32][]byte{},
		MerkleProofsHelperAccountAfter:              [4][31]int{},
	}
	witness, err = SetTxWitness(oTx)
	if err != nil {
		t.Fatal(err)
	}

	//assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

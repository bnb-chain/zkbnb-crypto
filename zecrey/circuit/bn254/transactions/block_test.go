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

func TestBlockConstraints_Define(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness BlockConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
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
	//proof, err := zecrey.ProveTransfer(relation)
	//if err != nil {
	//	t.Fatal(err)
	//}
	size := 35
	txs := make([]TxConstraints, size)
	for i := 0; i < size; i++ {
		//txWitness, err := SetTxWitness(proof, TxTypeTransfer, true)
		//if err != nil {
		//	t.Fatal(err)
		//}
		//txs[i] = txWitness
	}
	witness, err = SetBlockWitness(txs)
	if err != nil {
		t.Fatal(err)
	}
	//assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
}

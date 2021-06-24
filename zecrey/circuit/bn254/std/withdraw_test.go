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

package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestWithdrawProofCircuit_Define(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness WithdrawProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// generate withdraw proof
	sk, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(b, r, pk)
	//b4Enc, err := twistedElgamal.Enc(b4, r4, pk4)
	if err != nil {
		t.Fatal(err)
	}
	bStar := big.NewInt(-3)
	relation, err := zecrey.NewWithdrawRelation(bEnc, pk, bStar, sk, 1)
	if err != nil {
		t.Fatal(err)
	}
	withdrawProof, err := zecrey.ProveWithdraw(relation)
	if err != nil {
		t.Fatal(err)
	}
	witness, err = setWithdrawProofWitness(withdrawProof)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("constraints:", r1cs.GetNbConstraints())

	assert.SolvingSucceeded(r1cs, &witness)

}

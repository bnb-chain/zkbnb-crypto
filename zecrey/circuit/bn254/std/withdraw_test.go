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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestWithdrawProofCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness WithdrawProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	for i := 0; i < 1; i++ {
		sk, pk := twistedElgamal.GenKeyPair()
		b := uint64(8)
		r := curve.RandomValue()
		bEnc, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
		if err != nil {
			t.Error(err)
		}
		bEnc2, _ := twistedElgamal.Enc(big.NewInt(10), r, pk)
		bStar := uint64(2)
		fee := uint64(1)
		fmt.Println("sk:", sk.String())
		fmt.Println("pk:", curve.ToString(pk))
		fmt.Println("benc:", bEnc.String())
		fmt.Println("benc2:", bEnc2.String())
		addr := "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449"
		relation, err := zecrey.NewWithdrawRelation(bEnc, pk, b, bStar, sk, 1, addr, fee)
		if err != nil {
			t.Error(err)
		}
		withdrawProof, err := zecrey.ProveWithdraw(relation)
		if err != nil {
			t.Error(err)
		}
		witness, err = SetWithdrawProofWitness(withdrawProof, true)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("constraints:", r1cs.GetNbConstraints())
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
	}
}

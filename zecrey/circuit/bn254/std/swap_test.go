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

func TestSwapProofCircuit_Define(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness SwapProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		// generate swap proof
		sk1, pk1 := twistedElgamal.GenKeyPair()
		b1 := big.NewInt(8)
		r1 := curve.RandomValue()
		bEnc, err := twistedElgamal.Enc(b1, r1, pk1)
		if err != nil {
			t.Error(err)
		}
		bStarFrom := big.NewInt(1)
		bStarTo := big.NewInt(8)
		fromTokenId := uint32(1)
		toTokenId := uint32(2)
		relationPart1, err := zecrey.NewSwapRelationPart1(bEnc, pk1, bStarFrom, bStarTo, sk1, fromTokenId, toTokenId)
		if err != nil {
			t.Error(err)
		}
		swapProofPart1, err := zecrey.ProveSwapPart1(relationPart1, true)
		if err != nil {
			t.Error(err)
		}
		part1Res, err := swapProofPart1.Verify()
		if err != nil {
			t.Error(err)
		}
		if !part1Res {
			t.Error(err)
		}
		sk2, pk2 := twistedElgamal.GenKeyPair()
		b2 := big.NewInt(8)
		r2 := curve.RandomValue()
		bEnc2, err := twistedElgamal.Enc(b2, r2, pk2)
		if err != nil {
			t.Error(err)
		}
		relationPart2, err := zecrey.NewSwapRelationPart2(bEnc2, pk2, sk2, fromTokenId, toTokenId, swapProofPart1)
		if err != nil {
			t.Error(err)
		}
		swapProof, err := zecrey.ProveSwapPart2(relationPart2, swapProofPart1)
		if err != nil {
			t.Error(err)
		}
		witness, err = setSwapProofWitness(swapProof)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println("constraints:", r1cs.GetNbConstraints())

		assert.SolvingSucceeded(r1cs, &witness)
	}
}

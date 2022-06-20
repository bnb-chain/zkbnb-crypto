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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"math/big"
	"testing"
)

func TestWithdrawProofCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness WithdrawProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
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
		b_fee := uint64(10)
		bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
		bStar := uint64(2)
		fee := uint64(1)
		addr := "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449"
		assetId := uint32(1)
		feeAssetId := uint32(2)
		relation, err := zero.NewWithdrawRelation(
			1,
			bEnc,
			pk,
			b, bStar,
			sk,
			assetId, addr,
			bEnc2, b_fee, feeAssetId, fee,
		)
		if err != nil {
			t.Error(err)
		}
		withdrawProof, err := zero.ProveWithdraw(relation)
		if err != nil {
			t.Error(err)
		}
		witness, err = SetWithdrawProofWitness(withdrawProof, true)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("constraints:", r1cs.GetNbConstraints())
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
	}
}

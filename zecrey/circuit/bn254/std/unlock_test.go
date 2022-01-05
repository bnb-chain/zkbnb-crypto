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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"math/big"
	"testing"
)

func TestUnlockProofConstraints_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness UnlockProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit, frontend.IgnoreUnconstrainedInputs)
	if err != nil {
		t.Fatal(err)
	}
	sk, pk := twistedElgamal.GenKeyPair()
	chainId := uint32(0)
	assetId := uint32(0)
	balance := uint64(10)
	deltaAmount := uint64(2)
	b_fee := uint64(100)
	feeEnc, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), curve.RandomValue(), pk)
	proof, err := zecrey.ProveUnlock(
		sk, chainId, assetId, balance, deltaAmount,
		feeEnc,
		b_fee, uint32(1), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	witness, err = SetUnlockProofWitness(proof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs))
}

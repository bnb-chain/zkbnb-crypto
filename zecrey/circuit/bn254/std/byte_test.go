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
	"bytes"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"math/big"
	"math/rand"
	"testing"
)

func bitStringToBytes(s string) ([]byte, error) {
	b := make([]byte, (len(s)+(8-1))/8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '1' {
			return nil, errors.New("value out of range")
		}
		b[i>>3] |= (c - '0') << uint(7-i&7)
	}
	return b, nil
}

func TestByteCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var buf bytes.Buffer
	// 20byte
	ABytes := make([]byte, 16)
	if _, err := rand.Read(ABytes); err != nil {
		return
	}
	fmt.Println(ABytes)
	fmt.Println(new(big.Int).SetBytes(ABytes).String())
	BBytes := make([]byte, 20)
	if _, err := rand.Read(BBytes); err != nil {
		return
	}
	CBytes := make([]byte, 30)
	if _, err := rand.Read(CBytes); err != nil {
		return
	}
	buf.Write(ABytes)
	buf.Write(BBytes)
	buf.Write(CBytes)
	hFunc := mimc.NewMiMC()
	hFunc.Write(buf.Bytes())
	DHash := hFunc.Sum(nil)
	hFunc.Reset()
	EBytes := []byte{1}
	FBytes := []byte{2}
	GBytes := []byte{3}
	buf.Reset()
	buf.Write(EBytes)
	buf.Write(FBytes)
	buf.Write(GBytes)
	hFunc.Write(buf.Bytes())
	HHash := hFunc.Sum(nil)
	var circuit, witness ByteConstraints
	witness.A = ABytes
	witness.B = BBytes
	witness.C = CBytes
	witness.D = DHash
	witness.E = EBytes
	witness.F = FBytes
	witness.G = GBytes
	witness.H = HHash
	//witness.D = DHash
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(r1cs.GetNbConstraints())
	assert.SolvingSucceeded(&circuit, &witness, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

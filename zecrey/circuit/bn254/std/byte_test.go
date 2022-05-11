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
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
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
	bitStr := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000100100001010000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	buf, _ := bitStringToBytes(bitStr)
	fmt.Println(buf)
	// 20byte
	ABytes := make([]byte, 20)
	copy(ABytes[:], "ABC")
	fmt.Println(ABytes)
	fmt.Println(new(big.Int).SetBytes(ABytes).Bytes())
	BBytes := make([]byte, 16)
	copy(BBytes[:], "DEF")

	CBytes := append(ABytes, BBytes...)
	hFunc := mimc.NewMiMC()
	hFunc.Write(CBytes)
	CHash := hFunc.Sum(nil)
	var circuit, witness ByteConstraints
	witness.A = ABytes
	witness.B = BBytes
	witness.C = CHash
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

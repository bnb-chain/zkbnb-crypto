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

package commitRange

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
	"github.com/bnb-chain/zkbas-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
)

func TestProveAndVerify(t *testing.T) {
	for i := 0; i < 1; i++ {
		b := big.NewInt(1)
		var rs [RangeMaxBits]*big.Int
		sum := big.NewInt(0)
		for i := 0; i < RangeMaxBits; i++ {
			rs[i] = curve.RandomValue()
			sum.Add(sum, rs[i])
		}
		r := ffmath.Mod(sum, Order)
		g := curve.H
		h := curve.G
		T, _ := pedersen.Commit(b, r, g, h)
		elapse := time.Now()
		proof, err := Prove(b, r, T, rs, g, h)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(curve.Count)
		fmt.Println(time.Since(elapse))
		proofBytes := proof.Bytes()
		proofCopy, err := FromBytes(proofBytes)
		if err != nil {
			t.Fatal(err)
		}
		proofStr := proof.String()
		proofCheck, err := FromString(proofStr)
		if err != nil {
			t.Fatal(err)
		}
		res, err := proofCopy.Verify()
		fmt.Println(curve.Count)
		res, err = proofCheck.Verify()
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, res, true, "ComRangeProof works correctly")
	}
}

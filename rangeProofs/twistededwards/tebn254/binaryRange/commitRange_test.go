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
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
	"github.com/bnb-chain/zkbas-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/hash/bn254/zmimc"
	"github.com/bnb-chain/zkbas-crypto/util"
)

func TestProveAndVerify(t *testing.T) {
	for i := 0; i < 1; i++ {
		b := big.NewInt(3)
		r := curve.RandomValue()
		g := curve.H
		h := curve.G
		T, _ := pedersen.Commit(b, r, g, h)
		elapse := time.Now()
		proof, err := Prove(b, r, T, g, h, 32)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(curve.Count)
		fmt.Println(time.Since(elapse))
		res, err := proof.Verify()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(curve.Count)
		assert.Equal(t, res, true, "ComRangeProof works correctly")
	}
}

func TestProveCommitmentSameValue(t *testing.T) {
	b := big.NewInt(5)
	r1 := curve.RandomValue()
	r2 := curve.RandomValue()
	g := curve.H
	h := curve.G
	T, _ := pedersen.Commit(b, r1, g, h)
	Tprime, _ := pedersen.Commit(b, r2, g, h)
	A_T, A_Tprime, alpha_b, alpha_r, alpha_rprime, _ := commitCommitmentSameValue(g, h)
	var buf bytes.Buffer
	buf.Write(g.Marshal())
	buf.Write(h.Marshal())
	buf.Write(A_T.Marshal())
	buf.Write(A_Tprime.Marshal())
	c, _ := util.HashToInt(buf, zmimc.Hmimc)
	zb, zr, zrprime, _ := respondCommitmentSameValue(b, r1, r2, alpha_b, alpha_r, alpha_rprime, c)
	res, _ := verifyCommitmentSameValue(A_T, A_Tprime, T, Tprime, g, h, zb, zr, zrprime, c)
	fmt.Println(res)
}

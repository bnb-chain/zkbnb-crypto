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

package chaum_pedersen

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveVerify(t *testing.T) {
	g := G
	sk, pk := twistedElgamal.GenKeyPair()
	r1 := curve.RandomValue()
	r2 := curve.RandomValue()
	b := big.NewInt(3)
	CPrime, _ := twistedElgamal.Enc(b, r1, pk)
	CTilde, _ := twistedElgamal.Enc(b, r2, pk)
	u := curve.Add(CPrime.CR, curve.Neg(CTilde.CR))
	v := pk
	w := curve.ScalarMul(u, sk)
	w2 := curve.Add(CPrime.CL, curve.Neg(CTilde.CL))
	fmt.Println("w2 == w:", w2.Equal(w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}

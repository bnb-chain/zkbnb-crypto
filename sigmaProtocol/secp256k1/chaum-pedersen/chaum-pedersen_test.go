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
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/elgamal/secp256k1/twistedElgamal"
)

func TestProveVerify(t *testing.T) {
	g := zp256.Base()
	sk, pk := twistedElgamal.GenKeyPair()
	r1 := zp256.RandomValue()
	r2 := zp256.RandomValue()
	b := big.NewInt(3)
	CPrime := twistedElgamal.Enc(b, r1, pk)
	CTilde := twistedElgamal.Enc(b, r2, pk)
	u := zp256.Add(CPrime.CR, zp256.Neg(CTilde.CR))
	v := pk
	w := zp256.ScalarMul(u, sk)
	w2 := zp256.Add(CPrime.CL, zp256.Neg(CTilde.CL))
	fmt.Println("w2 == w:", zp256.Equal(w2, w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}

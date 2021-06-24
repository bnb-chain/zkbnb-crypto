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

package bulletProofs

import (
	"fmt"
	"math/big"
	"testing"
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/elgamal/secp256k1/twistedElgamal"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(8)
	r := zp256.RandomValue()
	bEnc := twistedElgamal.Enc(b, r, pk)
	params, err := Setup(32, 1)
	if err != nil {
		panic(err)
	}
	proof, err := Prove(b, r, bEnc.CR, params)
	if err != nil {
		panic(err)
	}
	res, err := proof.Verify()
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}

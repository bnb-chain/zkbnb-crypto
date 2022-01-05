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
	"github.com/zecrey-labs/zecrey-crypto/ecc/zp256"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/secp256k1/twistedElgamal"
)

func TestProveAggregationAndVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b1 := big.NewInt(8)
	r1 := zp256.RandomValue()
	b2 := big.NewInt(3)
	r2 := zp256.RandomValue()
	b1Enc := twistedElgamal.Enc(b1, r1, pk)
	b2Enc := twistedElgamal.Enc(b2, r2, pk)
	secrets := []*big.Int{b1, b2}
	gammas := []*big.Int{r1, r2}
	Vs := []*P256{b1Enc.CR, b2Enc.CR}
	params, err := Setup(32, 10)
	if err != nil {
		panic(err)
	}
	proof, err := ProveAggregation(secrets, gammas, Vs, params)
	if err != nil {
		panic(err)
	}
	res, err := proof.Verify()
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}

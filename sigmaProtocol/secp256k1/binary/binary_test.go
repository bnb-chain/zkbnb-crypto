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

package binary

import (
	"fmt"
	"math/big"
	"testing"
	"github.com/bnb-chain/zkbas-crypto/commitment/secp256k1/pedersen"
	"github.com/bnb-chain/zkbas-crypto/ecc/zp256"
)

func TestProveAndVerify(t *testing.T) {
	m := 0
	r := zp256.RandomValue()
	c := pedersen.Commit(big.NewInt(int64(m)), r, zp256.Base(), zp256.H)
	ca, cb, f, za, zb, err := Prove(m, r)
	if err != nil {
		panic(err)
	}
	isValid := Verify(c, ca, cb, f, za, zb)
	fmt.Println(isValid)
}

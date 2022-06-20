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

package elgamal

import (
	"fmt"
	"math"
	"math/big"
	"testing"
	"github.com/bnb-chain/zkbas-crypto/ecc/zp256"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(1000)
	//b := big.NewInt(100000)
	r := zp256.RandomValue()
	max := int64(math.Pow(2, 32))
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk, max)
	fmt.Println(bDec)
}

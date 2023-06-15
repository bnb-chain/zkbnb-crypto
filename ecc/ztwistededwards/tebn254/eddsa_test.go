/*
 * Copyright © 2022 ZkBNB Protocol
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

package tebn254

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func TestGenerateEddsaPrivateKey(t *testing.T) {
	count := 0
	hexChars := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	for {
		seedFormat := "3123456789abcdef0123456789ae01%c%c"
		seed := fmt.Sprintf(seedFormat, hexChars[count%16], hexChars[(count/16)%16])
		count += 1
		sk, err := GenerateEddsaPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		hFunc := mimc.NewMiMC()
		hFunc.Write([]byte("0123456789abcdef0123456789abcdef"))
		msg := hFunc.Sum(nil)
		hFunc.Reset()
		signMsg, err := sk.Sign(msg, hFunc)
		if err != nil {
			t.Fatal(err)
		}
		hFunc.Reset()
		isValid, err := sk.PublicKey.Verify(signMsg, msg, hFunc)
		if err != nil {
			t.Fatal(err)
		}
		if isValid != true {
			t.Fatal("invalid signature")
		}
		//log.Println(isValid)
		if count > 256 {
			break
		}
	}
}

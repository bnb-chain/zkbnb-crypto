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
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func TestGenerateEddsaPrivateKey(t *testing.T) {
	sk, err := GenerateEddsaPrivateKey("testeeetgcxsaahsadcastzxbmjhgmgjhcarwewfseasdasdavacsafaewe")
	if err != nil {
		t.Fatal(err)
	}
	log.Println(new(big.Int).SetBytes(sk.Bytes()[32:64]).BitLen())
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte("sher"))
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
	log.Println(isValid)
}

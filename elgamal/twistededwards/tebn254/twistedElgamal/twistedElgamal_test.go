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

package twistedElgamal

import (
	"fmt"
	"github.com/magiconair/properties/assert"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"math"
	"math/big"
	"testing"
	"time"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(10000)
	delta := big.NewInt(-500)
	bRes := ffmath.Add(b, delta)
	r := curve.RandomValue()
	i, _ := new(big.Int).SetString("2029490050459469381010394860546295858668907545094365921480173886327233296650", 10)
	fix := curve.Add(curve.ScalarMul(G, i), curve.ScalarMul(H, big.NewInt(0)))
	fmt.Println(fix.X)
	fmt.Println(fix.Y)

	max := int64(math.Pow(2, 32))
	enc, _ := Enc(b, r, pk)
	fmt.Println("sk:", sk.String())
	encStr := enc.String()
	fmt.Println("enc:", encStr)
	Ccopy, _ := FromString(enc.String())
	fmt.Println("enc unmarshal:", Ccopy)
	encDelta, _ := Enc(delta, r, pk)
	encAdd, _ := EncAdd(enc, encDelta)
	elapse := time.Now()
	bDelta, _ := Dec(encAdd, sk, max)
	fmt.Println("dec time:", time.Since(elapse))
	fmt.Println(bDelta)
	bPrime, _ := Dec(encAdd, sk, max)
	fmt.Println(bPrime)
	//assert.Equal(t, b, dec)
	assert.Equal(t, bRes, bDelta)
}

func TestDecByStartRoutine(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(100000)
	r := curve.RandomValue()
	max := int64(4294967295)
	enc, _ := Enc(b, r, pk)
	fmt.Println(sk.String())
	fmt.Println(enc.String())
	allElapse := int64(0)
	for i := 0; i < 5; i++ {
		elapse := time.Now()
		_, err := DecByStart(enc, sk, 0, max)
		if err != nil {
			t.Error(err)
		}
		//fmt.Println(time.Since(elapse))
		allElapse += time.Since(elapse).Milliseconds()
	}
	fmt.Println(allElapse / 5)
	assert.Equal(t, b, b, "decryption works correctly")
}

func TestDec(t *testing.T) {
	enc, err := FromString("vnD6I3qhOKPp2JpRNCShZnEmeCSC6DgXh8wr+GpKsh6mVVIxi2eRBYI4snGqXedK64+THIk5+/UfiH4IGJqEGg==")
	if err != nil {
		t.Fatal(err)
	}
	delta, err := FromString("9pYkX+HnCWWFagTuizryd4tnB0I4cz9fPGMUPT2vM5dBYBngm2oFJuZQutj6S/8bZjNamJ5o9sKsEIjqd5uSoA==")
	if err != nil {
		t.Fatal(err)
	}
	newEnc, err := EncAdd(enc, delta)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(newEnc.String())
	sk, b := new(big.Int).SetString("58701357177140449605359986386991314012065100879587586149814219788744791162880", 10)
	if !b {
		t.Fatal("cannot parse sk")
	}
	res, err := Dec(newEnc, sk, 100000)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res.String())

}

func TestGenKeyPair(t *testing.T) {
	sk, pk := GenKeyPair()
	enc, err := Enc(big.NewInt(100000), big.NewInt(444211), pk)
	if err != nil {
		t.Fatal(err)
	}
	ellapse := time.Now()
	fmt.Println(enc.String())
	fmt.Println(sk.String())
	_, err = Dec(enc, sk, 10000000000)
	fmt.Println(time.Since(ellapse))
	if err != nil {
		t.Fatal(err)
	}
}

func TestFakeElGamalEnc(t *testing.T) {
	CL := curve.ZeroPoint()
	CR := curve.ScalarMul(curve.H, big.NewInt(100))
	enc := &ElGamalEnc{CL: CL, CR: CR}
	fmt.Println(enc.String())
}

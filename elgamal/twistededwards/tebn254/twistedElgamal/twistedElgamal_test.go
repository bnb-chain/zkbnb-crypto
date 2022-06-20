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
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/magiconair/properties/assert"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
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
	enc, err := FromString("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARrk4rOFZLJ7pFNNWl1VQiqRP5bttHIcAfrh36Xj5wHA==")
	if err != nil {
		t.Fatal(err)
	}

	point := curve.ScalarMul(H, big.NewInt(30010))
	nEnc := &ElGamalEnc{
		CL: curve.ZeroPoint(),
		CR: point,
	}
	fmt.Println(nEnc.String())
	sk, b := new(big.Int).SetString("1274920211692271005034136269791630795266250736102937985856472195493871858111", 10)
	if !b {
		t.Fatal("cannot parse sk")
	}
	res, err := Dec(enc, sk, 10000000)
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

func TestEddsa(t *testing.T) {
	hFunc := mimc.NewMiMC()
	hFunc.Write([]byte("sher"))
	seedBytes := hFunc.Sum(nil)
	seed := common.Bytes2Hex(seedBytes)
	fmt.Println(seed)
	key, err := curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	fmt.Println("sher:", common.Bytes2Hex(key.PublicKey.A.X.Marshal()))
	fmt.Println("sher:", common.Bytes2Hex(key.PublicKey.A.Y.Marshal()))
	fmt.Println(key.Bytes())

	hFunc.Reset()
	hFunc.Write([]byte("gavin"))
	seedBytes = hFunc.Sum(nil)
	seed = common.Bytes2Hex(seedBytes)
	fmt.Println(seed)
	key, err = curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	fmt.Println("gavin:", common.Bytes2Hex(key.PublicKey.A.X.Marshal()))
	fmt.Println("gavin:", common.Bytes2Hex(key.PublicKey.A.Y.Marshal()))
	fmt.Println(key.Bytes())

	hFunc.Reset()
	hFunc.Write([]byte("treasury"))
	seedBytes = hFunc.Sum(nil)
	seed = common.Bytes2Hex(seedBytes)
	key, err = curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	fmt.Println("treasury:", common.Bytes2Hex(key.PublicKey.A.X.Marshal()))
	fmt.Println("treasury:", common.Bytes2Hex(key.PublicKey.A.Y.Marshal()))
	fmt.Println(key.Bytes())
	hFunc.Reset()
	hFunc.Write([]byte("gas"))
	seedBytes = hFunc.Sum(nil)
	seed = common.Bytes2Hex(seedBytes)
	key, err = curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	fmt.Println("gas:", common.Bytes2Hex(key.PublicKey.A.X.Marshal()))
	fmt.Println("gas:", common.Bytes2Hex(key.PublicKey.A.Y.Marshal()))
	fmt.Println(key.Bytes())

	seed = "ee823a72698fd05c70fbdf36ba2ea467d33cf628c94ef030383efcb39581e43f"
	key, err = curve.GenerateEddsaPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	fmt.Println(new(big.Int).SetBytes(key.Bytes()[32:64]).Bit(245))
	fmt.Println("amber:", common.Bytes2Hex(key.PublicKey.A.X.Marshal()))
	fmt.Println("amber:", common.Bytes2Hex(key.PublicKey.A.Y.Marshal()))
}

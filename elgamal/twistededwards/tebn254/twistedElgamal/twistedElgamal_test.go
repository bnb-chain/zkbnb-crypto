package twistedElgamal

import (
	"fmt"
	"github.com/magiconair/properties/assert"
	"math"
	"math/big"
	"testing"
	"time"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
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
	b := big.NewInt(-125933)
	r := curve.RandomValue()
	max := int64(200000)
	enc, _ := Enc(b, r, pk)
	elapse := time.Now()
	res, err := DecByStart(enc, sk, 0, max)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(time.Since(elapse))
	fmt.Println(res)
}

package zksneak_bn128

import (
	"ZKSneak/ZKSneak-crypto/bulletProofs/bp_bn128"
	"ZKSneak/ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	statement := NewStatement()
	// user1
	sk1, pk1 := twistedElgamal_bn128.GenKeyPair()
	b1 := big.NewInt(5)
	r1, _ := rand.Int(rand.Reader, ORDER)
	C1 := twistedElgamal_bn128.Enc(b1, r1, pk1)
	b1Delta := big.NewInt(-3)
	// user2
	_, pk2 := twistedElgamal_bn128.GenKeyPair()
	b2 := big.NewInt(2)
	r2, _ := rand.Int(rand.Reader, ORDER)
	C2 := twistedElgamal_bn128.Enc(b2, r2, pk2)
	b2Delta := big.NewInt(1)
	// user3
	_, pk3 := twistedElgamal_bn128.GenKeyPair()
	b3 := big.NewInt(3)
	r3, _ := rand.Int(rand.Reader, ORDER)
	C3 := twistedElgamal_bn128.Enc(b3, r3, pk3)
	b3Delta := big.NewInt(2)
	statement.AddRelation(C1, pk1, b1, b1Delta, sk1)
	statement.AddRelation(C2, pk2, nil, b2Delta, nil)
	statement.AddRelation(C3, pk3, nil, b3Delta, nil)
	params, _ := Setup(bp_bn128.MAX_RANGE_END)
	proof, _ := Prove(statement, &params)
	res := proof.Verify()
	assert.True(t, res, "should be true")
}

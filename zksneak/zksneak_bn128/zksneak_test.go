package zksneak_bn128

import (
	"ZKSneak/ZKSneak-crypto/bulletProofs/bp_bn128"
	"ZKSneak/ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	statement := NewStatement()
	// user1
	sk1, pk1 := twistedElgamal_bn128.GenKeyPair()
	b1 := big.NewInt(8)
	r1, _ := rand.Int(rand.Reader, ORDER)
	C1 := twistedElgamal_bn128.Enc(b1, r1, pk1)
	b1Delta := big.NewInt(-6)
	fmt.Println("user1 before balance:", b1.String())
	// user2
	sk2, pk2 := twistedElgamal_bn128.GenKeyPair()
	b2 := big.NewInt(4)
	r2, _ := rand.Int(rand.Reader, ORDER)
	C2 := twistedElgamal_bn128.Enc(b2, r2, pk2)
	b2Delta := big.NewInt(-2)
	fmt.Println("user2 before balance:", b2.String())
	// user3
	sk3, pk3 := twistedElgamal_bn128.GenKeyPair()
	b3 := big.NewInt(3)
	r3, _ := rand.Int(rand.Reader, ORDER)
	C3 := twistedElgamal_bn128.Enc(b3, r3, pk3)
	b3Delta := big.NewInt(5)
	fmt.Println("user3 before balance:", b3.String())
	// user4
	sk4, pk4 := twistedElgamal_bn128.GenKeyPair()
	b4 := big.NewInt(3)
	r4, _ := rand.Int(rand.Reader, ORDER)
	C4 := twistedElgamal_bn128.Enc(b4, r4, pk4)
	b4Delta := big.NewInt(3)
	fmt.Println("user4 before balance:", b4.String())
	// start prove transfer
	statement.AddRelation(C1, pk1, b1, b1Delta, sk1)
	statement.AddRelation(C2, pk2, b2, b2Delta, sk2)
	statement.AddRelation(C3, pk3, nil, b3Delta, nil)
	statement.AddRelation(C4, pk4, nil, b4Delta, nil)
	params, _ := Setup(bp_bn128.MAX_RANGE_END)
	proof, _ := ProveTransfer(statement, &params)
	res := proof.VerifyTransfer()
	sks := []*big.Int{sk1, sk2, sk3, sk4}
	if res {
		for i, relation := range statement.Relations {
			balanceAfter := relation.Public.CPrime
			balance := twistedElgamal_bn128.Dec(balanceAfter, sks[i])
			fmt.Printf("user%x after balance: %x\n", i+1, balance)
		}
	}
	assert.True(t, res, "should be true")
}

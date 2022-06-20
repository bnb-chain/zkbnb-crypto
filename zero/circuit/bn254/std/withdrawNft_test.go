package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/bnb-chain/zkbas-crypto/hash/bn254/zmimc"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"math/big"
	"testing"
)

func TestWithdrawNftProofCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness WithdrawNftProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	sk, pk := twistedElgamal.GenKeyPair()
	r := curve.RandomValue()
	b_fee := uint64(10)
	bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
	fee := uint64(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc2:", bEnc2.String())
	//feeAssetId := uint32(2)
	hFunc := zmimc.Hmimc
	hFunc.Write([]byte("test data"))
	contentHash := hFunc.Sum(nil)
	receiverAddr := "0xd5Aa3B56a2E2139DB315CdFE3b34149c8ed09171"
	relation, err := zero.NewWithdrawNftRelation(
		pk, 9, 1, 1, contentHash, receiverAddr, receiverAddr, 1, sk, bEnc2, b_fee, 1, fee,
	)
	if err != nil {
		t.Error(err)
	}
	oProof, err := zero.ProveWithdrawNft(relation)
	if err != nil {
		t.Error(err)
	}
	witness, err = SetWithdrawNftProofWitness(oProof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

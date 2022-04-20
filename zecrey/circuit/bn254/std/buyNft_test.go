package std

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/hash/bn254/zmimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"math/big"
	"testing"
)

func TestBuyNftProofCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness BuyNftProofConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	sk, pk := twistedElgamal.GenKeyPair()
	b := uint64(8)
	r := curve.RandomValue()
	bEnc, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
	if err != nil {
		t.Error(err)
	}
	b_fee := uint64(10)
	bEnc2, _ := twistedElgamal.Enc(big.NewInt(int64(b_fee)), r, pk)
	assetAmount := uint64(2)
	fee := uint64(1)
	fmt.Println("sk:", sk.String())
	fmt.Println("pk:", curve.ToString(pk))
	fmt.Println("benc:", bEnc.String())
	fmt.Println("benc2:", bEnc2.String())
	hFunc := zmimc.Hmimc
	hFunc.Write([]byte("test data"))
	contentHash := hFunc.Sum(nil)
	assetId := uint32(1)
	//feeAssetId := uint32(2)
	relation, err := zecrey.NewBuyNftRelation(
		bEnc,
		pk,
		b,
		sk,
		1, 1, contentHash, assetId, assetAmount,
		bEnc, b, assetId, fee,
		20,
	)
	if err != nil {
		t.Error(err)
	}
	oProof, err := zecrey.ProveBuyNft(relation)
	if err != nil {
		t.Error(err)
	}
	witness, err = SetBuyNftProofWitness(oProof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

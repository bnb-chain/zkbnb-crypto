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

func TestClaimNftProofCircuit_Define(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness MintNftProofConstraints
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
	receiverAccountIndex := uint32(3)
	relation, err := zecrey.NewMintNftRelation(
		pk, 9, contentHash, receiverAccountIndex,receiverAccountIndex, sk, bEnc2, b_fee, 1, fee,
	)
	if err != nil {
		t.Error(err)
	}
	oProof, err := zecrey.ProveMintNft(relation)
	if err != nil {
		t.Error(err)
	}
	witness, err = SetMintNftProofWitness(oProof, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}

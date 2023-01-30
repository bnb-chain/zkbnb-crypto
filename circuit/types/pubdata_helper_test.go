package types

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

type MintNftCircuit struct {
	ExpectedResult [PubDataBitsSizePerTx]frontend.Variable
	TxInfo         MintNftTxConstraints
}

func (circuit MintNftCircuit) Define(api frontend.API) error {
	pubData := CollectPubDataFromMintNft(api, circuit.TxInfo)

	for i := range pubData {
		api.AssertIsEqual(pubData[i], circuit.ExpectedResult[i])
	}
	return nil
}

func TestCollectPubDataFromMintNftFieldOverflow(t *testing.T) {
	var circuit, witness MintNftCircuit
	circuit.TxInfo = MintNftTxConstraints{}

	witness.TxInfo = MintNftTxConstraints{
		CreatorAccountIndex: 4,
		ToAccountIndex:      4,
		ToAccountNameHash:   common.FromHex("1e0b0d8c4c69d2c061ced93a60fa9f08812dcc9e804efff7f445039d7834f1e53"),
		NftIndex:            5,
		NftContentHash:      GetNftContentHashFromBytes(common.FromHex("af6b80f7c6b8d2e5ce1cfa3a58c7c8530a7f75bc4f73569a8dcffbde3efc0753")),
		CreatorTreasuryRate: 0,
		GasAccountIndex:     1,
		GasFeeAssetId:       0,
		GasFeeAssetAmount:   32010,
		CollectionId:        0,
		ExpiredAt:           1673624416687,
	}
	pubData := common.Hex2Bytes("070000000400000004000000000500007d0a00000000af6b80f7c6b8d2e5ce1cfa3a58c7c8530a7f75bc4f73569a8dcffbde3efc075300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	witness.ExpectedResult = [968]frontend.Variable{}

	j := 0
	for i := 0; i <= 960; i = i + 8 {
		witness.ExpectedResult[i] = pubData[j] >> 7 & 1
		witness.ExpectedResult[i+1] = pubData[j] >> 6 & 1
		witness.ExpectedResult[i+2] = pubData[j] >> 5 & 1
		witness.ExpectedResult[i+3] = pubData[j] >> 4 & 1
		witness.ExpectedResult[i+4] = pubData[j] >> 3 & 1
		witness.ExpectedResult[i+5] = pubData[j] >> 2 & 1
		witness.ExpectedResult[i+6] = pubData[j] >> 1 & 1
		witness.ExpectedResult[i+7] = pubData[j] >> 0 & 1
		j = j + 1
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()),
	)
}

func TestCollectPubDataFromMintNft(t *testing.T) {
	var circuit, witness MintNftCircuit
	circuit.TxInfo = MintNftTxConstraints{}

	witness.TxInfo = MintNftTxConstraints{
		CreatorAccountIndex: 4,
		ToAccountIndex:      4,
		ToAccountNameHash:   common.FromHex("1e0b0d8c4c69d2c061ced93a60fa9f08812dcc9e804efff7f445039d7834f1e5"),
		NftIndex:            5,
		NftContentHash:      GetNftContentHashFromBytes(common.FromHex("0d736736cea2105c1eae36c240a2ebe03e22d2393b4b7edc2fe5a921a5d66db2")),
		CreatorTreasuryRate: 0,
		GasAccountIndex:     1,
		GasFeeAssetId:       0,
		GasFeeAssetAmount:   32010,
		CollectionId:        0,
		ExpiredAt:           1673624416687,
	}
	pubData := common.Hex2Bytes("070000000400000004000000000500007d0a000000000d736736cea2105c1eae36c240a2ebe03e22d2393b4b7edc2fe5a921a5d66db200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	witness.ExpectedResult = [968]frontend.Variable{}

	j := 0
	for i := 0; i <= 960; i = i + 8 {
		witness.ExpectedResult[i] = pubData[j] >> 7 & 1
		witness.ExpectedResult[i+1] = pubData[j] >> 6 & 1
		witness.ExpectedResult[i+2] = pubData[j] >> 5 & 1
		witness.ExpectedResult[i+3] = pubData[j] >> 4 & 1
		witness.ExpectedResult[i+4] = pubData[j] >> 3 & 1
		witness.ExpectedResult[i+5] = pubData[j] >> 2 & 1
		witness.ExpectedResult[i+6] = pubData[j] >> 1 & 1
		witness.ExpectedResult[i+7] = pubData[j] >> 0 & 1
		j = j + 1
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()),
	)
}

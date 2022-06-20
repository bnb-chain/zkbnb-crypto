package test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/bnb-chain/zkbas-crypto/wasm/legend/legendTxTypes"
	"log"
	"testing"
)

func TestSwapSegmentFormat(t *testing.T){

	var segmentFormat *legendTxTypes.SwapSegmentFormat
	segmentFormat = &legendTxTypes.SwapSegmentFormat{
		FromAccountIndex:  0,
		PairIndex:         0,
		AssetAId:          1,
		AssetAAmount:      "10000",
		AssetBId:          2,
		AssetBMinAmount:   "95",
		AssetBAmountDelta: "99",
		GasAccountIndex:   1,
		GasFeeAssetId:     3,
		GasFeeAssetAmount: "3",
		ExpiredAt:         1654656781000, // milli seconds
		Nonce:             1,
	}

	res, err := json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))
}
package test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/zecrey-labs/zecrey-crypto/wasm/zecrey-legend/legendTxTypes"
	"log"
	"testing"
)

func TestRemoveLiquiditySegmentFormat(t *testing.T){

	var segmentFormat *legendTxTypes.RemoveLiquiditySegmentFormat
	segmentFormat = &legendTxTypes.RemoveLiquiditySegmentFormat{
		FromAccountIndex:  0,
		PairIndex:         0,
		AssetAId:          1,
		AssetAMinAmount:   "9000",
		AssetBId:          2,
		AssetBMinAmount:   "90",
		LpAmount:          "1000",
		AssetAAmountDelta: "10000",
		AssetBAmountDelta: "100",
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

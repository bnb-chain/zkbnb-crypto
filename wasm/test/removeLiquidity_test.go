package test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveLiquiditySegmentFormat(t *testing.T) {

	var segmentFormat *txtypes.RemoveLiquiditySegmentFormat
	segmentFormat = &txtypes.RemoveLiquiditySegmentFormat{
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

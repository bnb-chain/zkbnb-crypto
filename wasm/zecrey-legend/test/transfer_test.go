package test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/zecrey-labs/zecrey-crypto/wasm/zecrey-legend/legendTxTypes"
	"log"
	"testing"
)

func TestTransferSegmentFormat(t *testing.T){

	var segmentFormat *legendTxTypes.TransferSegmentFormat
	segmentFormat = &legendTxTypes.TransferSegmentFormat{
		FromAccountIndex:  0,
		ToAccountIndex:    1,
		ToAccountNameHash: "ddc6171f9fe33153d95c8394c9135c277eb645401b85eb499393a2aefe6422a6",
		AssetId:           0,
		AssetAmount:       "100",
		GasAccountIndex:   1,
		GasFeeAssetId:     3,
		GasFeeAssetAmount: "3",
		Memo:              "transfer memo",
		CallData:          "",
		ExpiredAt:         1654656781000, // milli seconds
		Nonce:             1,
	}

	res, err := json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))
}

package test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/zecrey-labs/zecrey-crypto/wasm/zecrey-legend/legendTxTypes"
	"log"
	"testing"
)

func TestCreateCollectionSegmentFormat(t *testing.T){

	var segmentFormat *legendTxTypes.CreateCollectionSegmentFormat
	segmentFormat = &legendTxTypes.CreateCollectionSegmentFormat{
		AccountIndex:      0,
		CollectionId:      1,
		Name:              "crypto punk",
		Introduction:      "crypto punk is the king of jpeg nft",
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
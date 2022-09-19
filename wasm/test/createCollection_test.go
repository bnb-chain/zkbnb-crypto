package test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/zkbnb-crypto/wasm/txtypes"
)

func TestCreateCollectionSegmentFormat(t *testing.T) {

	var segmentFormat *txtypes.CreateCollectionSegmentFormat
	segmentFormat = &txtypes.CreateCollectionSegmentFormat{
		AccountIndex:      0,
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

package test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCancelOfferSegmentFormat(t *testing.T) {

	var segmentFormat *txtypes.CancelOfferSegmentFormat
	segmentFormat = &txtypes.CancelOfferSegmentFormat{
		AccountIndex:      0,
		OfferId:           1,
		GasAccountIndex:   1,
		GasFeeAssetId:     3,
		GasFeeAssetAmount: "3",
		Nonce:             1,
		ExpiredAt:         1654656781000, // milli seconds
	}

	res, err := json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))

}

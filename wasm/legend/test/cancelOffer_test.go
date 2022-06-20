package test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/bnb-chain/zkbas-crypto/wasm/legend/legendTxTypes"
	"log"
	"testing"
)

func TestCancelOfferSegmentFormat(t *testing.T){

	var segmentFormat *legendTxTypes.CancelOfferSegmentFormat
	segmentFormat = &legendTxTypes.CancelOfferSegmentFormat{
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
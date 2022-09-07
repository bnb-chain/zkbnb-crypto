package test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/zkbnb-crypto/wasm/legend/legendTxTypes"
)

func TestOfferSegmentFormat(t *testing.T) {

	var segmentFormat *legendTxTypes.OfferSegmentFormat
	// buy offer
	segmentFormat = &legendTxTypes.OfferSegmentFormat{
		Type:         0,
		OfferId:      1,
		AccountIndex: 1,
		NftIndex:     1500,
		AssetId:      1,
		AssetAmount:  "10000",
		ListedAt:     1654656761000,
		ExpiredAt:    1654656781000, // milli seconds
		TreasuryRate: 200,           // 2%
	}

	res, err := json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))
	// sell offer
	segmentFormat = &legendTxTypes.OfferSegmentFormat{
		Type:         1,
		OfferId:      1,
		AccountIndex: 2,
		NftIndex:     1500,
		AssetId:      1,
		AssetAmount:  "10000",
		ListedAt:     1654656751000,
		ExpiredAt:    1654656791000, // milli seconds
		TreasuryRate: 200,           // 2%
	}

	res, err = json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))

}

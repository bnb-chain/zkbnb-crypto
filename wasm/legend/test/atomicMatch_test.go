package test

import (
	"encoding/json"
	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbnb-crypto/wasm/legend/legendTxTypes"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestAtomicMatchSegmentFormat(t *testing.T) {

	var segmentFormat *legendTxTypes.AtomicMatchSegmentFormat
	segmentFormat = &legendTxTypes.AtomicMatchSegmentFormat{
		AccountIndex:      0,
		BuyOffer:          "{\"Type\":0,\"OfferId\":1,\"AccountIndex\":1,\"NftIndex\":1500,\"AssetId\":1,\"AssetAmount\":10000,\"ListedAt\":1654656761000,\"ExpiredAt\":1654656781000,\"TreasuryRate\":200,\"Sig\":\"f7EryTm0P7xCgDYsyB+R+Of3ZHHyVa4uEI721shjoQgFdYuoMst49X0NFf9MraQevweNVH+728FHh0c1hEz20A==\"}",
		SellOffer:         "{\"Type\":1,\"OfferId\":1,\"AccountIndex\":2,\"NftIndex\":1500,\"AssetId\":1,\"AssetAmount\":10000,\"ListedAt\":1654656751000,\"ExpiredAt\":1654656791000,\"TreasuryRate\":200,\"Sig\":\"cCh08P8RloU+uNZESVVbl5mqOFiiXR2JRJaAnmqxz6gCBXny2J9OUh5X7tRHaEBxDRRXQ1mQGMVMoe1/ncw3sQ==\"}",
		GasAccountIndex:   1,
		GasFeeAssetId:     3,
		GasFeeAssetAmount: "3",
		Nonce:             1,
		ExpiredAt:         1654656781000, // milli seconds
	}

	res, err := json.Marshal(segmentFormat)
	assert.Nil(t, err)

	log.Println(string(res))

	var OfferTx *legendTxTypes.OfferTxInfo
	err = json.Unmarshal([]byte(segmentFormat.BuyOffer), &OfferTx)
	assert.Nil(t, err)
	log.Println(OfferTx)

	var atomicSig = "{\"account_index\":0,\"buy_offer\":\"{\\\"Type\\\":0,\\\"OfferId\\\":1,\\\"AccountIndex\\\":1,\\\"NftIndex\\\":1500,\\\"AssetId\\\":1,\\\"AssetAmount\\\":10000,\\\"ListedAt\\\":1654656761000,\\\"ExpiredAt\\\":1654656781000,\\\"TreasuryRate\\\":200,\\\"Sig\\\":\\\"f7EryTm0P7xCgDYsyB+R+Of3ZHHyVa4uEI721shjoQgFdYuoMst49X0NFf9MraQevweNVH+728FHh0c1hEz20A==\\\"}\",\"sell_offer\":\"{\\\"Type\\\":1,\\\"OfferId\\\":1,\\\"AccountIndex\\\":2,\\\"NftIndex\\\":1500,\\\"AssetId\\\":1,\\\"AssetAmount\\\":10000,\\\"ListedAt\\\":1654656751000,\\\"ExpiredAt\\\":1654656791000,\\\"TreasuryRate\\\":200,\\\"Sig\\\":\\\"cCh08P8RloU+uNZESVVbl5mqOFiiXR2JRJaAnmqxz6gCBXny2J9OUh5X7tRHaEBxDRRXQ1mQGMVMoe1/ncw3sQ==\\\"}\",\"gas_account_index\":1,\"gas_fee_asset_id\":3,\"gas_fee_asset_amount\":\"3\",\"nonce\":1,\"expired_at\":1654656781000}"

	err = json.Unmarshal([]byte(atomicSig), &segmentFormat)
	log.Println(segmentFormat)

	sk, err := curve.GenerateEddsaPrivateKey("seed")
	_, err = legendTxTypes.ConstructAtomicMatchTxInfo(sk, atomicSig)
	assert.Nil(t, err)
}

/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package legendTxTypes

import (
	"bytes"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"hash"
	"log"
	"math/big"
)

type OfferSegmentFormat struct {
	Type         int64  `json:"type"`
	OfferId      int64  `json:"offer_id"`
	AccountIndex int64  `json:"account_index"`
	NftIndex     int64  `json:"nft_index"`
	AssetId      int64  `json:"asset_id"`
	AssetAmount  string `json:"asset_amount"`
	ListedAt     int64  `json:"listed_at"`
	ExpiredAt    int64  `json:"expired_at"`
}

/*
	ConstructOfferTxInfo: construct offer tx, sign txInfo
*/
func ConstructOfferTxInfo(sk *PrivateKey, segmentStr string) (txInfo *OfferTxInfo, err error) {
	var segmentFormat *OfferSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructOfferTxInfo] err info:", err)
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructOfferTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	txInfo = &OfferTxInfo{
		Type:         segmentFormat.Type,
		OfferId:      segmentFormat.OfferId,
		AccountIndex: segmentFormat.AccountIndex,
		NftIndex:     segmentFormat.NftIndex,
		AssetId:      segmentFormat.AssetId,
		AssetAmount:  assetAmount,
		ListedAt:     segmentFormat.ListedAt,
		ExpiredAt:    segmentFormat.ExpiredAt,
		Sig:          nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeOfferMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructOfferTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type OfferTxInfo struct {
	Type         int64
	OfferId      int64
	AccountIndex int64
	NftIndex     int64
	AssetId      int64
	AssetAmount  *big.Int
	ListedAt     int64
	ExpiredAt    int64
	Sig          []byte
}

func ComputeOfferMsgHash(txInfo *OfferTxInfo, hFunc hash.Hash) (msgHash []byte) {
	hFunc.Reset()
	var buf bytes.Buffer
	WriteInt64IntoBuf(&buf, txInfo.Type)
	WriteInt64IntoBuf(&buf, txInfo.OfferId)
	WriteInt64IntoBuf(&buf, txInfo.AccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.AssetId)
	WriteBigIntIntoBuf(&buf, txInfo.AssetAmount)
	WriteInt64IntoBuf(&buf, txInfo.ListedAt)
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}

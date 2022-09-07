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
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

const (
	BuyOfferType  = 0
	SellOfferType = 1
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
	TreasuryRate int64  `json:"treasury_rate"`
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
	assetAmount, _ = CleanPackedAmount(assetAmount)
	txInfo = &OfferTxInfo{
		Type:         segmentFormat.Type,
		OfferId:      segmentFormat.OfferId,
		AccountIndex: segmentFormat.AccountIndex,
		NftIndex:     segmentFormat.NftIndex,
		AssetId:      segmentFormat.AssetId,
		AssetAmount:  assetAmount,
		ListedAt:     segmentFormat.ListedAt,
		ExpiredAt:    segmentFormat.ExpiredAt,
		TreasuryRate: segmentFormat.TreasuryRate,
		Sig:          nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := ComputeOfferMsgHash(txInfo, hFunc)
	if err != nil {
		return nil, err
	}
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
	TreasuryRate int64
	Sig          []byte
}

func (txInfo *OfferTxInfo) Validate() error {
	// Type
	if txInfo.Type != BuyOfferType && txInfo.Type != SellOfferType {
		return fmt.Errorf("Type should only be buy(%d) and sell(%d)", BuyOfferType, SellOfferType)
	}

	// OfferId
	if txInfo.OfferId < 0 {
		return fmt.Errorf("OfferId should not be less than 0")
	}

	// AccountIndex
	if txInfo.AccountIndex < minAccountIndex {
		return fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex)
	}

	// NftIndex
	if txInfo.NftIndex < minNftIndex {
		return fmt.Errorf("NftIndex should not be less than %d", minNftIndex)
	}
	if txInfo.NftIndex > maxNftIndex {
		return fmt.Errorf("NftIndex should not be larger than %d", maxNftIndex)
	}

	// AssetId
	if txInfo.AssetId < minAssetId {
		return fmt.Errorf("AssetId should not be less than %d", minAssetId)
	}
	if txInfo.AssetId > maxAssetId {
		return fmt.Errorf("AssetId should not be larger than %d", maxAssetId)
	}

	// AssetAmount
	if txInfo.AssetAmount == nil {
		return fmt.Errorf("AssetAmount should not be nil")
	}
	if txInfo.AssetAmount.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetAmount should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetAmount.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetAmount should not be larger than %s", maxAssetAmount.String())
	}

	// ListedAt
	if txInfo.ListedAt <= 0 {
		return fmt.Errorf("ListedAt should be larger than 0")
	}

	// TreasuryRate
	if txInfo.TreasuryRate < minTreasuryRate {
		return fmt.Errorf("TreasuryRate should  not be less than %d", minTreasuryRate)
	}
	if txInfo.TreasuryRate > maxTreasuryRate {
		return fmt.Errorf("TreasuryRate should not be larger than %d", maxTreasuryRate)
	}
	return nil
}

func (txInfo *OfferTxInfo) VerifySignature(pubKey string) error {
	// compute hash
	hFunc := crypto.NewKeccakState()
	msgHash, err := ComputeOfferMsgHash(txInfo, hFunc)
	if err != nil {
		return err
	}
	// verify signature
	hFunc.Reset()
	isValid := crypto.VerifySignature(common.Hex2Bytes(pubKey), msgHash, txInfo.Sig)
	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid signature")
	}
	return nil
}

func (txInfo *OfferTxInfo) GetTxType() int {
	return TxTypeOffer
}

func (txInfo *OfferTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *OfferTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func ComputeOfferMsgHash(txInfo *OfferTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedAmount, err := ToPackedAmount(txInfo.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.Type)
	WriteInt64IntoBuf(&buf, txInfo.OfferId)
	WriteInt64IntoBuf(&buf, txInfo.AccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.AssetId)
	WriteInt64IntoBuf(&buf, packedAmount)
	WriteInt64IntoBuf(&buf, txInfo.ListedAt)
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.TreasuryRate)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}

/*
 * Copyright © 2022 ZkBNB Protocol
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

package txtypes

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/bnb-chain/zkbnb-crypto/ffmath"
	"github.com/bnb-chain/zkbnb-crypto/util"
	"github.com/bnb-chain/zkbnb-crypto/wasm/signature"
	"github.com/ethereum/go-ethereum/common"
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
	Type                int64  `json:"type"`
	OfferId             int64  `json:"offer_id"`
	AccountIndex        int64  `json:"account_index"`
	NftIndex            int64  `json:"nft_index"`
	AssetId             int64  `json:"asset_id"`
	AssetAmount         string `json:"asset_amount"`
	ListedAt            int64  `json:"listed_at"`
	ExpiredAt           int64  `json:"expired_at"`
	RoyaltyRate         int64  `json:"royalty_rate"`
	ChannelAccountIndex int64  `json:"channel_account_index"`
	ChannelRate         int64  `json:"channel_rate"`
	ProtocolRate        int64  `json:"protocol_rate"`
	ProtocolAmount      string `json:"protocol_amount"`
}

func ConstructOfferTxInfo(sk *PrivateKey, segmentStr string) (txInfo *OfferTxInfo, err error) {
	var segmentFormat *OfferSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructOfferTxInfo] err info:", err)
		return nil, err
	}
	assetAmount, err := StringToBigInt(segmentFormat.AssetAmount)
	if err != nil {
		log.Println("[ConstructOfferTxInfo] assetAmount unable to convert string to big int:", err)
		return nil, err
	}
	assetAmount, _ = CleanPackedAmount(assetAmount)

	protocolAmount, err := StringToBigInt(segmentFormat.ProtocolAmount)
	if err != nil {
		log.Println("[ConstructOfferTxInfo] protocolAmount unable to convert string to big int:", err)
		return nil, err
	}
	protocolAmount, _ = CleanPackedAmount(protocolAmount)

	txInfo = &OfferTxInfo{
		Type:                segmentFormat.Type,
		OfferId:             segmentFormat.OfferId,
		AccountIndex:        segmentFormat.AccountIndex,
		NftIndex:            segmentFormat.NftIndex,
		AssetId:             segmentFormat.AssetId,
		AssetAmount:         assetAmount,
		ListedAt:            segmentFormat.ListedAt,
		ExpiredAt:           segmentFormat.ExpiredAt,
		RoyaltyRate:         segmentFormat.RoyaltyRate,
		ChannelAccountIndex: segmentFormat.ChannelAccountIndex,
		ChannelRate:         segmentFormat.ChannelRate,
		ProtocolRate:        segmentFormat.ProtocolRate,
		ProtocolAmount:      protocolAmount,
		Sig:                 nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := txInfo.Hash(hFunc)
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
	Type                int64
	OfferId             int64
	AccountIndex        int64
	NftIndex            int64
	AssetId             int64
	AssetAmount         *big.Int
	ListedAt            int64
	ExpiredAt           int64
	RoyaltyRate         int64
	ChannelAccountIndex int64
	ChannelRate         int64
	ProtocolRate        int64
	ProtocolAmount      *big.Int
	Sig                 []byte
	L1Sig               string
}

func (txInfo *OfferTxInfo) GetTxType() int {
	return TxTypeOffer
}

func (txInfo *OfferTxInfo) Validate() error {
	// Type
	if txInfo.Type != BuyOfferType && txInfo.Type != SellOfferType {
		return ErrOfferTypeInvalid
	}

	// OfferId
	if txInfo.OfferId < 0 {
		return ErrOfferIdTooLow
	}

	// AccountIndex
	if txInfo.AccountIndex < minAccountIndex {
		return ErrAccountIndexTooLow
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return ErrAccountIndexTooHigh
	}

	// NftIndex
	if txInfo.NftIndex < minNftIndex {
		return ErrNftIndexTooLow
	}
	if txInfo.NftIndex > maxNftIndex {
		return ErrNftIndexTooHigh
	}

	// AssetId
	if txInfo.AssetId < minAssetId {
		return ErrAssetIdTooLow
	}
	if txInfo.AssetId > maxAssetId {
		return ErrAssetIdTooHigh
	}

	// AssetAmount
	if txInfo.AssetAmount == nil {
		return fmt.Errorf("AssetAmount should not be nil")
	}
	if txInfo.AssetAmount.Cmp(minAssetAmount) <= 0 {
		return ErrAssetAmountTooLow
	}
	if txInfo.AssetAmount.Cmp(maxAssetAmount) > 0 {
		return ErrAssetAmountTooHigh
	}
	assetAmount, _ := CleanPackedAmount(txInfo.AssetAmount)
	if txInfo.AssetAmount.Cmp(assetAmount) != 0 {
		return ErrAssetAmountPrecision
	}

	// ChannelAccountIndex
	if txInfo.ChannelAccountIndex < minAccountIndex {
		return ErrAccountIndexTooLow
	}
	if txInfo.ChannelAccountIndex > maxAccountIndex {
		return ErrAccountIndexTooHigh
	}
	// ListedAt
	if txInfo.ListedAt <= 0 {
		return ErrListedAtTooLow
	}

	if txInfo.Type == BuyOfferType {
		//ChannelRate
		if txInfo.ChannelRate < minRate {
			return ErrChannelRateTooLow
		}
		if txInfo.ChannelRate > maxRate {
			return ErrChannelRateTooHigh
		}

		//ProtocolRate
		if txInfo.ProtocolRate < minRate {
			return ErrProtocolRateTooLow
		}
		if txInfo.ProtocolRate > maxRate {
			return ErrProtocolRateTooHigh
		}
		//ProtocolAmount
		if txInfo.ProtocolAmount == nil {
			return fmt.Errorf("ProtocolAmount should not be nil")
		}
		if txInfo.ProtocolAmount.Cmp(minAssetAmount) <= 0 {
			return ErrProtocolAmountTooLow
		}
		if txInfo.ProtocolAmount.Cmp(maxAssetAmount) > 0 {
			return ErrProtocolAmountTooHigh
		}
		protocolAmount, _ := CleanPackedAmount(txInfo.ProtocolAmount)
		if protocolAmount.Cmp(txInfo.ProtocolAmount) != 0 {
			return ErrProtocolAmountPrecision
		}
		protocolAmount = ffmath.Div(ffmath.Multiply(txInfo.AssetAmount, big.NewInt(txInfo.ProtocolRate)), big.NewInt(types.RateBase))
		if protocolAmount.Cmp(txInfo.ProtocolAmount) != 0 {
			return ErrProtocolAmountInvalid
		}
	} else {
		//ChannelRate
		if txInfo.ChannelRate < minRate {
			return ErrChannelRateTooLow
		}
		if txInfo.ChannelRate > maxSellRate {
			return ErrChannelRateTooHigh
		}
	}

	//ChannelAmount
	channelAmount := ffmath.Div(ffmath.Multiply(txInfo.AssetAmount, big.NewInt(txInfo.ChannelRate)), big.NewInt(types.RateBase))
	channelAmountPrecision, _ := CleanPackedAmount(channelAmount)
	if channelAmount.Cmp(channelAmountPrecision) != 0 {
		return ErrChannelAmountPrecision
	}

	// RoyaltyRate
	if txInfo.RoyaltyRate < minRate {
		return ErrRoyaltyRateTooLow
	}
	if txInfo.RoyaltyRate > maxRate {
		return ErrRoyaltyRateTooHigh
	}
	royaltyAmount := ffmath.Div(ffmath.Multiply(txInfo.AssetAmount, big.NewInt(txInfo.RoyaltyRate)), big.NewInt(types.RateBase))
	royaltyAmountPrecision, _ := CleanPackedAmount(royaltyAmount)
	if royaltyAmount.Cmp(royaltyAmountPrecision) != 0 {
		return ErrRoyaltyAmountPrecision
	}
	return nil
}

func (txInfo *OfferTxInfo) VerifySignature(pubKey string) error {
	// compute hash
	hFunc := mimc.NewMiMC()
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		return err
	}
	// verify signature
	hFunc.Reset()
	pk, err := ParsePublicKey(pubKey)
	if err != nil {
		return err
	}
	isValid, err := pk.Verify(txInfo.Sig, msgHash, hFunc)
	if err != nil {
		return err
	}

	if !isValid {
		return errors.New("invalid signature")
	}
	return nil
}

func (txInfo *OfferTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *OfferTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetL1SignatureBody() string {
	signatureBody := fmt.Sprintf(signature.SignatureTemplateOffer, txInfo.AccountIndex,
		txInfo.NftIndex, txInfo.AssetId, util.FormatWeiToEtherStr(txInfo.AssetAmount))
	return signatureBody
}

func (txInfo *OfferTxInfo) GetL1AddressBySignature() common.Address {
	return signature.CalculateL1AddressBySignature(txInfo.GetL1SignatureBody(), txInfo.L1Sig)
}

func (txInfo *OfferTxInfo) GetNonce() int64 {
	return NilNonce
}

func (txInfo *OfferTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *OfferTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	packedAmount, err := ToPackedAmount(txInfo.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] assetAmount unable to packed amount:", err.Error())
		return nil, err
	}
	if txInfo.Type == BuyOfferType {
		packedProtocolAmount, err := ToPackedAmount(txInfo.ProtocolAmount)
		if err != nil {
			log.Println("[ComputeTransferMsgHash] protocolAmount unable to packed amount:", err.Error())
			return nil, err
		}
		msgHash = Poseidon(txInfo.Type, txInfo.OfferId, txInfo.AccountIndex, txInfo.NftIndex,
			txInfo.AssetId, packedAmount, txInfo.ListedAt, txInfo.ExpiredAt, txInfo.RoyaltyRate, txInfo.ChannelAccountIndex,
			txInfo.ChannelRate, txInfo.ProtocolRate, packedProtocolAmount, 0)
		return msgHash, nil
	} else {
		msgHash = Poseidon(txInfo.Type, txInfo.OfferId, txInfo.AccountIndex, txInfo.NftIndex,
			txInfo.AssetId, packedAmount, txInfo.ListedAt, txInfo.ExpiredAt, txInfo.ChannelAccountIndex,
			txInfo.ChannelRate)
		return msgHash, nil
	}
}

func (txInfo *OfferTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

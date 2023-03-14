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
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
	L1Sig        string
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

	// ListedAt
	if txInfo.ListedAt <= 0 {
		return ErrListedAtTooLow
	}

	// TreasuryRate
	if txInfo.TreasuryRate < minTreasuryRate {
		return ErrTreasuryRateTooLow
	}
	if txInfo.TreasuryRate > maxTreasuryRate {
		return ErrTreasuryRateTooHigh
	}

	if len(txInfo.L1Sig) == 0 {
		return ErrL1SigInvalid
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

func (txInfo *OfferTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetToAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *OfferTxInfo) GetL1Signature() string {
	return "xx"
}

func (txInfo *OfferTxInfo) GetL1AddressBySignatureInfo() common.Address {
	message := accounts.TextHash([]byte(txInfo.GetL1Signature()))
	//Decode from signature string to get the signature byte array
	signatureContent, err := hexutil.Decode(txInfo.L1Sig)
	if err != nil {
		return [20]byte{}
	}
	signatureContent[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	//Calculate the public key from the signature and source string
	signaturePublicKey, err := crypto.SigToPub(message, signatureContent)
	if err != nil {
		return [20]byte{}
	}

	//Calculate the address from the public key
	publicAddress := crypto.PubkeyToAddress(*signaturePublicKey)
	return publicAddress
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
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	msgHash = Poseidon(txInfo.Type, txInfo.OfferId, txInfo.AccountIndex, txInfo.NftIndex,
		txInfo.AssetId, packedAmount, txInfo.ListedAt, txInfo.ExpiredAt, txInfo.TreasuryRate,
	)
	return msgHash, nil
}

func (txInfo *OfferTxInfo) GetGas() (int64, int64, *big.Int) {
	return NilAccountIndex, NilAssetId, nil
}

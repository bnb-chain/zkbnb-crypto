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
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/pkg/errors"
)

type AtomicMatchSegmentFormat struct {
	AccountIndex int64  `json:"account_index"`
	BuyOffer     string `json:"buy_offer"`
	// OfferTxInfo Type
	SellOffer string `json:"sell_offer"`
	// OfferTxInfo Type
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
	// transaction amount +1 for fromAccountIndex
	ExpiredAt int64 `json:"expired_at"`
	// transaction expire time in milli-second type
	// eg. current timestamp + 1 week
}

/*
ConstructMintNftTxInfo: construct mint nft tx, sign txInfo
*/
func ConstructAtomicMatchTxInfo(sk *PrivateKey, segmentStr string) (txInfo *AtomicMatchTxInfo, err error) {
	var segmentFormat *AtomicMatchSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructMintNftTxInfo] err info:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	var (
		buyOffer, sellOffer *OfferTxInfo
	)
	err = json.Unmarshal([]byte(segmentFormat.BuyOffer), &buyOffer)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to unmarshal offer", err.Error())
		return nil, err
	}
	err = json.Unmarshal([]byte(segmentFormat.SellOffer), &sellOffer)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to unmarshal offer", err.Error())
		return nil, err
	}
	txInfo = &AtomicMatchTxInfo{
		AccountIndex:      segmentFormat.AccountIndex,
		BuyOffer:          buyOffer,
		SellOffer:         sellOffer,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		Nonce:             segmentFormat.Nonce,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		log.Println("[ConstructMintNftTxInfo] unable to compute hash: ", err.Error())
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructMintNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type AtomicMatchTxInfo struct {
	AccountIndex      int64
	BuyOffer          *OfferTxInfo
	SellOffer         *OfferTxInfo
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	RoyaltyAmount     *big.Int
	BuyChannelAmount  *big.Int
	SellChannelAmount *big.Int
	Nonce             int64
	ExpiredAt         int64
	Sig               []byte
}

func (txInfo *AtomicMatchTxInfo) Validate() error {
	// AccountIndex
	if txInfo.AccountIndex < minAccountIndex {
		return ErrAccountIndexTooLow
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return ErrAccountIndexTooHigh
	}

	// BuyOffer
	if txInfo.BuyOffer == nil {
		return fmt.Errorf("BuyOffer should not be nil")
	}
	if err := txInfo.BuyOffer.Validate(); err != nil {
		return errors.Wrap(ErrBuyOfferInvalid, err.Error())
	}

	// SellOffer
	if txInfo.SellOffer == nil {
		return fmt.Errorf("SellOffer should not be nil")
	}
	if err := txInfo.SellOffer.Validate(); err != nil {
		return errors.Wrap(ErrSellOfferInvalid, err.Error())
	}

	// GasAccountIndex
	if txInfo.GasAccountIndex < minAccountIndex {
		return ErrGasAccountIndexTooLow
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return ErrGasAccountIndexTooHigh
	}

	// GasFeeAssetId
	if txInfo.GasFeeAssetId < minAssetId {
		return ErrGasFeeAssetIdTooLow
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return ErrGasFeeAssetIdTooHigh
	}

	// GasFeeAssetAmount
	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return ErrGasFeeAssetAmountTooLow
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return ErrGasFeeAssetAmountTooHigh
	}
	gasFeeAmount, _ := CleanPackedFee(txInfo.GasFeeAssetAmount)
	if txInfo.GasFeeAssetAmount.Cmp(gasFeeAmount) != 0 {
		return ErrGasFeeAssetAmountPrecision
	}
	// Nonce
	if txInfo.Nonce < minNonce {
		return ErrNonceTooLow
	}

	return nil
}

func (txInfo *AtomicMatchTxInfo) VerifySignature(pubKey string) error {
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

func (txInfo *AtomicMatchTxInfo) GetTxType() int {
	return TxTypeAtomicMatch
}

func (txInfo *AtomicMatchTxInfo) GetPubKey() string {
	return ""
}

func (txInfo *AtomicMatchTxInfo) GetAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *AtomicMatchTxInfo) GetFromAccountIndex() int64 {
	return txInfo.SellOffer.AccountIndex
}

func (txInfo *AtomicMatchTxInfo) GetToAccountIndex() int64 {
	return txInfo.BuyOffer.AccountIndex
}

func (txInfo *AtomicMatchTxInfo) GetL1SignatureBody() string {
	return ""
}

func (txInfo *AtomicMatchTxInfo) GetL1AddressBySignature() common.Address {
	return [20]byte{}
}

func (txInfo *AtomicMatchTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *AtomicMatchTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *AtomicMatchTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	packedBuyAmount, err := ToPackedAmount(txInfo.BuyOffer.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedBuyProtocolAmount, err := ToPackedAmount(txInfo.BuyOffer.ProtocolAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] packedBuyProtocolAmount unable to packed amount:", err.Error())
		return nil, err
	}

	packedSellAmount, err := ToPackedAmount(txInfo.SellOffer.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	var (
		buyerSig, sellerSig = new(eddsa.Signature), new(eddsa.Signature)
	)
	_, err = buyerSig.SetBytes(txInfo.BuyOffer.Sig)
	if err != nil {
		log.Println("[ComputeAtomicMatchMsgHash] unable to convert to buyer sig: ", err.Error())
		return nil, err
	}
	_, err = sellerSig.SetBytes(txInfo.SellOffer.Sig)
	if err != nil {
		log.Println("[ComputeAtomicMatchMsgHash] unable to convert to seller sig: ", err.Error())
		return nil, err
	}
	buyOfferHash := Poseidon(txInfo.BuyOffer.Type, txInfo.BuyOffer.OfferId, txInfo.BuyOffer.AccountIndex, txInfo.BuyOffer.NftIndex,
		txInfo.BuyOffer.AssetId, packedBuyAmount, txInfo.BuyOffer.ListedAt, txInfo.BuyOffer.ExpiredAt,
		buyerSig.R.X.Marshal(), buyerSig.R.Y.Marshal(), buyerSig.S[:], txInfo.BuyOffer.RoyaltyRate, txInfo.BuyOffer.ChannelAccountIndex,
		txInfo.BuyOffer.ChannelRate, txInfo.BuyOffer.ProtocolRate, packedBuyProtocolAmount)
	sellOfferHash := Poseidon(txInfo.SellOffer.Type, txInfo.SellOffer.OfferId, txInfo.SellOffer.AccountIndex, txInfo.SellOffer.NftIndex,
		txInfo.SellOffer.AssetId, packedSellAmount, txInfo.SellOffer.ListedAt, txInfo.SellOffer.ExpiredAt,
		sellerSig.R.X.Marshal(), sellerSig.R.Y.Marshal(), sellerSig.S[:], txInfo.SellOffer.ChannelAccountIndex,
		txInfo.SellOffer.ChannelRate, 0)
	msgHash = Poseidon(ChainId, TxTypeAtomicMatch, txInfo.AccountIndex, txInfo.Nonce, txInfo.ExpiredAt, txInfo.GasFeeAssetId, packedFee, buyOfferHash, sellOfferHash)
	return msgHash, nil
}

func (txInfo *AtomicMatchTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}

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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/abi"
	abiEth "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"log"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
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
	msgHash, err := ComputeAtomicMatchMsgHash(txInfo, hFunc)
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
	CreatorAmount     *big.Int
	TreasuryAmount    *big.Int
	Nonce             int64
	ExpiredAt         int64
	Sig               []byte
}

func (txInfo *AtomicMatchTxInfo) Validate() error {
	// AccountIndex
	if txInfo.AccountIndex < minAccountIndex {
		return fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex)
	}

	// BuyOffer
	if txInfo.BuyOffer == nil {
		return fmt.Errorf("BuyOffer should not be nil")
	}
	if err := txInfo.BuyOffer.Validate(); err != nil {
		return fmt.Errorf("BuyOffer is invalid, %s", err.Error())
	}

	// SellOffer
	if txInfo.SellOffer == nil {
		return fmt.Errorf("SellOffer should not be nil")
	}
	if err := txInfo.SellOffer.Validate(); err != nil {
		return fmt.Errorf("SellOffer is invalid, %s", err.Error())
	}

	// GasAccountIndex
	if txInfo.GasAccountIndex < minAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex)
	}

	// GasFeeAssetId
	if txInfo.GasFeeAssetId < minAssetId {
		return fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId)
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId)
	}

	// GasFeeAssetAmount
	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String())
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String())
	}

	// Nonce
	if txInfo.Nonce < minNonce {
		return fmt.Errorf("Nonce should not be less than %d", minNonce)
	}

	return nil
}

func (txInfo *AtomicMatchTxInfo) VerifySignature(pubKey string) error {
	// compute hash
	abiEncoder, err := abiEth.JSON(strings.NewReader(abi.AtomicMatchABIJSON))
	if err != nil {
		return err
	}
	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.AtomicMatch)

	inner, err := abiEncoder.Pack("", messageTypeBytes32, txInfo.SellOffer.AccountIndex, txInfo.SellOffer.NftIndex, txInfo.SellOffer.OfferId, txInfo.SellOffer.Type, txInfo.SellOffer.AssetId,
		txInfo.SellOffer.AssetAmount, txInfo.SellOffer.ListedAt, txInfo.SellOffer.ExpiredAt, txInfo.SellOffer.TreasuryRate, ConvertBytesToBytes32(txInfo.SellOffer.Sig[:32]), ConvertBytesToBytes32(txInfo.SellOffer.Sig[32:64]),
		txInfo.BuyOffer.AccountIndex, txInfo.BuyOffer.NftIndex, txInfo.BuyOffer.OfferId, txInfo.BuyOffer.Type, txInfo.BuyOffer.AssetId,
		txInfo.BuyOffer.AssetAmount, txInfo.BuyOffer.ListedAt, txInfo.BuyOffer.ExpiredAt, txInfo.BuyOffer.TreasuryRate, ConvertBytesToBytes32(txInfo.BuyOffer.Sig[:32]), ConvertBytesToBytes32(txInfo.BuyOffer.Sig[32:64]), txInfo.Nonce, ChainId)
	if err != nil {
		return err
	}

	innerKeccak := crypto.Keccak256(inner)
	prefixBytes, err := hex.DecodeString(abi.HexPrefixAndEip712DomainKeccakHash)
	if err != nil {
		return err
	}

	outerBytes := append(prefixBytes, innerKeccak...)
	outerBytesKeccak := crypto.Keccak256(outerBytes)

	pk, err := crypto.Ecrecover(outerBytesKeccak, txInfo.Sig)
	if common.Bytes2Hex(pk) != pubKey {
		return errors.New("invalid signature")
	}
	return nil
}

func (txInfo *AtomicMatchTxInfo) GetTxType() int {
	return TxTypeAtomicMatch
}

func (txInfo *AtomicMatchTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *AtomicMatchTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *AtomicMatchTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func ComputeAtomicMatchMsgHash(txInfo *AtomicMatchTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedBuyAmount, err := ToPackedAmount(txInfo.BuyOffer.AssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
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
	WriteInt64IntoBuf(&buf, txInfo.AccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.Type)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.OfferId)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.AccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.AssetId)
	WriteInt64IntoBuf(&buf, packedBuyAmount)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.ListedAt)
	WriteInt64IntoBuf(&buf, txInfo.BuyOffer.ExpiredAt)
	var (
		buyerSig, sellerSig = new(eddsa.Signature), new(eddsa.Signature)
	)
	_, err = buyerSig.SetBytes(txInfo.BuyOffer.Sig)
	if err != nil {
		log.Println("[ComputeAtomicMatchMsgHash] unable to convert to sig: ", err.Error())
		return nil, err
	}
	buf.Write(buyerSig.R.X.Marshal())
	buf.Write(buyerSig.R.Y.Marshal())
	buf.Write(buyerSig.S[:])
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.Type)
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.OfferId)
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.AccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.NftIndex)
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.AssetId)
	WriteInt64IntoBuf(&buf, packedSellAmount)
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.ListedAt)
	WriteInt64IntoBuf(&buf, txInfo.SellOffer.ExpiredAt)
	_, err = sellerSig.SetBytes(txInfo.SellOffer.Sig)
	if err != nil {
		log.Println("[ComputeAtomicMatchMsgHash] unable to convert to sig: ", err.Error())
		return nil, err
	}
	buf.Write(sellerSig.R.X.Marshal())
	buf.Write(sellerSig.R.Y.Marshal())
	buf.Write(sellerSig.S[:])
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, packedFee)
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	WriteInt64IntoBuf(&buf, ChainId)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}

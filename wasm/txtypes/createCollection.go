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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type CreateCollectionSegmentFormat struct {
	AccountIndex      int64  `json:"account_index"`
	Name              string `json:"name"`
	Introduction      string `json:"introduction"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

/*
	ConstructCreateCollectionTxInfo: construct mint nft tx, sign txInfo
*/
func ConstructCreateCollectionTxInfo(sk *PrivateKey, segmentStr string) (txInfo *CreateCollectionTxInfo, err error) {
	var segmentFormat *CreateCollectionSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructCreateCollectionTxInfo] err info:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &CreateCollectionTxInfo{
		AccountIndex:      segmentFormat.AccountIndex,
		Name:              segmentFormat.Name,
		Introduction:      segmentFormat.Introduction,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash, err := txInfo.Hash(hFunc)
	if err != nil {
		log.Println("[ConstructCreateCollectionTxInfo] unable to compute hash:", err)
		return nil, err
	}
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructCreateCollectionTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type CreateCollectionTxInfo struct {
	AccountIndex      int64
	CollectionId      int64
	Name              string
	Introduction      string
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
}

func (txInfo *CreateCollectionTxInfo) Validate() error {
	// AccountIndex
	if txInfo.AccountIndex < minAccountIndex {
		return fmt.Errorf("AccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.AccountIndex > maxAccountIndex {
		return fmt.Errorf("AccountIndex should not be larger than %d", maxAccountIndex)
	}

	// Name
	if len(txInfo.Name) < minCollectionNameLength {
		return fmt.Errorf("length of Name should not be less than %d", minCollectionNameLength)
	}
	if len(txInfo.Name) > maxCollectionNameLength {
		return fmt.Errorf("length of Name should not be larger than %d", maxCollectionNameLength)
	}

	// Introduction
	if len(txInfo.Introduction) > maxCollectionIntroductionLength {
		return fmt.Errorf("length of Introduction should not be larger than %d", maxCollectionIntroductionLength)
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

func (txInfo *CreateCollectionTxInfo) VerifySignature(pubKey string) error {
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

func (txInfo *CreateCollectionTxInfo) GetTxType() int {
	return TxTypeCreateCollection
}

func (txInfo *CreateCollectionTxInfo) GetFromAccountIndex() int64 {
	return txInfo.AccountIndex
}

func (txInfo *CreateCollectionTxInfo) GetNonce() int64 {
	return txInfo.Nonce
}

func (txInfo *CreateCollectionTxInfo) GetExpiredAt() int64 {
	return txInfo.ExpiredAt
}

func (txInfo *CreateCollectionTxInfo) Hash(hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.AccountIndex)
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

func (txInfo *CreateCollectionTxInfo) GetGas() (int64, int64, *big.Int) {
	return txInfo.GasAccountIndex, txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount
}

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
	"fmt"
	"hash"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type SwapSegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	PairIndex         int64  `json:"pair_index"`
	AssetAId          int64  `json:"asset_a_id"`
	AssetAAmount      string `json:"asset_a_amount"`
	AssetBId          int64  `json:"asset_b_id"`
	AssetBMinAmount   string `json:"asset_b_min_amount"`
	AssetBAmountDelta string `json:"asset_b_amount_delta"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	ExpiredAt         int64  `json:"expired_at"`
	Nonce             int64  `json:"nonce"`
}

func ConstructSwapTxInfo(sk *PrivateKey, segmentStr string) (txInfo *SwapTxInfo, err error) {
	var segmentFormat *SwapSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] err info:", err)
		return nil, err
	}
	assetAAmount, err := StringToBigInt(segmentFormat.AssetAAmount)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetAAmount, _ = CleanPackedAmount(assetAAmount)
	assetBMinAmount, err := StringToBigInt(segmentFormat.AssetBMinAmount)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetBMinAmount, _ = CleanPackedAmount(assetBMinAmount)
	assetBAmountDelta, err := StringToBigInt(segmentFormat.AssetBAmountDelta)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetBAmountDelta, _ = CleanPackedAmount(assetBAmountDelta)
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, _ = CleanPackedFee(gasFeeAmount)
	txInfo = &SwapTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		PairIndex:         segmentFormat.PairIndex,
		AssetAId:          segmentFormat.AssetAId,
		AssetAAmount:      assetAAmount,
		AssetBId:          segmentFormat.AssetBId,
		AssetBMinAmount:   assetBMinAmount,
		AssetBAmountDelta: assetBAmountDelta,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		Nonce:             segmentFormat.Nonce,
		ExpiredAt:         segmentFormat.ExpiredAt,
		Sig:               nil,
	}
	hFunc := mimc.NewMiMC()
	msgHash, err := ComputeSwapMsgHash(txInfo, hFunc)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] unable to compute hash:", err)
		return nil, err
	}
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type SwapTxInfo struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAAmount      *big.Int
	AssetBId          int64
	AssetBMinAmount   *big.Int
	AssetBAmountDelta *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	ExpiredAt         int64
	Nonce             int64
	Sig               []byte
}

func ValidateSwapTxInfo(txInfo *SwapTxInfo) error {
	if txInfo.FromAccountIndex < minAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.FromAccountIndex > maxAccountIndex {
		return fmt.Errorf("FromAccountIndex should not be larger than %d", maxAccountIndex)
	}

	if txInfo.PairIndex < minPairIndex {
		return fmt.Errorf("PairIndex should not be less than %d", minPairIndex)
	}
	if txInfo.PairIndex > maxPairIndex {
		return fmt.Errorf("PairIndex should not be larger than %d", maxPairIndex)
	}

	if txInfo.AssetAId < minAssetId {
		return fmt.Errorf("AssetAId should not be less than %d", minAssetId)
	}
	if txInfo.AssetAId > maxAssetId {
		return fmt.Errorf("AssetAId should not be larger than %d", maxAssetId)
	}

	if txInfo.AssetAAmount == nil {
		return fmt.Errorf("AssetAAmount should not be nil")
	}
	if txInfo.AssetAAmount.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetAAmount should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetAAmount.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetAAmount should not be larger than %s", maxAssetAmount.String())
	}

	if txInfo.AssetBId < minAssetId {
		return fmt.Errorf("AssetBId should not be less than %d", minAssetId)
	}
	if txInfo.AssetBId > maxAssetId {
		return fmt.Errorf("AssetBId should not be larger than %d", maxAssetId)
	}

	if txInfo.AssetBMinAmount == nil {
		return fmt.Errorf("AssetBMinAmount should not be nil")
	}
	if txInfo.AssetBMinAmount.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetBMinAmount should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetBMinAmount.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetBMinAmount should not be larger than %s", maxAssetAmount.String())
	}

	if txInfo.AssetBAmountDelta == nil {
		return fmt.Errorf("AssetBAmountDelta should not be nil")
	}
	if txInfo.AssetBAmountDelta.Cmp(minAssetAmount) < 0 {
		return fmt.Errorf("AssetBAmountDelta should not be less than %s", minAssetAmount.String())
	}
	if txInfo.AssetBAmountDelta.Cmp(maxAssetAmount) > 0 {
		return fmt.Errorf("AssetBAmountDelta should not be larger than %s", maxAssetAmount.String())
	}

	if txInfo.GasAccountIndex < minAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be less than %d", minAccountIndex)
	}
	if txInfo.GasAccountIndex > maxAccountIndex {
		return fmt.Errorf("GasAccountIndex should not be larger than %d", maxAccountIndex)
	}

	if txInfo.GasFeeAssetId < minAssetId {
		return fmt.Errorf("GasFeeAssetId should not be less than %d", minAssetId)
	}
	if txInfo.GasFeeAssetId > maxAssetId {
		return fmt.Errorf("GasFeeAssetId should not be larger than %d", maxAssetId)
	}

	if txInfo.GasFeeAssetAmount == nil {
		return fmt.Errorf("GasFeeAssetAmount should not be nil")
	}
	if txInfo.GasFeeAssetAmount.Cmp(minPackedFeeAmount) < 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be less than %s", minPackedFeeAmount.String())
	}
	if txInfo.GasFeeAssetAmount.Cmp(maxPackedFeeAmount) > 0 {
		return fmt.Errorf("GasFeeAssetAmount should not be larger than %s", maxPackedFeeAmount.String())
	}

	if txInfo.ExpiredAt <= 0 {
		return fmt.Errorf("ExpiredAt should be larger than 0")
	}

	if txInfo.Nonce < minNonce {
		return fmt.Errorf("Nonce should not be less than %d", minNonce)
	}
	return nil
}

func ComputeSwapMsgHash(txInfo *SwapTxInfo, hFunc hash.Hash) (msgHash []byte, err error) {
	hFunc.Reset()
	var buf bytes.Buffer
	packedAAmount, err := ToPackedAmount(txInfo.AssetAAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedBAmount, err := ToPackedAmount(txInfo.AssetBMinAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	packedFee, err := ToPackedFee(txInfo.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ComputeTransferMsgHash] unable to packed amount:", err.Error())
		return nil, err
	}
	WriteInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.PairIndex)
	WriteInt64IntoBuf(&buf, packedAAmount)
	WriteInt64IntoBuf(&buf, packedBAmount)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteInt64IntoBuf(&buf, int64(packedFee))
	WriteInt64IntoBuf(&buf, txInfo.ExpiredAt)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	WriteInt64IntoBuf(&buf, ChainId)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash, nil
}
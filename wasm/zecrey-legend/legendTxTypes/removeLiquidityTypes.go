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

type RemoveLiquiditySegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	PairIndex         int64  `json:"pair_index"`
	AssetAId          int64  `json:"asset_a_id"`
	AssetAMinAmount   string `json:"asset_a_min_amount"`
	AssetBId          int64  `json:"asset_b_id"`
	AssetBMinAmount   string `json:"asset_b_min_amount"`
	LpAmount          string `json:"lp_amount"`
	AssetAAmountDelta string `json:"asset_a_amount_delta"`
	AssetBAmountDelta string `json:"asset_b_amount_delta"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
}

func ConstructRemoveLiquidityTxInfo(sk *PrivateKey, segmentStr string) (txInfo *RemoveLiquidityTxInfo, err error) {
	var segmentFormat *RemoveLiquiditySegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructRemoveLiquidityTxInfo] err info:", err)
		return nil, err
	}
	assetAMinAmount, err := StringToBigInt(segmentFormat.AssetAMinAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetBMinAmount, err := StringToBigInt(segmentFormat.AssetBMinAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	lpAmount, err := StringToBigInt(segmentFormat.LpAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetAAmountDelta, err := StringToBigInt(segmentFormat.AssetAAmountDelta)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetBAmountDelta, err := StringToBigInt(segmentFormat.AssetBAmountDelta)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructBuyNftTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	txInfo = &RemoveLiquidityTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		PairIndex:         segmentFormat.PairIndex,
		AssetAId:          segmentFormat.AssetAId,
		AssetAMinAmount:   assetAMinAmount,
		AssetBId:          segmentFormat.AssetBId,
		AssetBMinAmount:   assetBMinAmount,
		LpAmount:          lpAmount,
		AssetAAmountDelta: assetAAmountDelta,
		AssetBAmountDelta: assetBAmountDelta,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeRemoveLiquidityMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructRemoveLiquidityTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type RemoveLiquidityTxInfo struct {
	FromAccountIndex  int64
	PairIndex         int64
	AssetAId          int64
	AssetAMinAmount   *big.Int
	AssetBId          int64
	AssetBMinAmount   *big.Int
	LpAmount          *big.Int
	AssetAAmountDelta *big.Int
	AssetBAmountDelta *big.Int
	PoolAAmount       *big.Int
	PoolBAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	Nonce             int64
	Sig               []byte
}

func ComputeRemoveLiquidityMsgHash(txInfo *RemoveLiquidityTxInfo, hFunc hash.Hash) (msgHash []byte) {
	/*
		hFunc.Write(
			tx.FromAccountIndex,
			tx.ToAccountIndex,
			tx.AssetAId,
			tx.AssetAMinAmount,
			tx.AssetBId,
			tx.AssetBMinAmount,
			tx.LpAmount,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	hFunc.Reset()
	var buf bytes.Buffer
	WriteInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.PairIndex)
	WriteInt64IntoBuf(&buf, txInfo.AssetAId)
	WriteBigIntIntoBuf(&buf, txInfo.AssetAMinAmount)
	WriteInt64IntoBuf(&buf, txInfo.AssetBId)
	WriteBigIntIntoBuf(&buf, txInfo.AssetBMinAmount)
	WriteBigIntIntoBuf(&buf, txInfo.LpAmount)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteBigIntIntoBuf(&buf, txInfo.GasFeeAssetAmount)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}

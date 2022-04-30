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
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"hash"
	"log"
	"math/big"
)

type AddLiquiditySegmentFormat struct {
	FromAccountIndex  int64  `json:"from_account_index"`
	ToAccountIndex    int64  `json:"to_account_index"`
	PairIndex         int64  `json:"pair_index"`
	AssetAId          int64  `json:"asset_a_id"`
	AssetAAmount      string `json:"asset_a_amount"`
	AssetBId          int64  `json:"asset_b_id"`
	AssetBAmount      string `json:"asset_b_amount"`
	LpAmount          string `json:"lp_amount"`
	PoolAAmount       string `json:"pool_a_amount"`
	PoolBAmount       string `json:"pool_b_amount"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount string `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
}

func ConstructAddLiquidityTxInfo(sk *PrivateKey, segmentStr string) (txInfo *AddLiquidityTxInfo, err error) {
	var segmentFormat *AddLiquiditySegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] err info:", err)
		return nil, err
	}
	// TODO lp amount
	assetAAmount, err := StringToBigInt(segmentFormat.AssetAAmount)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	assetBAmount, err := StringToBigInt(segmentFormat.AssetBAmount)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	gasFeeAmount, err := StringToBigInt(segmentFormat.GasFeeAssetAmount)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to convert string to big int:", err)
		return nil, err
	}
	lpSquare := ffmath.Multiply(assetAAmount, assetBAmount)
	lpAmount := new(big.Int).Sqrt(lpSquare)
	txInfo = &AddLiquidityTxInfo{
		FromAccountIndex:  segmentFormat.FromAccountIndex,
		ToAccountIndex:    segmentFormat.ToAccountIndex,
		PairIndex:         segmentFormat.PairIndex,
		AssetAId:          segmentFormat.AssetAId,
		AssetAAmount:      assetAAmount,
		AssetBId:          segmentFormat.AssetBId,
		AssetBAmount:      assetBAmount,
		LpAmount:          lpAmount,
		PoolAAmount:       ZeroBigInt,
		PoolBAmount:       ZeroBigInt,
		GasAccountIndex:   segmentFormat.GasAccountIndex,
		GasFeeAssetId:     segmentFormat.GasFeeAssetId,
		GasFeeAssetAmount: gasFeeAmount,
		Nonce:             segmentFormat.Nonce,
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeAddLiquidityMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type AddLiquidityTxInfo struct {
	FromAccountIndex  int64
	ToAccountIndex    int64
	PairIndex         int64
	AssetAId          int64
	AssetAAmount      *big.Int
	AssetBId          int64
	AssetBAmount      *big.Int
	LpAmount          *big.Int
	PoolAAmount       *big.Int
	PoolBAmount       *big.Int
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount *big.Int
	Nonce             int64
	Sig               []byte
}

func ComputeAddLiquidityMsgHash(txInfo *AddLiquidityTxInfo, hFunc hash.Hash) (msgHash []byte) {
	/*
		hFunc.Write(
			tx.FromAccountIndex,
			tx.ToAccountIndex,
			tx.PairIndex,
			tx.AssetAId,
			tx.AssetAAmount,
			tx.AssetBId,
			tx.AssetBAmount,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	hFunc.Reset()
	var buf bytes.Buffer
	WriteInt64IntoBuf(&buf, txInfo.FromAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.ToAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.PairIndex)
	WriteInt64IntoBuf(&buf, txInfo.AssetAId)
	WriteBigIntIntoBuf(&buf, txInfo.AssetAAmount)
	WriteInt64IntoBuf(&buf, txInfo.AssetBId)
	WriteBigIntIntoBuf(&buf, txInfo.AssetBAmount)
	WriteInt64IntoBuf(&buf, txInfo.GasAccountIndex)
	WriteInt64IntoBuf(&buf, txInfo.GasFeeAssetId)
	WriteBigIntIntoBuf(&buf, txInfo.GasFeeAssetAmount)
	WriteInt64IntoBuf(&buf, txInfo.Nonce)
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}

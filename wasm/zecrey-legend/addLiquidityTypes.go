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

package zecrey_legend

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
	FromAccountIndex  int64 `json:"from_account_index"`
	ToAccountIndex    int64 `json:"to_account_index"`
	PairIndex         int64 `json:"pair_index"`
	AssetAId          int64 `json:"asset_a_id"`
	AssetAAmount      int64 `json:"asset_a_amount"`
	AssetBId          int64 `json:"asset_b_id"`
	AssetBAmount      int64 `json:"asset_b_amount"`
	LpAmount          int64 `json:"lp_amount"`
	PoolAAmount       int64 `json:"pool_a_amount"`
	PoolBAmount       int64 `json:"pool_b_amount"`
	GasAccountIndex   int64 `json:"gas_account_index"`
	GasFeeAssetId     int64 `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64 `json:"gas_fee_asset_amount"`
	Nonce             int64 `json:"nonce"`
}

func ConstructAddLiquidityTxInfo(sk *PrivateKey, segmentStr string) (txInfo *AddLiquidityTxInfo, err error) {
	var segmentFormat *AddLiquiditySegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructAddLiquidityTxInfo] err info:", err)
		return nil, err
	}
	// TODO lp amount
	lpSquare := ffmath.Multiply(new(big.Int).SetInt64(segmentFormat.AssetAAmount), new(big.Int).SetInt64(segmentFormat.AssetBAmount))
	lpAmount := new(big.Int).Sqrt(lpSquare).Uint64()
	txInfo = &AddLiquidityTxInfo{
		FromAccountIndex:  uint32(segmentFormat.FromAccountIndex),
		ToAccountIndex:    uint32(segmentFormat.ToAccountIndex),
		PairIndex:         uint32(segmentFormat.PairIndex),
		AssetAId:          uint32(segmentFormat.AssetAId),
		AssetAAmount:      uint64(segmentFormat.AssetAAmount),
		AssetBId:          uint32(segmentFormat.AssetBId),
		AssetBAmount:      uint64(segmentFormat.AssetBAmount),
		LpAmount:          lpAmount,
		PoolAAmount:       uint64(segmentFormat.PoolAAmount),
		PoolBAmount:       uint64(segmentFormat.PoolBAmount),
		GasAccountIndex:   uint32(segmentFormat.GasAccountIndex),
		GasFeeAssetId:     uint32(segmentFormat.GasFeeAssetId),
		GasFeeAssetAmount: uint64(segmentFormat.GasFeeAssetAmount),
		Nonce:             uint64(segmentFormat.Nonce),
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
	FromAccountIndex  uint32
	ToAccountIndex    uint32
	PairIndex         uint32
	AssetAId          uint32
	AssetAAmount      uint64
	AssetBId          uint32
	AssetBAmount      uint64
	LpAmount          uint64
	PoolAAmount       uint64
	PoolBAmount       uint64
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	Nonce             uint64
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
	writeUint64IntoBuf(&buf, uint64(txInfo.FromAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.ToAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.PairIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetAId))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetAAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetBId))
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetBAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.Nonce))
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}

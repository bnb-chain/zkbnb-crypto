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
	"hash"
	"log"
)

type SwapSegmentFormat struct {
	FromAccountIndex       int64 `json:"from_account_index"`
	ToAccountIndex         int64 `json:"to_account_index"`
	PairIndex              int64 `json:"pair_index"`
	AssetAId               int64 `json:"asset_a_id"`
	AssetAAmount           int64 `json:"asset_a_amount"`
	AssetBId               int64 `json:"asset_b_id"`
	AssetBMinAmount        int64 `json:"asset_b_min_amount"`
	AssetBAmountDelta      int64 `json:"asset_b_amount_delta"`
	PoolAAmount            int64 `json:"pool_a_amount"`
	PoolBAmount            int64 `json:"pool_b_amount"`
	FeeRate                int64 `json:"fee_rate"`
	TreasuryAccountIndex   int64 `json:"treasury_account_index"`
	TreasuryRate           int64 `json:"treasury_rate"`
	TreasuryFeeAmountDelta int64 `json:"treasury_fee_amount_delta"`
	GasAccountIndex        int64 `json:"gas_account_index"`
	GasFeeAssetId          int64 `json:"gas_fee_asset_id"`
	GasFeeAssetAmount      int64 `json:"gas_fee_asset_amount"`
	Nonce                  int64 `json:"nonce"`
}

func ConstructSwapTxInfo(sk *PrivateKey, segmentStr string) (txInfo *SwapTxInfo, err error) {
	var segmentFormat *SwapSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructSwapTxInfo] err info:", err)
		return nil, err
	}
	txInfo = &SwapTxInfo{
		FromAccountIndex:       uint32(segmentFormat.FromAccountIndex),
		ToAccountIndex:         uint32(segmentFormat.ToAccountIndex),
		PairIndex:              uint32(segmentFormat.PairIndex),
		AssetAId:               uint32(segmentFormat.AssetAId),
		AssetAAmount:           uint64(segmentFormat.AssetAAmount),
		AssetBId:               uint32(segmentFormat.AssetBId),
		AssetBMinAmount:        uint64(segmentFormat.AssetBMinAmount),
		AssetBAmountDelta:      uint64(segmentFormat.AssetBAmountDelta),
		PoolAAmount:            uint64(segmentFormat.PoolAAmount),
		PoolBAmount:            uint64(segmentFormat.PoolBAmount),
		FeeRate:                uint32(segmentFormat.FeeRate),
		TreasuryAccountIndex:   uint32(segmentFormat.TreasuryAccountIndex),
		TreasuryRate:           uint32(segmentFormat.TreasuryRate),
		TreasuryFeeAmountDelta: uint64(segmentFormat.TreasuryFeeAmountDelta),
		GasAccountIndex:        uint32(segmentFormat.GasAccountIndex),
		GasFeeAssetId:          uint32(segmentFormat.GasFeeAssetId),
		GasFeeAssetAmount:      uint64(segmentFormat.GasFeeAssetAmount),
		Nonce:                  uint64(segmentFormat.Nonce),
		Sig:                    nil,
	}
	hFunc := mimc.NewMiMC()
	msgHash := ComputeSwapMsgHash(txInfo, hFunc)
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
	FromAccountIndex       uint32
	ToAccountIndex         uint32
	PairIndex              uint32
	AssetAId               uint32
	AssetAAmount           uint64
	AssetBId               uint32
	AssetBMinAmount        uint64
	AssetBAmountDelta      uint64
	PoolAAmount            uint64
	PoolBAmount            uint64
	FeeRate                uint32
	TreasuryAccountIndex   uint32
	TreasuryRate           uint32
	TreasuryFeeAmountDelta uint64
	GasAccountIndex        uint32
	GasFeeAssetId          uint32
	GasFeeAssetAmount      uint64
	Nonce                  uint64
	Sig                    []byte
}

func ComputeSwapMsgHash(txInfo *SwapTxInfo, hFunc hash.Hash) (msgHash []byte) {
	/*
		hFunc.Write(
			tx.FromAccountIndex,
			tx.ToAccountIndex,
			tx.PairIndex,
			tx.AssetAId,
			tx.AssetAAmount,
			tx.AssetBId,
			tx.AssetBMinAmount,
			tx.FeeRate,
			tx.TreasuryAccountIndex,
			tx.TreasuryRate,
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
	writeUint64IntoBuf(&buf, uint64(txInfo.AssetBMinAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.FeeRate))
	writeUint64IntoBuf(&buf, uint64(txInfo.TreasuryAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.TreasuryRate))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.Nonce))
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}

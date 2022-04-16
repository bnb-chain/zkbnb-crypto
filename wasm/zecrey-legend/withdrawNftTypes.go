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

type WithdrawNftSegmentFormat struct {
	AccountIndex      int64  `json:"account_index"`
	NftIndex          int64  `json:"nft_index"`
	ToAddress         string `json:"to_address"`
	ProxyAddress      string `json:"proxy_address"`
	GasAccountIndex   int64  `json:"gas_account_index"`
	GasFeeAssetId     int64  `json:"gas_fee_asset_id"`
	GasFeeAssetAmount int64  `json:"gas_fee_asset_amount"`
	Nonce             int64  `json:"nonce"`
}

func ConstructWithdrawNftTxInfo(sk *PrivateKey, segmentStr string) (txInfo *WithdrawNftTxInfo, err error) {
	var segmentFormat *WithdrawNftSegmentFormat
	err = json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[ConstructWithdrawNftTxInfo] err info:", err)
		return nil, err
	}
	txInfo = &WithdrawNftTxInfo{
		AccountIndex:      uint32(segmentFormat.AccountIndex),
		NftIndex:          uint32(segmentFormat.NftIndex),
		ToAddress:         segmentFormat.ToAddress,
		ProxyAddress:      segmentFormat.ProxyAddress,
		GasAccountIndex:   uint32(segmentFormat.GasAccountIndex),
		GasFeeAssetId:     uint32(segmentFormat.GasFeeAssetId),
		GasFeeAssetAmount: uint64(segmentFormat.GasFeeAssetAmount),
		Nonce:             uint64(segmentFormat.Nonce),
		Sig:               nil,
	}
	// compute call data hash
	hFunc := mimc.NewMiMC()
	// compute msg hash
	msgHash := ComputeWithdrawNftMsgHash(txInfo, hFunc)
	// compute signature
	hFunc.Reset()
	sigBytes, err := sk.Sign(msgHash, hFunc)
	if err != nil {
		log.Println("[ConstructWithdrawNftTxInfo] unable to sign:", err)
		return nil, err
	}
	txInfo.Sig = sigBytes
	return txInfo, nil
}

type WithdrawNftTxInfo struct {
	AccountIndex      uint32
	NftIndex          uint32
	ToAddress         string
	ProxyAddress      string
	GasAccountIndex   uint32
	GasFeeAssetId     uint32
	GasFeeAssetAmount uint64
	Nonce             uint64
	Sig               []byte
}

func ComputeWithdrawNftMsgHash(txInfo *WithdrawNftTxInfo, hFunc hash.Hash) (msgHash []byte) {
	/*
		hFunc.Write(
			tx.AccountIndex,
			tx.NftIndex,
			tx.ToAddress,
			tx.ProxyAddress,
			tx.GasAccountIndex,
			tx.GasFeeAssetId,
			tx.GasFeeAssetAmount,
		)
		hFunc.Write(nonce)
	*/
	hFunc.Reset()
	var buf bytes.Buffer
	writeUint64IntoBuf(&buf, uint64(txInfo.AccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.NftIndex))
	buf.Write(PaddingStringToBytes32(txInfo.ToAddress))
	buf.Write(PaddingStringToBytes32(txInfo.ProxyAddress))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasAccountIndex))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetId))
	writeUint64IntoBuf(&buf, uint64(txInfo.GasFeeAssetAmount))
	writeUint64IntoBuf(&buf, uint64(txInfo.Nonce))
	hFunc.Write(buf.Bytes())
	msgHash = hFunc.Sum(nil)
	return msgHash
}

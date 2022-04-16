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

package zecrey_zero

import (
	"encoding/json"
	"errors"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
)

/*
	WithdrawNftSegment: which is used to construct withdraw nft proof
*/
type WithdrawNftSegment struct {
	AccountIndex uint32
	Pk           *Point
	Sk           *big.Int
	// common input part
	NftIndex     uint32
	ReceiverAddr string
	ProxyAddr    string
	ChainId      uint32
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

/*
	WithdrawNftSegmentFormat: format version of WithdrawNftSegment
*/
type WithdrawNftSegmentFormat struct {
	// account index
	AccountIndex int `json:"account_index"`
	// public key
	Pk string `json:"pk"`
	// private key
	Sk string `json:"sk"`
	// common input part
	NftIndex     int    `json:"nft_index"`
	ReceiverAddr string `json:"receiver_addr"`
	ProxyAddr    string `json:"proxy_addr"`
	ChainId      int    `json:"chain_id"`
	// fee part
	// encryption of balance of the gas fee asset
	C_fee string `json:"c_fee"`
	// balance of gas fee asset
	B_fee int64 `json:"b_fee"`
	// gas fee asset id
	GasFeeAssetId int `json:"gas_fee_asset_id"`
	// gas fee
	GasFee int64 `json:"gas_fee"`
}

func FromWithdrawNftSegmentJSON(segmentStr string) (*WithdrawNftSegment, string) {
	var segmentFormat *WithdrawNftSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromTransferNftSegmentJSON] err info:", err)
		return nil, ErrUnmarshal
	}
	if segmentFormat.Pk == "" || segmentFormat.Sk == "" {
		log.Println("[FromTransferNftSegmentJSON] invalid params")
		return nil, errors.New("[FromTransferNftSegmentJSON] invalid params").Error()
	}
	// verify params
	if segmentFormat.AccountIndex < 0 || segmentFormat.B_fee < 0 ||
		segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		return nil, errors.New("[FromTransferNftSegmentJSON] invalid params").Error()
	}
	Pk, err := curve.FromString(segmentFormat.Pk)
	if err != nil {
		log.Println("[FromTransferNftSegmentJSON] invalid params")
		return nil, ErrParsePoint
	}
	Sk, isValid := new(big.Int).SetString(segmentFormat.Sk, 10)
	if !isValid {
		log.Println("[FromTransferNftSegmentJSON] invalid params")
		return nil, ErrParseBigInt
	}
	C_fee, err := twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromTransferNftSegmentJSON] invalid params")
		return nil, ErrParseEnc
	}
	segment := &WithdrawNftSegment{
		AccountIndex:  uint32(segmentFormat.AccountIndex),
		Pk:            Pk,
		Sk:            Sk,
		NftIndex:      uint32(segmentFormat.NftIndex),
		ReceiverAddr:  segmentFormat.ReceiverAddr,
		ProxyAddr:     segmentFormat.ProxyAddr,
		ChainId:       uint32(segmentFormat.ChainId),
		C_fee:         C_fee,
		B_fee:         uint64(segmentFormat.B_fee),
		GasFeeAssetId: uint32(segmentFormat.GasFeeAssetId),
		GasFee:        uint64(segmentFormat.GasFee),
	}
	return segment, Success
}

type WithdrawNftTxInfo struct {
	// zecrey-legend index
	AccountIndex uint32
	// common input part
	NftIndex     uint32
	ReceiverAddr string
	ProxyAddr    string
	ChainId      uint32
	// gas fee part
	GasFeeAssetId uint32
	GasFee        uint64
	// mint nft proof
	Proof string
}

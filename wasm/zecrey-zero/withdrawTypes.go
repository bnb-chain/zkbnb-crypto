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
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"log"
	"math/big"
)

/*
	WithdrawSegment: which is used to construct withdraw proof
*/
type WithdrawSegment struct {
	AccountIndex uint32
	C            *ElGamalEnc
	Pk           *Point
	B            uint64
	BStar        uint64
	Sk           *big.Int
	AssetId      uint32
	ChainId      uint8
	ReceiveAddr  string
	// fee part
	C_fee         *ElGamalEnc
	B_fee         uint64
	GasFeeAssetId uint32
	GasFee        uint64
}

/*
	WithdrawSegmentFormat: format version of WithdrawSegment
*/
type WithdrawSegmentFormat struct {
	// account index
	AccountIndex int    `json:"account_index"`
	// encryption of the balance
	C            string `json:"c"`
	// public key
	Pk           string `json:"pk"`
	// balance
	B            int64  `json:"b"`
	// withdraw amount
	BStar        int64  `json:"b_star"`
	// private key
	Sk           string `json:"sk"`
	// asset id
	AssetId      int    `json:"asset_id"`
	// chain id
	ChainId      int    `json:"chain_id"`
	// receive address
	ReceiveAddr  string `json:"receive_addr"`
	// fee part
	// encryption of balance of the gas fee asset
	C_fee         string `json:"c_fee"`
	// balance of gas fee asset
	B_fee         int64  `json:"b_fee"`
	// gas fee asset id
	GasFeeAssetId int    `json:"gas_fee_asset_id"`
	// gas fee
	GasFee        int64  `json:"gas_fee"`
}

func FromWithdrawSegmentJSON(segmentStr string) (*WithdrawSegment, string) {
	var segmentFormat *WithdrawSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &segmentFormat)
	if err != nil {
		log.Println("[FromWithdrawSegmentJSON] err info:", err)
		return nil, ErrUnmarshal
	}
	if segmentFormat.C == "" || segmentFormat.Pk == "" ||
		segmentFormat.Sk == "" {
		log.Println("[FromWithdrawSegmentJSON] invalid params")
		return nil, ErrInvalidWithdrawParams
	}
	// verify params
	if segmentFormat.AccountIndex < 0 || segmentFormat.B < 0 || segmentFormat.BStar < 0 ||
		segmentFormat.AssetId < 0 || segmentFormat.ChainId < 0 || segmentFormat.B_fee < 0 ||
		segmentFormat.GasFeeAssetId < 0 || segmentFormat.GasFee < 0 {
		return nil, ErrInvalidWithdrawParams
	}
	C, err := twistedElgamal.FromString(segmentFormat.C)
	if err != nil {
		log.Println("[FromWithdrawSegmentJSON] invalid params")
		return nil, ErrParseEnc
	}
	Pk, err := curve.FromString(segmentFormat.Pk)
	if err != nil {
		log.Println("[FromWithdrawSegmentJSON] invalid params")
		return nil, ErrParsePoint
	}
	Sk, isValid := new(big.Int).SetString(segmentFormat.Sk, 10)
	if !isValid {
		log.Println("[FromWithdrawSegmentJSON] invalid params")
		return nil, ErrParseBigInt
	}
	C_fee, err := twistedElgamal.FromString(segmentFormat.C_fee)
	if err != nil {
		log.Println("[FromWithdrawSegmentJSON] invalid params")
		return nil, ErrParseEnc
	}
	withdrawSegment := &WithdrawSegment{
		AccountIndex:  uint32(segmentFormat.AccountIndex),
		C:             C,
		Pk:            Pk,
		B:             uint64(segmentFormat.B),
		BStar:         uint64(segmentFormat.BStar),
		Sk:            Sk,
		AssetId:       uint32(segmentFormat.AssetId),
		ChainId:       uint8(segmentFormat.ChainId),
		ReceiveAddr:   segmentFormat.ReceiveAddr,
		C_fee:         C_fee,
		B_fee:         uint64(segmentFormat.B_fee),
		GasFeeAssetId: uint32(segmentFormat.GasFeeAssetId),
		GasFee:        uint64(segmentFormat.GasFee),
	}
	return withdrawSegment, Success
}

type WithdrawTxInfo struct {
	// chain id
	ChainId uint8
	// token id
	AssetId uint32
	// zecrey-legend index
	AccountIndex uint32
	// L1 address
	ReceiveAddr string
	// withdraw amount
	BStar uint64
	// gas fee part
	GasFeeAssetId uint32
	GasFee        uint64
	// withdraw proof
	Proof string
}

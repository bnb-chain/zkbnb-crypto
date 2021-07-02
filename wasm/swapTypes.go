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

package wasm

import (
	"encoding/json"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	SwapSegment: which is used to construct swap proof
*/
type SwapSegment struct {
	EncVal         *ElGamalEnc `json:"enc_val"`
	Pk             *Point      `json:"pk"`
	ReceiverEncVal *ElGamalEnc `json:"receiver_enc_val"`
	ReceiverPk     *Point      `json:"receiver_pk"`
	BStarFrom      *big.Int    `json:"b_star_from"`
	BStarTo        *big.Int    `json:"b_star_to"`
	Sk             *big.Int    `json:"sk"`
}

/*
	SwapSegmentFormat: format version of SwapSegment
*/
type SwapSegmentFormat struct {
	EncVal         string `json:"enc_val"`
	Pk             string `json:"pk"`
	ReceiverEncVal string `json:"receiver_enc_val"`
	ReceiverPk     string `json:"receiver_pk"`
	BStarFrom      int    `json:"b_star_from"`
	BStarTo        int    `json:"b_star_to"`
	Sk             string `json:"sk"`
}

func FromSwapSegmentJSON(segmentStr string) (*SwapSegment, string) {
	var swapSegmentFormat *SwapSegmentFormat
	err := json.Unmarshal([]byte(segmentStr), &swapSegmentFormat)
	if err != nil {
		return nil, ErrUnmarshal
	}
	if swapSegmentFormat.EncVal == "" || swapSegmentFormat.Pk == "" ||
		swapSegmentFormat.BStarFrom <= 0 || swapSegmentFormat.BStarTo <= 0 || swapSegmentFormat.Sk == "" {
		return nil, ErrInvalidSwapParams
	}
	encVal, err := twistedElgamal.FromString(swapSegmentFormat.EncVal)
	if err != nil {
		return nil, ErrParseEnc
	}
	receiverEncVal, err := twistedElgamal.FromString(swapSegmentFormat.ReceiverEncVal)
	if err != nil {
		return nil, ErrParseEnc
	}
	pk, err := curve.FromString(swapSegmentFormat.Pk)
	if err != nil {
		return nil, ErrParsePoint
	}
	receiverPk, err := curve.FromString(swapSegmentFormat.ReceiverPk)
	if err != nil {
		return nil, ErrParsePoint
	}
	bStarFrom := big.NewInt(int64(swapSegmentFormat.BStarFrom))
	bStarTo := big.NewInt(int64(swapSegmentFormat.BStarTo))
	sk, b := new(big.Int).SetString(swapSegmentFormat.Sk, 10)
	if !b {
		return nil, ErrParseBigInt
	}
	swapSegment := &SwapSegment{
		EncVal:         encVal,
		Pk:             pk,
		ReceiverEncVal: receiverEncVal,
		ReceiverPk:     receiverPk,
		BStarFrom:      bStarFrom,
		BStarTo:        bStarTo,
		Sk:             sk,
	}
	return swapSegment, Success
}

type SwapTransactionAo struct {
	// token id
	TokenIdFrom uint32
	TokenIdTo   uint32
	// L2 address
	L2Address string
	// withdraw amount
	BStarFrom *big.Int
	BStarTo   *big.Int
	// withdraw proof
	Proof *zecrey.SwapProofPart
	// create time
	CreateAt int64
}

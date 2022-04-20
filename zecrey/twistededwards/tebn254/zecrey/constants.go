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

package zecrey

import (
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
	"math/big"
)

type (
	ElGamalEnc = twistedElgamal.ElGamalEnc
	Point      = curve.Point
	RangeProof = ctrange.RangeProof
)

const (
	RangeMaxBits          = ctrange.RangeMaxBits // max bits
	PointSize             = curve.PointSize
	ElGamalEncSize        = PointSize * 2
	RangeProofSize        = ctrange.RangeProofSize
	WithdrawProofSize     = 14*PointSize + 2*RangeProofSize + 2*EightBytes + AddressSize + 3*FourBytes
	OneMillion            = 1000000
	TenThousand           = 10000
	MaxFeeRate            = 40
	MinFee                = 1
	OneByte               = 1
	FourBytes             = 4
	EightBytes            = 8
	TransferSubProofCount = 3
	TransferSubProofSize  = 24*PointSize + RangeProofSize
	TransferProofSize     = TransferSubProofCount*TransferSubProofSize + 4*PointSize + 1*EightBytes + 1*FourBytes

	// NFT related
	MintNftProofSize     = 8*PointSize + 1*ElGamalEncSize + 1*RangeProofSize + 2*EightBytes + 4*FourBytes
	TransferNftProofSize = 8*PointSize + 1*ElGamalEncSize + 1*RangeProofSize + 2*EightBytes + 4*FourBytes
	SetNftPriceProofSize = 8*PointSize + 1*ElGamalEncSize + 1*RangeProofSize + 3*EightBytes + 4*FourBytes
	BuyNftProofSize      = 15*PointSize + 2*RangeProofSize + 3*EightBytes + 4*FourBytes
	WithdrawNftProofSize = 9*PointSize + 1*ElGamalEncSize + 1*AddressSize + 1*RangeProofSize + 2*EightBytes + 4*FourBytes

	SwapProofSize            = 32*PointSize + 2*RangeProofSize + 10*EightBytes + 4*FourBytes
	AddLiquidityProofSize    = 35*PointSize + 6*EightBytes + 3*FourBytes + 3*RangeProofSize
	RemoveLiquidityProofSize = 36*PointSize + 9*EightBytes + 3*FourBytes + 2*RangeProofSize
	UnlockProofSize          = 9*PointSize + 3*FourBytes + 3*EightBytes + 1*RangeProofSize

	AddressSize = 20

	ErrCode = -1
)

var (
	G           = curve.G
	H           = curve.H
	Order       = curve.Order
	MaxRange    = int64(1099511627775) // 2^{40} - 1
	MaxRangeNeg = int64(-1099511627776)
	curveId     = "ZecreyBN254"
	FixedCurve  = new(big.Int).SetBytes([]byte(curveId))
)

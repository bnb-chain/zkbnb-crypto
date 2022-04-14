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

package ctrange

import (
	"encoding/base64"
	"errors"
	"math/big"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
)

type RangeProof struct {
	// challenge
	C *big.Int
	// special commitment for each bit
	As [RangeMaxBits]*Point
	Zs [RangeMaxBits]*big.Int
	// commitment for b
	A    *Point
	G, H *Point
}

func (proof *RangeProof) Bytes() []byte {
	res := make([]byte, RangeProofSize)
	copy(res[:PointSize], proof.A.Marshal())
	copy(res[PointSize:PointSize*2], proof.G.Marshal())
	copy(res[PointSize*2:PointSize*3], proof.H.Marshal())
	copy(res[PointSize*3:PointSize*4], proof.C.FillBytes(make([]byte, PointSize)))
	for i := 0; i < RangeMaxBits; i++ {
		copy(res[PointSize*4+i*2*PointSize:PointSize*4+i*2*PointSize+PointSize], proof.As[i].Marshal())
		copy(res[PointSize*4+i*2*PointSize+PointSize:PointSize*4+i*2*PointSize+PointSize*2], proof.Zs[i].FillBytes(make([]byte, PointSize)))
	}
	return res
}

func (proof *RangeProof) String() string {
	proofBytes := proof.Bytes()
	return base64.StdEncoding.EncodeToString(proofBytes)
}

func FromBytes(proofBytes []byte) (*RangeProof, error) {
	if len(proofBytes) != RangeProofSize {
		return nil, errors.New("[ctrange FromBytes] err: invalid size")
	}
	var (
		err error
	)
	proof := new(RangeProof)
	proof.A, err = curve.FromBytes(proofBytes[:PointSize])
	if err != nil {
		return nil, err
	}
	proof.G, err = curve.FromBytes(proofBytes[PointSize : PointSize*2])
	if err != nil {
		return nil, err
	}
	proof.H, err = curve.FromBytes(proofBytes[PointSize*2 : PointSize*3])
	if err != nil {
		return nil, err
	}
	proof.C = new(big.Int).SetBytes(proofBytes[PointSize*3 : PointSize*4])
	for i := 0; i < RangeMaxBits; i++ {
		proof.As[i], err = curve.FromBytes(proofBytes[PointSize*4+i*2*PointSize : PointSize*4+i*2*PointSize+PointSize])
		if err != nil {
			return nil, err
		}
		proof.Zs[i] = new(big.Int).SetBytes(proofBytes[PointSize*4+i*2*PointSize+PointSize : PointSize*4+i*2*PointSize+PointSize*2])
	}
	return proof, nil
}

func FromString(proofStr string) (*RangeProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return FromBytes(proofBytes)
}

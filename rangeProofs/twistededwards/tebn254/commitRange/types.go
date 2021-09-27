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

package commitRange

import (
	"encoding/base64"
	"math/big"
)

type ComRangeProof struct {
	// 0 or 2^i commitment proof
	Cas, Cbs [RangeMaxBits]*Point
	Zas, Zbs [RangeMaxBits]*big.Int
	// A_A
	A_A *Point
	// Z_{\alpha_{r}}
	Z_alpha_r, Z_alpha_b *big.Int
	// Z_{\alpha_{b}}
	// public statements
	T, G, H *Point
	// commitment to each bit
	As     [RangeMaxBits]*Point
	C1, C2 *big.Int
}

const size = PointSize * 5

// serialize methods

func (proof *ComRangeProof) Bytes() []byte {
	res := make([]byte, RangeProofSize)
	for i := 0; i < RangeMaxBits; i++ {
		copy(res[i*size:i*size+PointSize], proof.Cas[i].Marshal())
		copy(res[i*size+PointSize:i*size+PointSize*2], proof.Cbs[i].Marshal())
		copy(res[i*size+PointSize*2:i*size+PointSize*3], proof.Zas[i].FillBytes(make([]byte, PointSize)))
		copy(res[i*size+PointSize*3:i*size+PointSize*4], proof.Zbs[i].FillBytes(make([]byte, PointSize)))
		copy(res[i*size+PointSize*4:i*size+PointSize*5], proof.As[i].Marshal())
	}
	copy(res[size*RangeMaxBits:size*RangeMaxBits+PointSize], proof.T.Marshal())
	copy(res[size*RangeMaxBits+PointSize*1:size*RangeMaxBits+PointSize*2], proof.G.Marshal())
	copy(res[size*RangeMaxBits+PointSize*2:size*RangeMaxBits+PointSize*3], proof.H.Marshal())
	copy(res[size*RangeMaxBits+PointSize*3:size*RangeMaxBits+PointSize*4], proof.C1.FillBytes(make([]byte, PointSize)))
	copy(res[size*RangeMaxBits+PointSize*4:size*RangeMaxBits+PointSize*5], proof.C2.FillBytes(make([]byte, PointSize)))
	copy(res[size*RangeMaxBits+PointSize*5:size*RangeMaxBits+PointSize*6], proof.A_A.Marshal())
	copy(res[size*RangeMaxBits+PointSize*6:size*RangeMaxBits+PointSize*7], proof.Z_alpha_r.FillBytes(make([]byte, PointSize)))
	copy(res[size*RangeMaxBits+PointSize*7:size*RangeMaxBits+PointSize*8], proof.Z_alpha_b.FillBytes(make([]byte, PointSize)))
	return res
}

func (proof *ComRangeProof) String() string {
	return base64.StdEncoding.EncodeToString(proof.Bytes())
}

func FromString(proofStr string) (*ComRangeProof, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(proofStr)
	if err != nil {
		return nil, err
	}
	return FromBytes(proofBytes)
}

func FromBytes(proofBytes []byte) (*ComRangeProof, error) {
	if len(proofBytes) != RangeProofSize {
		return nil, ErrInvalidProofSize
	}
	proof := new(ComRangeProof)
	for i := 0; i < RangeMaxBits; i++ {
		proof.Cas[i] = new(Point)
		proof.Cbs[i] = new(Point)
		proof.Zas[i] = new(big.Int)
		proof.Zbs[i] = new(big.Int)
		proof.As[i] = new(Point)
		readSize, err := proof.Cas[i].SetBytes(proofBytes[i*size : i*size+PointSize])
		if err != nil {
			return nil, err
		}
		if readSize != PointSize {
			return nil, ErrInvalidPointBytes
		}
		readSize, err = proof.Cbs[i].SetBytes(proofBytes[i*size+PointSize : i*size+PointSize*2])
		if err != nil {
			return nil, err
		}
		if readSize != PointSize {
			return nil, ErrInvalidPointBytes
		}
		proof.Zas[i].SetBytes(proofBytes[i*size+PointSize*2 : i*size+PointSize*3])
		proof.Zbs[i].SetBytes(proofBytes[i*size+PointSize*3 : i*size+PointSize*4])
		readSize, err = proof.As[i].SetBytes(proofBytes[i*size+PointSize*4 : i*size+PointSize*5])
		if err != nil {
			return nil, err
		}
		if readSize != PointSize {
			return nil, ErrInvalidPointBytes
		}
	}
	proof.T = new(Point)
	proof.G = new(Point)
	proof.H = new(Point)
	proof.C1 = new(big.Int)
	proof.C2 = new(big.Int)
	proof.A_A = new(Point)
	proof.Z_alpha_r = new(big.Int)
	proof.Z_alpha_b = new(big.Int)
	readSize, err := proof.T.SetBytes(proofBytes[size*RangeMaxBits : size*RangeMaxBits+PointSize])
	if err != nil {
		return nil, err
	}
	if readSize != PointSize {
		return nil, ErrInvalidPointBytes
	}
	readSize, err = proof.G.SetBytes(proofBytes[size*RangeMaxBits+PointSize*1 : size*RangeMaxBits+PointSize*2])
	if err != nil {
		return nil, err
	}
	if readSize != PointSize {
		return nil, ErrInvalidPointBytes
	}
	readSize, err = proof.H.SetBytes(proofBytes[size*RangeMaxBits+PointSize*2 : size*RangeMaxBits+PointSize*3])
	if err != nil {
		return nil, err
	}
	if readSize != PointSize {
		return nil, ErrInvalidPointBytes
	}
	proof.C1.SetBytes(proofBytes[size*RangeMaxBits+PointSize*3 : size*RangeMaxBits+PointSize*4])
	proof.C2.SetBytes(proofBytes[size*RangeMaxBits+PointSize*4 : size*RangeMaxBits+PointSize*5])
	readSize, err = proof.A_A.SetBytes(proofBytes[size*RangeMaxBits+PointSize*5 : size*RangeMaxBits+PointSize*6])
	if err != nil {
		return nil, err
	}
	if readSize != PointSize {
		return nil, ErrInvalidPointBytes
	}
	proof.Z_alpha_r.SetBytes(proofBytes[size*RangeMaxBits+PointSize*6 : size*RangeMaxBits+PointSize*7])
	proof.Z_alpha_b.SetBytes(proofBytes[size*RangeMaxBits+PointSize*7 : size*RangeMaxBits+PointSize*8])
	return proof, nil
}

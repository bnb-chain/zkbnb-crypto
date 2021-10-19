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
	"bytes"
	"log"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func notNullElGamal(C *ElGamalEnc) bool {
	return C != nil && C.CL != nil && C.CR != nil
}

func writePointIntoBuf(buf *bytes.Buffer, p *Point) {
	buf.Write(p.X.Marshal())
	buf.Write(p.Y.Marshal())
}

func writeEncIntoBuf(buf *bytes.Buffer, enc *ElGamalEnc) {
	writePointIntoBuf(buf, enc.CL)
	writePointIntoBuf(buf, enc.CR)
}

func writeUint64IntoBuf(buf *bytes.Buffer, a uint64) {
	buf.Write(new(big.Int).SetUint64(a).FillBytes(make([]byte, PointSize)))
}

func equalEnc(a, b *ElGamalEnc) bool {
	return a.CL.Equal(b.CL) && a.CR.Equal(b.CR)
}

func negElgamal(enc *ElGamalEnc) *ElGamalEnc {
	return &ElGamalEnc{
		CL: curve.Neg(enc.CL),
		CR: curve.Neg(enc.CR),
	}
}

func printElgamal(enc *ElGamalEnc) {
	log.Println(enc.CL.X.String())
	log.Println(enc.CL.Y.String())
	log.Println(enc.CR.X.String())
	log.Println(enc.CR.Y.String())
}

func PaddingBigIntBytes(a *big.Int) []byte {
	return a.FillBytes(make([]byte, PointSize))
}

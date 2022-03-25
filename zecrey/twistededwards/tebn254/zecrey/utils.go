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
	"encoding/binary"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/rangeProofs/twistededwards/tebn254/ctrange"
	"log"
	"math/big"
)

func zeroElGamal() *ElGamalEnc {
	return &ElGamalEnc{CL: curve.ZeroPoint(), CR: curve.ZeroPoint()}
}

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

func printPoint(a *Point) {
	log.Println(a.X.String())
	log.Println(a.Y.String())
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

func elgamalToBytes(enc *ElGamalEnc) []byte {
	buf := enc.Bytes()
	return buf[:]
}

func uint64ToBytes(a uint64) []byte {
	buf := make([]byte, EightBytes)
	binary.BigEndian.PutUint64(buf, a)
	return buf
}

func uint32ToBytes(a uint32) []byte {
	buf := make([]byte, FourBytes)
	binary.BigEndian.PutUint32(buf, a)
	return buf
}

func copyBuf(buf *[]byte, offset int, size int, data []byte) (newOffset int) {
	copy((*buf)[offset:offset+size], data)
	newOffset = offset + size
	return newOffset
}

func readPointFromBuf(buf []byte, offset int) (newOffset int, p *Point, err error) {
	newOffset = offset + PointSize
	p, err = curve.FromBytes(buf[offset : offset+PointSize])
	return newOffset, p, err
}

func readTxTypeFromBuf(buf []byte, offset int) (newOffset int, txType uint8) {
	newOffset = offset + OneByte
	txType = buf[offset]
	return newOffset, txType
}

func readHashFromBuf(buf []byte, offset int) (newOffset int, hashVal []byte) {
	newOffset = offset + PointSize
	hashVal = make([]byte, PointSize)
	copy(hashVal[:], buf[offset:newOffset])
	return newOffset, hashVal
}

func readBigIntFromBuf(buf []byte, offset int) (newOffset int, a *big.Int) {
	newOffset = offset + PointSize
	a = new(big.Int).SetBytes(buf[offset : offset+PointSize])
	return newOffset, a
}

func readElGamalEncFromBuf(buf []byte, offset int) (newOffset int, enc *ElGamalEnc, err error) {
	newOffset = offset + ElGamalEncSize
	enc, err = twistedElgamal.FromBytes(buf[offset : offset+ElGamalEncSize])
	return newOffset, enc, err
}

func readTransferSubProofFromBuf(buf []byte, offset int) (newOffset int, proof *TransferSubProof, err error) {
	newOffset = offset + TransferSubProofSize
	proof, err = ParseTransferSubProofBytes(buf[offset : offset+TransferSubProofSize])
	return newOffset, proof, err
}

func readRangeProofFromBuf(buf []byte, offset int) (newOffset int, proof *RangeProof, err error) {
	newOffset = offset + RangeProofSize
	proof, err = ctrange.FromBytes(buf[offset : offset+RangeProofSize])
	return newOffset, proof, err
}

func readUint64FromBuf(buf []byte, offset int) (newOffset int, a uint64) {
	newOffset = offset + EightBytes
	return newOffset, binary.BigEndian.Uint64(buf[offset : offset+EightBytes])
}

func readUint32FromBuf(buf []byte, offset int) (newOffset int, a uint32) {
	newOffset = offset + FourBytes
	return newOffset, binary.BigEndian.Uint32(buf[offset : offset+FourBytes])
}

func readAddressFromBuf(buf []byte, offset int) (newOffset int, a *big.Int) {
	newOffset = offset + AddressSize
	a = new(big.Int).SetBytes(buf[offset : offset+AddressSize])
	return newOffset, a
}

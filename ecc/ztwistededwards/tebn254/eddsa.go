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

package tebn254

import (
	"bytes"
	"crypto/subtle"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"golang.org/x/crypto/blake2b"
	"math/big"
)

/*
	GenerateEddsaPrivateKey: generate eddsa private key
*/
func GenerateEddsaPrivateKey(seed string) (sk *PrivateKey, err error) {
	buf := make([]byte, 32)
	copy(buf, seed)
	reader := bytes.NewReader(buf)
	sk, err = GenerateKey(reader)

	return sk, err

}

const (
	sizeFr = fr.Bytes
)

func GenerateKey(r io.Reader) (*PrivateKey, error) {

	c := twistededwards.GetEdwardsCurve()

	var (
		randSrc [32]byte
		scalar  [32]byte
		pub     PublicKey
	)

	// hash(h) = private_key || random_source, on 32 bytes each
	seed := make([]byte, 32)
	_, err := r.Read(seed)
	if err != nil {
		return nil, err
	}
	h := blake2b.Sum512(seed[:])
	for i := 0; i < 32; i++ {
		randSrc[i] = h[i+32]
	}

	// prune the key
	// https://tools.ietf.org/html/rfc8032#section-5.1.5, key generation

	h[0] &= 0xF8
	h[31] &= 0x7F
	h[31] |= 0x40

	/*
		0xFC = 1111 1100
		convert 256 bits to 254 bits supporting bn254 curve
	*/
	h[31] &= 0xFC

	// reverse first bytes because setBytes interpret stream as big endian
	// but in eddsa specs s is the first 32 bytes in little endian
	for i, j := 0, sizeFr-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}

	copy(scalar[:], h[:sizeFr])

	var bscalar big.Int
	bscalar.SetBytes(scalar[:])
	pub.A.ScalarMul(&c.Base, &bscalar)

	var res [sizeFr * 3]byte
	pubkBin := pub.A.Bytes()
	subtle.ConstantTimeCopy(1, res[:sizeFr], pubkBin[:])
	subtle.ConstantTimeCopy(1, res[sizeFr:2*sizeFr], scalar[:])
	subtle.ConstantTimeCopy(1, res[2*sizeFr:], randSrc[:])

	var pk = &PrivateKey{}
	// make sure pk is not nil

	_, err = pk.SetBytes(res[:])

	return pk, err
}

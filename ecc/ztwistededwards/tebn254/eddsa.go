/*
 * Copyright © 2022 ZkBNB Protocol
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
	"crypto/sha256"
	"encoding/hex"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

/*
GenerateEddsaPrivateKey: generate eddsa private key
*/
func GenerateEddsaPrivateKey(seed string) (sk *PrivateKey, err error) {
	buf, err := hex.DecodeString(seed)
	if err != nil {
		return nil, err
	}
	// calc hash by using sha256 to not lose seed data
	hash := sha256.Sum256(buf)
	reader := bytes.NewReader(hash[:])
	sk, err = eddsa.GenerateKey(reader)
	return sk, err
}

const (
	sizeFr = fr.Bytes
)


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
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

/*
	GenerateEddsaPrivateKey: generate eddsa private key
*/
func GenerateEddsaPrivateKey(seed string) (sk *PrivateKey, err error) {
	buf := make([]byte, 32)
	copy(buf, seed)
	reader := bytes.NewReader(buf)
	sk, err = eddsa.GenerateKey(reader)
	return sk, err
}

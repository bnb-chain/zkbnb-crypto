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
	"errors"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"math/big"
)

/*
	GetL2PublicKey: help the user generates the public key
*/
func GetL2PublicKey(skStr string) (pkStr string, err error) {
	sk, b := new(big.Int).SetString(skStr, 10)
	if !b {
		return "", errors.New("[GetL2PublicKey] invalid private key, should be big integer")
	}
	// pk = g^{Sk}
	pk := curve.ScalarBaseMul(sk)
	return curve.ToString(pk), nil
}

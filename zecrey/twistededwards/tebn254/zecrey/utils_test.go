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
	"fmt"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"log"
	"math/big"
	"testing"
)

func TestCopyBuf(t *testing.T) {
	buf := make([]byte, PointSize)
	copyBuf(&buf, 0, PointSize, curve.ZeroPoint().Marshal())
	fmt.Println(buf)

	sk, _ := new(big.Int).SetString("1145579467787228778633768930478674647292872939759547285137310086581633142460", 10)
	log.Println(curve.ToString(curve.ScalarBaseMul(sk)))
}

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

package test

import (
	"encoding/json"
	"fmt"
	"github.com/bnb-chain/zkbas-crypto/wasm/zero/src"
	"testing"
)

func TestFromWithdrawSegmentJSON(t *testing.T) {
	segment := &src.WithdrawSegmentFormat{
		AccountIndex:  1,
		C:             "m3jEfxmLrL9xXmr8hRjw2ddRuS9LD+ylbdr3w0JMuRZMdG3aiLo+hfDOezMSeXXiw+Jk2U/967RLC99qhgBTqA==",
		Pk:            "fhtYaJmDcV93EuGRJUkiPQkgk+dr4mLKFdayOsiPKZo=",
		B:             8,
		BStar:         2,
		Sk:            "1534761834718427049701159954173450085001264109697049531015992277578747248868",
		AssetId:       1,
		ChainId:       1,
		ReceiveAddr:   "0xE9b15a2D396B349ABF60e53ec66Bcf9af262D449",
		C_fee:         "m3jEfxmLrL9xXmr8hRjw2ddRuS9LD+ylbdr3w0JMuRbKvX/UaPrH9qMqHt7ddc//CQC7tdM9W7Cu1gPoFVpZKQ==",
		B_fee:         10,
		GasFeeAssetId: 2,
		GasFee:        1,
	}
	fmt.Println(json.Marshal(segment))
}

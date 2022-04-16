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

package zecrey_legend

import (
	"encoding/json"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"log"
	"syscall/js"
)

func RemoveLiquidityTx() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "invalid swap params"
		}
		seed := args[0].String()
		segmentStr := args[1].String()
		sk, err := curve.GenerateEddsaPrivateKey(seed)
		if err != nil {
			return err.Error()
		}
		txInfo, err := ConstructRemoveLiquidityTxInfo(sk, segmentStr)
		if err != nil {
			log.Println("[RemoveLiquidityTx] unable to construct generic transfer:", err)
			return err.Error()
		}
		txInfoBytes, err := json.Marshal(txInfo)
		if err != nil {
			log.Println("[RemoveLiquidityTx] unable to marshal:", err)
			return err.Error()
		}
		return string(txInfoBytes)
	})
	return helperFunc
}


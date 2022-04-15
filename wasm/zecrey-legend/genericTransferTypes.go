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
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"syscall/js"
)

func GenericTransfer() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return "invalid generic transfer params"
		}
		seed := args[0].String()
		txInfo := args[1].String()
		sk, err := curve.GenerateEddsaPrivateKey(seed)
		if err != nil {
			return err.Error()
		}
		signature, err := sk.Sign([]byte(txInfo), mimc.NewMiMC())
		if err != nil {
			return err.Error()
		}
		return hex.EncodeToString(signature)
	})
	return helperFunc
}

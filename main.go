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

package main

import (
	"fmt"
	"syscall/js"
	"zecrey-crypto/wasm"
)

func main() {
	fmt.Println("Zecrey Assembly")
	js.Global().Set("getL2PublicKey", wasm.GetL2PublicKey())
	js.Global().Set("elgamalEnc", wasm.ElgamalEnc())
	js.Global().Set("elgamalDec", wasm.ElgamalDec())
	js.Global().Set("proveWithdraw", wasm.ProveWithdraw())
	js.Global().Set("proveTransfer", wasm.ProveTransfer())
	js.Global().Set("proveSwap", wasm.ProveSwap())
	<-make(chan bool)
}

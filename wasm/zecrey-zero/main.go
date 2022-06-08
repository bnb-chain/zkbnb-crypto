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
	"github.com/zecrey-labs/zecrey-crypto/wasm/zecrey-zero"
	"syscall/js"
)

/*
	zecrey-zero wasm libraries
*/
func main() {
	fmt.Println("Zecrey-zero Crypto Assembly")
	js.Global().Set("getL2PublicKey", zecrey_zero.GetL2PublicKey())
	js.Global().Set("elgamalEnc", zecrey_zero.ElgamalEnc())
	js.Global().Set("elgamalDec", zecrey_zero.ElgamalDec())
	js.Global().Set("elgamalRawDec", zecrey_zero.ElgamalRawDec())
	js.Global().Set("proveWithdraw", zecrey_zero.ProveWithdraw())
	js.Global().Set("proveUnlock", zecrey_zero.ProveUnlock())
	js.Global().Set("proveTransfer", zecrey_zero.ProveTransfer())
	js.Global().Set("proveSwap", zecrey_zero.ProveSwap())
	js.Global().Set("proveAddLiquidity", zecrey_zero.ProveAddLiquidity())
	js.Global().Set("proveRemoveLiquidity", zecrey_zero.ProveRemoveLiquidity())
	js.Global().Set("proveMintNft", zecrey_zero.ProveMintNft())
	js.Global().Set("proveTransferNft", zecrey_zero.ProveTransferNft())
	js.Global().Set("proveSetNftPrice", zecrey_zero.ProveSetNftPrice())
	js.Global().Set("proveBuyNft", zecrey_zero.ProveBuyNft())
	js.Global().Set("proveWithdrawNft", zecrey_zero.ProveWithdrawNft())
	<-make(chan bool)
}

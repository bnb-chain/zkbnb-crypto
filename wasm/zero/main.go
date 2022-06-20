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
	"github.com/bnb-chain/zkbas-crypto/wasm/zero/src"
	"syscall/js"
)

/*
	zecrey-zero wasm libraries
*/
func main() {
	fmt.Println("Zecrey-zero Crypto Assembly")
	js.Global().Set("getL2PublicKey", src.GetL2PublicKey())
	js.Global().Set("elgamalEnc", src.ElgamalEnc())
	js.Global().Set("elgamalDec", src.ElgamalDec())
	js.Global().Set("elgamalRawDec", src.ElgamalRawDec())
	js.Global().Set("proveWithdraw", src.ProveWithdraw())
	js.Global().Set("proveUnlock", src.ProveUnlock())
	js.Global().Set("proveTransfer", src.ProveTransfer())
	js.Global().Set("proveSwap", src.ProveSwap())
	js.Global().Set("proveAddLiquidity", src.ProveAddLiquidity())
	js.Global().Set("proveRemoveLiquidity", src.ProveRemoveLiquidity())
	js.Global().Set("proveMintNft", src.ProveMintNft())
	js.Global().Set("proveTransferNft", src.ProveTransferNft())
	js.Global().Set("proveSetNftPrice", src.ProveSetNftPrice())
	js.Global().Set("proveBuyNft", src.ProveBuyNft())
	js.Global().Set("proveWithdrawNft", src.ProveWithdrawNft())
	<-make(chan bool)
}

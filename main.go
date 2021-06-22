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
	<-make(chan bool)
}

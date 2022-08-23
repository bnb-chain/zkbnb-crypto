package keccak

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/abi"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/eip712"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	abiEth "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var nameToCircuitValidation map[string]func(*testing.T, []byte)
var namesOfCircuit []string
var TestPkHex = "048318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"

func callEthSignLocal(arg string) ([]byte, error) {
	cmd := "node"
	args := []string{"./ethers-sign.js", arg}
	process := exec.Command(cmd, args...)
	stdin, err := process.StdinPipe()
	if err != nil {
		fmt.Println(err)
	}
	defer stdin.Close()
	buf := new(bytes.Buffer) // THIS STORES THE NODEJS OUTPUT
	process.Stdout = buf
	process.Stderr = os.Stderr

	if err = process.Start(); err != nil {
		return nil, err
	}

	process.Wait()
	pure := buf.String()[2:]
	pure = pure[:len(pure)-1]

	bs, err := hex.DecodeString(pure)

	if err != nil {
		return nil, err
	}
	return bs, nil
}

func TestUnittest(t *testing.T) {
	nameToCircuitValidation = make(map[string]func(*testing.T, []byte))
	nameToCircuitValidation["Transfer"] = RunTransfer
	nameToCircuitValidation["Withdraw"] = RunWithdraw
	nameToCircuitValidation["AddLiquidity"] = RunAddLiquidity
	nameToCircuitValidation["RemoveLiquidity"] = RunRemoveLiquidity
	nameToCircuitValidation["Swap"] = RunSwap
	nameToCircuitValidation["CreateCollection"] = RunCreateCollection
	nameToCircuitValidation["TransferNft"] = RunTransferNft
	nameToCircuitValidation["WithdrawNft"] = RunWithdrawNft
	nameToCircuitValidation["MintNft"] = RunMintNft
	nameToCircuitValidation["CancelOffer"] = RunCancelOffer
	nameToCircuitValidation["AtomicMatch"] = RunAtomicMatch
	namesOfCircuit = []string{
		abi.Transfer, abi.Withdraw, abi.AddLiquidity, abi.RemoveLiquidity, abi.Swap,
		abi.CreateCollection, abi.TransferNft, abi.WithdrawNft, abi.MintNft, abi.CancelOffer,
		abi.AtomicMatch}
	for _, name := range namesOfCircuit {
		bs, err := callEthSignLocal(name)
		if err != nil {
			t.Error(err.Error())
			t.FailNow()
		}
		nameToCircuitValidation[name](t, bs)
	}
}

func DefaultCircuit() (circuit eip712.Eip712Circuit) {
	circuit.AbiId = 0
	circuit.Values = make([]frontend.Variable, 255)
	circuit.Keccaa256Hash = make([]frontend.Variable, 32)
	circuit.SIG = make([]frontend.Variable, 65)
	circuit.PK = make([]frontend.Variable, 65)
	for i := 0; i < len(circuit.Values); i++ {
		circuit.Values[i] = 0
	}
	for i := 0; i < len(circuit.Keccaa256Hash); i++ {
		circuit.Keccaa256Hash[i] = 0
	}
	circuit.Name = 1
	return circuit
}

func fillCircuitHashAndPK(t *testing.T, w *eip712.Eip712Circuit, inner []byte, bs []byte, hexPrefix string) {
	innerKeccak := crypto.Keccak256(inner)
	prefixBytes, err := hex.DecodeString(hexPrefix)
	assert.NoError(t, err)
	outerBytes := append(prefixBytes, innerKeccak...)
	outerBytesKeccak := crypto.Keccak256(outerBytes)
	for i := 0; i < 32; i++ {
		w.Keccaa256Hash[i] = outerBytesKeccak[i]
	}
	bs[64] -= 27

	w.SIG = make([]frontend.Variable, 65)
	for i := 0; i < len(bs); i++ {
		w.SIG[i] = bs[i]
	}

	w.SIG = make([]frontend.Variable, 65)
	for i := 0; i < len(bs); i++ {
		w.SIG[i] = bs[i]
	}

	pkBytes, err := hex.DecodeString(TestPkHex)
	assert.NoError(t, err)

	w.PK = make([]frontend.Variable, 65)
	for i := 0; i < len(w.PK); i++ {
		w.PK[i] = pkBytes[i]
	}

	w.Name = 1
}

func RunTransfer(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.TransferAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	bytesFirst := [32]byte{'0'}
	wrappedFirst := abi.WrapToAbiBytes32(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	w.Values[34] = uint16(1)
	w.Values[35] = uint64(1)
	w.Values[36] = uint32(1)
	w.Values[37] = uint16(1)
	w.Values[38] = uint16(1)

	bytesLast := [32]byte{'0'}
	wrappedLast := abi.WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[39+i] = wrappedLast[i]
	}

	w.Values[71] = uint64(1)
	w.Values[72] = uint32(1)
	w.Values[73] = uint32(1)

	abiTransfer, err := abiEth.JSON(strings.NewReader(abi.TransferABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.Transfer)

	inner, err := abiTransfer.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint32), bytesFirst, w.Values[34].(uint16), new(big.Int).SetUint64(w.Values[35].(uint64)), w.Values[36].(uint32), w.Values[37].(uint16), w.Values[38].(uint16), bytesLast, w.Values[71].(uint64), w.Values[72].(uint32), w.Values[73].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, inner, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunWithdraw(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.WithdrawAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)

	bytesFirst := [16]byte{'0'}
	wrappedFirst := abi.WrapToAbiBytes16(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	w.Values[18] = uint32(1)
	w.Values[19] = uint16(1)
	w.Values[20] = uint16(1)

	bytesLast := [20]byte{'0'}
	wrappedLast := abi.WrapToAbiBytes20(bytesLast)
	for i := range wrappedLast {
		w.Values[21+i] = wrappedLast[i]
	}

	w.Values[41] = uint64(1)
	w.Values[42] = uint32(1)
	w.Values[43] = uint32(1)

	abiWithdraw, err := abiEth.JSON(strings.NewReader(abi.WithdrawABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.Withdraw)

	b, err := abiWithdraw.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint16), bytesFirst, w.Values[18].(uint32), w.Values[19].(uint16), w.Values[20].(uint16), bytesLast, w.Values[41].(uint64), w.Values[42].(uint32), w.Values[43].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunAddLiquidity(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.AddLiquidityAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)
	w.Values[2] = uint64(1)
	w.Values[3] = uint64(1)
	w.Values[4] = uint32(1)
	w.Values[5] = uint16(1)
	w.Values[6] = uint16(1)
	w.Values[7] = uint64(1)
	w.Values[8] = uint32(1)
	w.Values[9] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.AddLiquidityABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.AddLiquidity)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint16), new(big.Int).SetUint64(w.Values[2].(uint64)), new(big.Int).SetUint64(w.Values[3].(uint64)), w.Values[4].(uint32), w.Values[5].(uint16), w.Values[6].(uint16), w.Values[7].(uint64), w.Values[8].(uint32), w.Values[9].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunRemoveLiquidity(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.RemoveLiquidityAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)
	w.Values[2] = uint64(1)
	w.Values[3] = uint64(1)
	w.Values[4] = uint64(1)
	w.Values[5] = uint32(1)
	w.Values[6] = uint16(1)
	w.Values[7] = uint16(1)
	w.Values[8] = uint64(1)
	w.Values[9] = uint32(1)
	w.Values[10] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.RemoveLiquidityABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.RemoveLiquidity)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint16), new(big.Int).SetUint64(w.Values[2].(uint64)), new(big.Int).SetUint64(w.Values[3].(uint64)), new(big.Int).SetUint64(w.Values[4].(uint64)), w.Values[5].(uint32), w.Values[6].(uint16), w.Values[7].(uint16), w.Values[8].(uint64), w.Values[9].(uint32), w.Values[10].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunSwap(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.SwapAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint16(1)
	w.Values[2] = uint64(1)
	w.Values[3] = uint64(1)
	w.Values[4] = uint32(1)
	w.Values[5] = uint16(1)
	w.Values[6] = uint16(1)
	w.Values[7] = uint64(1)
	w.Values[8] = uint32(1)
	w.Values[9] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.SwapABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.Swap)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint16), new(big.Int).SetUint64(w.Values[2].(uint64)), new(big.Int).SetUint64(w.Values[3].(uint64)), w.Values[4].(uint32), w.Values[5].(uint16), w.Values[6].(uint16), w.Values[7].(uint64), w.Values[8].(uint32), w.Values[9].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunCreateCollection(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.CreateCollectionAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	w.Values[2] = uint16(1)
	w.Values[3] = uint16(1)
	w.Values[4] = uint64(1)
	w.Values[5] = uint32(1)
	w.Values[6] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.CreateCollectionABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.CreateCollection)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint32), w.Values[2].(uint16), w.Values[3].(uint16), w.Values[4].(uint64), w.Values[5].(uint32), w.Values[6].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunWithdrawNft(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.WithdrawNftAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = new(big.Int).SetUint64(1)
	bytesLast := [20]byte{'0'}
	wrappedLast := abi.WrapToAbiBytes20(bytesLast)
	for i := range wrappedLast {
		w.Values[2+i] = wrappedLast[i]
	}
	w.Values[22] = uint32(1)
	w.Values[23] = uint16(1)
	w.Values[24] = uint16(1)
	w.Values[25] = uint64(1)
	w.Values[26] = uint32(1)
	w.Values[27] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.WithdrawNftABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.WithdrawNft)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1], bytesLast, w.Values[22].(uint32), w.Values[23].(uint16), w.Values[24].(uint16), w.Values[25].(uint64), w.Values[26].(uint32), w.Values[27].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunTransferNft(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.TransferNftAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	bytesFirst := [32]byte{'0'}
	wrappedFirst := abi.WrapToAbiBytes32(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	w.Values[34] = new(big.Int).SetUint64(1)
	w.Values[35] = uint32(1)
	w.Values[36] = uint16(1)
	w.Values[37] = uint16(1)
	bytesLast := [32]byte{'0'}
	wrappedLast := abi.WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[38+i] = wrappedLast[i]
	}
	w.Values[70] = uint64(1)
	w.Values[71] = uint32(1)
	w.Values[72] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.TransferNftABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.TransferNft)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint32), bytesFirst, w.Values[34], w.Values[35].(uint32), w.Values[36].(uint16), w.Values[37].(uint16), bytesLast, w.Values[70].(uint64), w.Values[71].(uint32), w.Values[72].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunMintNft(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.MintNftAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	bytesFirst := [32]byte{'0'}
	wrappedFirst := abi.WrapToAbiBytes32(bytesFirst)
	for i := range wrappedFirst {
		w.Values[2+i] = wrappedFirst[i]
	}
	bytesLast := [32]byte{'0'}
	wrappedLast := abi.WrapToAbiBytes32(bytesLast)
	for i := range wrappedLast {
		w.Values[34+i] = wrappedLast[i]
	}
	w.Values[68] = uint32(1)
	w.Values[69] = uint16(1)
	w.Values[70] = uint16(1)
	w.Values[71] = uint32(1)
	w.Values[72] = uint32(1)
	w.Values[73] = uint64(1)
	w.Values[74] = uint32(1)
	w.Values[75] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.MintNftABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.MintNft)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), w.Values[1].(uint32), bytesFirst, bytesLast, w.Values[68].(uint32), w.Values[69].(uint16), w.Values[70].(uint16), w.Values[71].(uint32), w.Values[72].(uint32), w.Values[73].(uint64), w.Values[74].(uint32), w.Values[75].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunCancelOffer(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.CancelOfferAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	w.Values[0] = uint32(1)
	w.Values[1] = uint64(1)
	w.Values[2] = uint32(1)
	w.Values[3] = uint16(1)
	w.Values[4] = uint16(1)
	w.Values[5] = uint64(1)
	w.Values[6] = uint32(1)
	w.Values[7] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.CancelOfferABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.CancelOffer)

	b, err := a.Pack("", messageTypeBytes32, w.Values[0].(uint32), new(big.Int).SetUint64(w.Values[1].(uint64)), w.Values[2].(uint32), w.Values[3].(uint16), w.Values[4].(uint16), w.Values[5].(uint64), w.Values[6].(uint32), w.Values[7].(uint32))
	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func RunAtomicMatch(t *testing.T, bs []byte) {
	// Compile circuit
	var circuit eip712.Eip712Circuit = DefaultCircuit()
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", len(_scs.GetConstraints()))

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w eip712.Eip712Circuit
	w.AbiId = int(abi.AtomicMatchAbi)
	w.Values = make([]frontend.Variable, 255)
	w.Keccaa256Hash = make([]frontend.Variable, 32)
	for i := 0; i < len(w.Values); i++ {
		w.Values[i] = 0
	}
	r := [32]byte{'0'}
	s := [32]byte{'0'}
	wrappedR := abi.WrapToAbiBytes32(r)
	wrappedS := abi.WrapToAbiBytes32(s)
	w.Values[0] = uint32(1)
	w.Values[1] = uint32(1)
	w.Values[2] = uint32(1)
	w.Values[3] = uint32(1)
	w.Values[4] = uint32(1)
	w.Values[5] = uint32(1)
	w.Values[6] = uint32(1)
	w.Values[7] = uint32(1)
	w.Values[8] = uint32(1)
	for i, ri := range wrappedR {
		w.Values[9+i] = ri
	}
	for i, ri := range wrappedS {
		w.Values[41+i] = ri
	}
	w.Values[73] = uint32(1)
	w.Values[74] = uint32(1)
	w.Values[75] = uint32(1)
	w.Values[76] = uint32(1)
	w.Values[77] = uint32(1)
	w.Values[78] = uint32(1)
	w.Values[79] = uint32(1)
	w.Values[80] = uint32(1)
	w.Values[81] = uint32(1)
	for i, ri := range wrappedR {
		w.Values[82+i] = ri
	}
	for i, ri := range wrappedS {
		w.Values[114+i] = ri
	}
	w.Values[146] = uint32(1)
	w.Values[147] = uint32(1)

	a, err := abiEth.JSON(strings.NewReader(abi.AtomicMatchABIJSON))
	assert.NoError(t, err)

	messageTypeBytes32 := abi.GetEIP712MessageTypeHashBytes32(abi.AtomicMatch)

	one := new(big.Int).SetUint64(1)
	b, err := a.Pack("", messageTypeBytes32,
		one, one, one, one, one,
		one, one, one, one, r, s,
		one, one, one, one, one,
		one, one, one, one, r, s,
		one, one)

	assert.NoError(t, err)

	fillCircuitHashAndPK(t, &w, b, bs, abi.HexPrefixAndEip712DomainKeccakHash)

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	assert.NoError(t, err)

	proof, err := plonk.Prove(_scs, pk, witnessFull)
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

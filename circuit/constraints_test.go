package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"testing"
)

func TestTransactionConstraintsCount(t *testing.T) {
	var txCircuit TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &txCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Println("error occured ", err)
	}
	fmt.Println("tx circuit constraints number is ", r1cs.GetNbConstraints())
}

func TestBlockConstraintsCounts(t *testing.T) {
	var blockCircuit BlockConstraints
	blockCircuit.TxsCount = 1
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	blockCircuit.Txs = make([]TxConstraints, blockCircuit.TxsCount)
	for i := 0; i < blockCircuit.TxsCount; i++ {
		blockCircuit.Txs[i] = GetZeroTxConstraint()
	}
	blockCircuit.GasAssetIds = gasAssetIds
	blockCircuit.GasAccountIndex = gasAccountIndex
	blockCircuit.Gas = GetZeroGasConstraints(gasAssetIds)

	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &blockCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Println("error occured ", err)
	}
	fmt.Println("block circuit constraints number is ", r1cs.GetNbConstraints())
}

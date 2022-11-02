package circuit

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

import (
	"testing"
)

func TestTransactionConstraintsCounts(t *testing.T) {
	var txCircuit TxConstraints
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &txCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Println("error occured ", err)
	}
	fmt.Println("tx circuit constraints number is ", r1cs.GetNbConstraints())
}

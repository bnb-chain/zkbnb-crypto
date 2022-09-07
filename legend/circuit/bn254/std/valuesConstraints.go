package std

const TxValueConstraintLimit = 256

type ValuesConstraints struct {
	Values [TxValueConstraintLimit]Variable
}

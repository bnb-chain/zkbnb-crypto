package std

import "github.com/consensys/gnark/std/algebra/twistededwards"

type EccTool struct {
	api    API
	params twistededwards.EdCurve
}

func NewEccTool(api API, params twistededwards.EdCurve) *EccTool {
	return &EccTool{api: api, params: params}
}

func (tool *EccTool) ScalarBaseMul(b Variable) Point {
	var p Point
	p.ScalarMulFixedBase(tool.api, tool.params.BaseX, tool.params.BaseY, b, tool.params)
	return p
}

func (tool *EccTool) ScalarMul(a Point, b Variable) Point {
	var p Point
	p.ScalarMulNonFixedBase(tool.api, &a, b, tool.params)
	return p
}

func (tool *EccTool) AddPoint(a, b Point) Point {
	var p Point
	p.AddGeneric(tool.api, &a, &b, tool.params)
	return p
}

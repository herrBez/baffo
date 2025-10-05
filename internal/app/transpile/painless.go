package transpile

type PNodeType int

const (
	Literal PNodeType = iota
	Operator
	UnaryOperator
	PropertyAccess
)

// PNode represents a node in the AST
type PNode struct {
	Type     PNodeType
	Value    string
	Left     *PNode
	Right    *PNode
	Object   *PNode
	Operator string
	Property string
	Nullable bool
}

// Create helper functions to create nodes
func NewLiteral(value string) *PNode {
	return &PNode{Type: Literal, Value: value}
}

func NewOperator(operator string, left, right *PNode) *PNode {
	return &PNode{Type: Operator, Operator: operator, Left: left, Right: right}
}

func NewUnaryOperator(operator string, operand *PNode) *PNode {
	return &PNode{Type: UnaryOperator, Operator: operator, Left: operand}
}

func NewPropertyAccess(object *PNode, property string, nullable bool) *PNode {
	return &PNode{Type: PropertyAccess, Object: object, Property: property}
}

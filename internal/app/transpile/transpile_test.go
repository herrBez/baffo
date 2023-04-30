package transpile

import (
	"testing"

	ast "github.com/breml/logstash-config/ast"
)

func TestConversionOfConditions(t *testing.T) {
	tt := []struct {
		name  string
		input ast.Condition
		want  string
	}{

		{
			name: "Empty Condition",
			input: ast.Condition{
				Expression: []ast.Expression{},
			},
			want: ``,
		},
		{
			name: "Field Exists",
			input: ast.Condition{
				Expression: []ast.Expression{
					ast.NewRvalueExpression(
						ast.BooleanOperator{Op: ast.NoOperator},
						ast.NewSelector(
							[]ast.SelectorElement{
								ast.NewSelectorElement("foo"),
							},
						),
					),
				},
			},
			want: `ctx?.foo != null`,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := transpileCondition(tc.input)

			if tc.want != got {
				t.Errorf("want %s, got %s", tc.want, got)
			}
		})
	}
}

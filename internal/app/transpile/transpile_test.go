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
			// [foo]
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
			want: `ctx?.foo != null && ctx.foo != null`,
		},
		{
			name: "Field equals value",
			want: `ctx?.foo != null && ctx.foo == "foo"`,
			// [foo] == "foo"
			input: ast.Condition{
				Expression: []ast.Expression{
					ast.NewCompareExpression(
						ast.BooleanOperator{Op: ast.NoOperator},
						ast.NewSelector([]ast.SelectorElement{ast.NewSelectorElement("foo")}),
						ast.CompareOperator{Op: ast.Equal},
						ast.NewStringAttribute("foo", "foo", ast.DoubleQuoted),
					),
				},
			},
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

// The function is called when converting selectors in if boolean expression
func TestToElasticPipelineSelectorCondition(t *testing.T) {
	tt := []struct {
		name  string
		input string
		want  []string
	}{

		{
			name:  "Normal case",
			input: "[foo][bar]",
			want:  []string{`ctx?.foo?.bar`, `ctx.foo.bar`},
		},
		{
			name:  "Special fields with '@' cannot be converted with . syntax, they need to use square",
			input: "[@metadata][bar]",
			want:  []string{`ctx.getOrDefault('@metadata', null)?.bar`, `ctx['@metadata'].bar`},
		},
		{
			name:  "Fields without special symbols are converted with the same name",
			input: "A",
			want:  []string{`ctx?.A`, `ctx.A`},
		},
		{
			name:  "Fields with special symbols are converted with square syntax",
			input: "A@B",
			want:  []string{`ctx.getOrDefault('A@B', null)`, `ctx['A@B']`},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := []string{
				toElasticPipelineSelectorWithNullable(tc.input, true),
				toElasticPipelineSelectorWithNullable(tc.input, false),
			}

			if tc.want[0] != got[0] {
				t.Errorf("Nullable: want \"%s\", got \"%s\"", tc.want[0], got[0])
			}
			if tc.want[1] != got[1] {
				t.Errorf("Nullable False: want \"%s\", got \"%s\"", tc.want[1], got[1])
			}
		})
	}
}

func TestToElasticPipelineSelector(t *testing.T) {
	tt := []struct {
		name  string
		input string
		want  string
	}{

		{
			name:  "Normal case",
			input: "[foo][bar]",
			want:  `foo.bar`,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := toElasticPipelineSelector(tc.input)
			if tc.want != got {
				t.Errorf("want \"%s\", got \"%s\"", tc.want, got)
			}
		})
	}
}

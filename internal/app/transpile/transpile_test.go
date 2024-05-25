package transpile

import (
	"fmt"
	"testing"

	config "github.com/breml/logstash-config"
	ast "github.com/breml/logstash-config/ast"
	"github.com/rs/zerolog/log"
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
			want: `ctx?.foo != null`,
		},
		{
			name: "Field equals value",
			want: `(ctx?.foo != null && ctx.foo == "foo")`,
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
func TestToElasticPipelineSelectorConditionWithNullable(t *testing.T) {
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
		{
			name:  "At case",
			input: "[@metadata][test]",
			want:  `@metadata.test`,
		},
		{
			name:  "Without square brackets",
			input: "justafield",
			want:  `justafield`,
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

// Help function to guarantee that a function returning a value and an error, returns only the value
func dealWithError(i interface{}, err error) interface{} {
	if err == nil {
		return i
	}
	log.Panic().Msgf("Error: %v", err)
	return err
}

// Instead of writing the parse tree manually, we do the following:
// 1. Create a dummy filter
// 2. Parse the dummy configuration
// 3. Extract the condition
func extractCondition(s string) ast.Condition {
	return dealWithError(config.Parse("fake", []byte(fmt.Sprintf("filter { if %s {} }", s)))).(ast.Config).Filter[0].BranchOrPlugins[0].(ast.Branch).IfBlock.Condition
}

func TestEndToEnd(t *testing.T) {
	tt := []struct {
		name  string
		input string
		want  string
	}{

		{
			name:  "Field does not exist",
			input: "![foo][bar]",
			want:  "ctx?.foo?.bar == null",
		},
		{
			name:  "Field equals string",
			input: `[test] == "45"`,
			want:  `(ctx?.test != null && ctx.test == "45")`,
		},
		{
			name:  "Negation",
			input: "!(![test] or ![foo])",
			want:  "!(ctx?.test == null || ctx?.foo == null)",
		},
		{
			name:  "Cond1 or cond2",
			input: `[abc] == "def" or [ghi]`,
			// Got: (ctx?.foo != null && ctx.foo == "foo") && ctx?.test != null && ctx.test
			want: `(ctx?.abc != null && ctx.abc == "def") || ctx?.ghi != null`,
		},
		{
			name:  "Field exist",
			input: `[test][bar]`,
			want:  `ctx?.test?.bar != null`,
		},
		{
			name:  "Field with special chars exist",
			input: `[@metadata][input]`,
			want:  `ctx.getOrDefault('@metadata', null)?.input != null`,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := transpileCondition(extractCondition(tc.input))
			if tc.want != got {
				t.Errorf("want \"%s\", got \"%s\"", tc.want, got)
			}
		})
	}
}

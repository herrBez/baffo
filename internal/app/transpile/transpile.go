package transpile

import (
	"log"
	"os"
	"strings"
	"time"

	// "strings"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"reflect"

	config "github.com/breml/logstash-config"
	"github.com/breml/logstash-config/internal/format"

	ast "github.com/breml/logstash-config/ast"

	"math/rand"
)

type Transpile struct{}

func New() Transpile {
	return Transpile{}
}

func (f Transpile) Run(args []string) error {
	var result *multierror.Error

	for _, filename := range args {
		stat, err := os.Stat(filename)
		if err != nil {
			result = multierror.Append(result, errors.Errorf("%s: %v", filename, err))
		}
		if stat.IsDir() {
			continue
		}

		res, err1 := config.ParseFile(filename, config.IgnoreComments(true))

		if err1 != nil {
			log.Println(err1)

			log.Println(res)
			log.Println(reflect.TypeOf(res))

			// if errMsg, hasErr := config.GetFarthestFailure(); hasErr {
			// 	if !strings.Contains(err.Error(), errMsg) {
			// 		err = errors.Errorf("%s: %v\n%s", filename, err, errMsg)
			// 	}
			// }
			// result = multierror.Append(result, errors.Errorf("%s: %v", filename, err))
			// continue
		} else {
			var tree ast.Config = res.(ast.Config)
			// log.Println(reflect.TypeOf(tree))

			buildIngestPipeline(tree)

		}
	}

	if result != nil {
		result.ErrorFormat = format.MultiErr
		return result
	}

	return nil
}

func transpileBoolExpression(bo ast.BooleanOperator) string {
	switch bo.Op {
	case ast.NoOperator:
		return ""
	case ast.And:
		return " && "
	case ast.Or:
		return " || "
	default:
		fmt.Println("Unknown operator")
		os.Exit(1)

		//	case ast.Xor: ""
		// case ast.Nand:
	}
	return ""
}

func transpileExpression(expr ast.Expression) string {
	return ""
}

func toElasticPipelineSelectorCondition(sel string) string {

	if sel[0] == '[' && sel[len(sel)-1] == ']' {
		return "ctx?." + strings.ReplaceAll(sel[1:len(sel)-1], "][", "?.")
	}
	return "ctx." + sel
}

func toElasticPipelineSelector(sel string) string {

	if sel[0] == '[' && sel[len(sel)-1] == ']' {
		return strings.ReplaceAll(sel[1:len(sel)-1], "][", ".")
	}
	return sel
}

func transpileRvalue(expr ast.Node) string {
	switch texpr := expr.(type) {
	case ast.StringAttribute:
		return "\"" + texpr.Value() + "\""
	case ast.Selector:
		return toElasticPipelineSelectorCondition(texpr.String())

	case ast.ArrayAttribute:
		output := "["
		for i, attr := range texpr.Attributes {
			output += transpileRvalue(attr)
			if i < len(texpr.Attributes)-1 {
				output = output + ", "
			}
		}
		output = output + "]"
		return output
	}

	fmt.Println(reflect.TypeOf(expr))
	return ""

}

func transpileCondition(c ast.Condition) string {
	var output string
	for _, expr := range c.Expression {
		// if i != 0 && i <= len(c.Expression)-1 {
		// 	output += ") && ("
		// }
		// fmt.Printf("Here %s\n", reflect.TypeOf(expr))
		switch texpr := expr.(type) {

		case ast.ConditionExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + bOpComparator + transpileCondition(texpr.Condition)
		case ast.NegativeConditionExpression:
			operator_converted := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + "!" + operator_converted + "(" + transpileCondition(texpr.Condition) + ")"

		case ast.InExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + bOpComparator + transpileRvalue(texpr.LValue) + ".contains(" + transpileRvalue(texpr.RValue) + ")"

		case ast.NotInExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + "!" + bOpComparator + transpileRvalue(texpr.LValue) + ".contains(" + transpileRvalue(texpr.RValue) + ")"

		case ast.CompareExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			transpileRvalue(texpr.RValue)
			transpileRvalue(texpr.LValue)
			output = output + bOpComparator + transpileRvalue(texpr.LValue) + " " + texpr.CompareOperator.String() + " " + transpileRvalue(texpr.RValue)

		// case ast.RegexpExpression: TODO

		// case ast.RvalueExpression: TODO

		default:
			fmt.Println("Cannot convert %s", reflect.TypeOf(texpr))
		}
	}
	return output
}

type TranspileProcessor func(plugin ast.Plugin, constraint Constraints) []IngestProcessor

func getHashAttributeKeyValue(attr ast.Attribute) ([]string, []string) {
	var keys []string
	var values []string
	switch t := attr.(type) {
	case ast.HashAttribute:
		for _, entry := range t.Entries {
			switch tKey := entry.Key.(type) {
			case ast.StringAttribute:
				keys = append(keys, toElasticPipelineSelector(tKey.Value()))
			default:
				log.Panic("Unexpected key of type not string")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute:
				values = append(values, tValue.Value())

			default:
				log.Panic("Unexpected key of type not string")
			}

			// raw_keys = append(raw_keys, entry.Key)

			// raw_values = append(raw_values, entry.Value)
		}

	default: // Unexpected Case --> PANIC
		log.Panicf("Unexpected Case")
	}
	return keys, values
}

func getStringAttributeString(attr ast.Attribute) string {
	switch tattr := attr.(type) {
	case ast.StringAttribute:
		return tattr.Value()
	default:
		log.Panic("Not expected")
	}
	return ""
}

func getArrayStringAttributes(attr ast.Attribute) []string {
	var values []string
	switch tattr := attr.(type) {
	case ast.ArrayAttribute:
		for _, el := range tattr.Attributes {
			values = append(values, getStringAttributeString(el))
		}

	default:
		log.Panicf("I will only an array of strings")
	}
	return values
}

func hashAttributeToMap(attr ast.Attribute) map[string]string {
	m := map[string]string{}
	switch tattr := attr.(type) {
	case ast.HashAttribute:
		for _, entry := range tattr.Entries {
			var keyString string
			var valueString string

			switch tKey := entry.Key.(type) {
			case ast.StringAttribute:
				keyString = tKey.Value()
			default:
				log.Panicf("Expecting a string for the keys")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute:
				valueString = tValue.Value()
			default:
				log.Panicf("Expecting a string")
			}

			m[keyString] = valueString
		}
	}
	return m
}

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length+2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[2 : length+2]
}

func DealWithMutate(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}

	id, err := plugin.ID()
	if err != nil {
		// Autogenerate plugin-id
		id = plugin.Name() + "-" + randomString(2)
	}

	counter := 0 // Counter used to increment the tag

	constraintTranspiled := transpileConstraint(constraint)

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "add_field":
			keys, values := getHashAttributeKeyValue(attr)

			for i := range keys {
				ingestProcessors = append(ingestProcessors,
					SetProcessor{
						Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
						If:          constraintTranspiled,
						Value:       values[i],
						Field:       keys[i],
						OnFailure:   nil,
						Tag:         fmt.Sprintf("%s-%d", id, counter),
					})
				counter += 1
			}
		case "id": // Do Nothing --> It is already extracted
		case "rename":

			keys, values := getHashAttributeKeyValue(attr)
			for i := range keys {
				ingestProcessors = append(ingestProcessors,
					RenameProcessor{
						Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
						If:          constraintTranspiled,
						TargetField: values[i],
						Field:       keys[i],
						OnFailure:   nil,
						Tag:         fmt.Sprintf("%s-%d", id, counter),
					})
				counter += 1
			}
		case "copy":
			keys, values := getHashAttributeKeyValue(attr)

			constraintTranspiled := transpileConstraint(constraint)
			for i := range keys {

				ingestProcessors = append(ingestProcessors,
					SetProcessor{
						Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),

						If:        constraintTranspiled,
						CopyFrom:  keys[i],
						Field:     values[i],
						OnFailure: nil,
						Tag:       fmt.Sprintf("%s-%d", id, counter),
					})
				counter += 1
			}
		case "uppercase", "lowercase":
			// Assuming only the field
			switch tAttributes := attr.(type) {
			case ast.ArrayAttribute:
				for _, el := range tAttributes.Attributes {
					ingestProcessors = append(ingestProcessors,
						CaseProcessor{
							Type:        attr.Name(), // either uppercase or lowercase
							Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
							If:          transpileConstraint(constraint),
							TargetField: getStringAttributeString(el),
							Field:       getStringAttributeString(el),
							OnFailure:   nil,
							Tag:         fmt.Sprintf("%s-%d", id, counter),
						})
				}
				counter += 1

			default: // uppercase/lowercase require an Array
				log.Printf("Mutate filter attribute '%s' not supported", attr.Name())
			}

		case "gsub":
			// Assuming only the field
			switch tAttributes := attr.(type) {
			case ast.ArrayAttribute:

				gsubexpression := getArrayStringAttributes(tAttributes)

				if len(gsubexpression)%3 != 0 {
					log.Printf("Something does not go")
				}

				for i := 0; i < len(gsubexpression); i += 3 {
					ingestProcessors = append(ingestProcessors,
						GsubProcessor{
							Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
							If:          transpileConstraint(constraint),
							Field:       gsubexpression[i],
							Pattern:     gsubexpression[i+1],
							Replacement: gsubexpression[i+2],
							OnFailure:   nil,
							Tag:         fmt.Sprintf("%s-%d", id, counter),
						})
				}
			}

		}
	}

	return ingestProcessors
}

func DealWithGrok(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}

	id, err := plugin.ID()
	if err != nil {
		// Autogenerate plugin-id
		id = plugin.Name() + "-" + randomString(2)
	}

	counter := 0 // Counter used to increment the tag

	constraintTranspiled := transpileConstraint(constraint)

	gp := GrokProcessor{
		Tag: id,
	}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "add_field":
			keys, values := getHashAttributeKeyValue(attr)

			for i := range keys {
				ingestProcessors = append(ingestProcessors,
					SetProcessor{
						Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
						If:          constraintTranspiled,
						Value:       values[i],
						Field:       keys[i],
						OnFailure:   nil,
						Tag:         fmt.Sprintf("%s-%d", id, counter),
					})
				counter += 1
			}
		case "match":
			helpPattern := hashAttributeToMapArray(attr)
			// TODO: Deal with multiple keys, currently only the last is used
			for key := range helpPattern {
				gp.Patterns = helpPattern[key]
			}

		case "ecs_compatibility":
			gp.ECSCompatibility = getStringAttributeString(attr)
		case "pattern_definitions":
			gp.PatternDefinitions = hashAttributeToMap(attr)
		case "tag_on_failure":
			gp.OnFailure = []IngestProcessor{AppendProcessor{
				Tag:         fmt.Sprintf("append-tag-%s-%d", id, counter),
				Description: getStringPointer("Append Tag on Failure"),
				Field:       "tags",
				Value:       getArrayStringAttributes(attr),
			}}

		default:
			log.Printf("Pattern '%s' is currently not supported", attr.Name())

		}
	}
	ingestProcessors = append(ingestProcessors, gp)
	return ingestProcessors
}

func DealWithMissingTranspiler(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	constraintTranspiled := transpileConstraint(constraint)
	if constraintTranspiled == nil {
		tmp := ""
		constraintTranspiled = &tmp
	}

	log.Printf("[WARN] Plugin %s is not yet supported. Consider Making a contribution :)\nHere is the translated if-condition '%s'", plugin.Name(), *constraintTranspiled)
	return []IngestProcessor{}
}

var transpiler = map[string]map[string]TranspileProcessor{
	"input": {},
	"filter": {
		"mutate": DealWithMutate,
		"grok":   DealWithGrok,
	},
	"output": {},
}

func transpileConstraint(constraint Constraints) *string {
	if len(constraint.Conditions) == 0 {
		return nil
	}
	converted := "("
	for i, cond := range constraint.Conditions {
		converted = converted + transpileCondition(cond)
		if i < len(constraint.Conditions)-1 {
			converted += ") && ("
		}
	}
	converted = converted + ")"
	return &converted
}

func buildIngestPipeline(c ast.Config) {
	plugin_names := []string{}
	ip := IngestPipeline{
		Description:         "",
		Processors:          []IngestProcessor{},
		OnFailureProcessors: nil,
	}
	applyFunc := func(c *Cursor, constraint Constraints) {
		// fmt.Printf("Plugin: %s, Pos: %s\n", c.Plugin().Name(), c.Plugin().Pos())

		f, ok := transpiler["filter"][c.Plugin().Name()]
		if !ok {
			fmt.Printf("There is no handler for the plugin %s\n", c.Plugin().Name())
			f = DealWithMissingTranspiler
		}
		ip.Processors = append(ip.Processors, f(*c.Plugin(), constraint)...)

		plugin_names = append(plugin_names, c.Plugin().Name())
	}

	for _, f := range c.Filter {
		MyIteration(f.BranchOrPlugins, NewConstraintLiteral(), applyFunc)
	}

	fmt.Printf("%s", ip)

}

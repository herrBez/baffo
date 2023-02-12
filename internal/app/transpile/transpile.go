package transpile

import (
	"log"
	"os"
	"regexp"
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

		case ast.NegativeSelectorExpression:
			output = output + "!" + transpileRvalue(texpr.Selector)

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

		case ast.RvalueExpression:
			bOpComparator := ""
			if texpr.BoolExpression.BoolOperator().Op != ast.NoOperator {
				bOpComparator = transpileBoolExpression(texpr.BoolExpression.BoolOperator())
				output = output + bOpComparator + transpileRvalue(texpr.RValue)
			} else {
				output = output + transpileRvalue(texpr.RValue) + " != null"
			}
		default:
			log.Printf("Cannot convert %s %s", reflect.TypeOf(texpr), texpr)
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

	id := getProcessorID(plugin)

	counter := 0 // Counter used to increment the tag

	constraintTranspiled := transpileConstraint(constraint)

	// Remove all Common Attributes
	plugin_attributes := []ast.Attribute{}

	for _, attr := range plugin.Attributes {
		if !Contains(CommonAttributes, attr.Name()) {
			plugin_attributes = append(plugin_attributes, attr)
		}
	}

	onSuccessProcessors := DealWithCommonAttributes(plugin, constraint, id)

	for _, attr := range plugin_attributes {
		switch attr.Name() {
		// It is a common field
		case "rename":

			keys, values := getHashAttributeKeyValue(attr)
			for i := range keys {
				ingestProcessors = append(ingestProcessors,
					RenameProcessor{
						Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
						If:          constraintTranspiled,
						TargetField: toElasticPipelineSelector(values[i]),
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

		case "join":

			keys, values := getHashAttributeKeyValue(attr)
			for i := range keys {
				ingestProcessors = append(ingestProcessors,
					JoinProcessor{
						Description:   getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
						If:            constraintTranspiled,
						Separator:     values[i],
						Field:         keys[i],
						IgnoreFailure: true, // Ignore Failure set to true, because Logstash does not require it to be an array
						OnFailure:     nil,
						Tag:           fmt.Sprintf("%s-%d", id, counter),
					})
				counter += 1
			}
		default:
			log.Printf("Mutate of type '%s' not supported", attr.Name())

		}

	}

	ingestProcessors = append(ingestProcessors, onSuccessProcessors...)

	return ingestProcessors
}

func DealWithTagOnFailure(attr ast.Attribute, id string) []IngestProcessor {
	return []IngestProcessor{AppendProcessor{
		Tag:         fmt.Sprintf("append-tag-%s", id),
		Description: getStringPointer("Append Tag on Failure"),
		Field:       "tags",
		Value:       getArrayStringAttributes(attr),
	}}
}

var CommonAttributes = []string{"add_field", "remove_field", "add_tag", "id", "enable_metric", "periodic_flush", "remove_tag"}

func toElasticPipelineSelectorExpression(s string) string {
	newS := s
	// Strings of type foo_%{[afield]}
	field_finder := regexp.MustCompile(`\%\{([^\}]+)\}`)
	for _, m := range field_finder.FindAll([]byte(s), -1) {
		log.Println(toElasticPipelineSelector(string(m[2 : len(m)-1])))
		newS = strings.Replace(newS, string(m), "{{"+toElasticPipelineSelector(string(m[2:len(m)-1]))+"}}", 1)
	}
	return newS
}

func DealWithCommonAttributes(plugin ast.Plugin, constraint Constraints, id string) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}
	constraintTranspiled := transpileConstraint(constraint)
	counter := 0
	for _, attr := range plugin.Attributes {
		if !Contains(CommonAttributes, attr.Name()) {
			continue // Ignore not common attributes
		}
		switch attr.Name() {
		// It is a common field
		case "add_field":
			keys, values := getHashAttributeKeyValue(attr)

			for i := range keys {
				ingestProcessors = append(ingestProcessors,
					SetProcessor{
						Description: getStringPointer(plugin.Comment.String() + attr.CommentBlock()),
						If:          constraintTranspiled,
						Value:       toElasticPipelineSelectorExpression(values[i]),
						Field:       keys[i],
						OnFailure:   nil,
						Tag:         fmt.Sprintf("%s-%d", id, counter),
					})
				counter += 1
			}
		case "remove_field":
			ingestProcessors = append(ingestProcessors,
				RemoveProcessor{
					Field: getStringAttributeString(attr),
				},
			)
		case "add_tag":
			ingestProcessors = append(ingestProcessors,
				AppendProcessor{
					Tag:   fmt.Sprintf("append-tag-%s", id),
					Field: "tags",
					Value: getArrayStringAttributes(attr),
				},
			)
		case "id": // Already Added
		case "enable_metric", "periodic_flush": // N/A

		// case "remove_tag": // Not Supported
		default:
			log.Printf("Remove Tag (%s) is not yet supported", attr.Name())

		}
	}
	return ingestProcessors

}

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func getProcessorID(plugin ast.Plugin) string {
	id, err := plugin.ID()
	if err != nil {
		// Autogenerate plugin-id
		id = plugin.Name() + "-" + randomString(2)
	}
	return id
}

func DealWithGrok(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}

	id := getProcessorID(plugin)

	constraintTranspiled := transpileConstraint(constraint)

	gp := GrokProcessor{
		Tag: getProcessorID(plugin),
		If:  constraintTranspiled,
	}

	onSuccessProcessors := DealWithCommonAttributes(plugin, constraint, id)

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		// It is a common field
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
			gp.OnFailure = DealWithTagOnFailure(attr, id)
		default:
			log.Printf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}
	// Add _grok_parse_failure
	if len(gp.OnFailure) == 0 {
		gp.OnFailure = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_grok_parse_failure", ast.DoubleQuoted)), id)
	}

	ingestProcessors = append(ingestProcessors, gp)
	// TODO Add processors if on success and not always
	ingestProcessors = append(ingestProcessors, onSuccessProcessors...)
	return ingestProcessors
}

func DealWithKV(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}

	id := getProcessorID(plugin)

	constraintTranspiled := transpileConstraint(constraint)

	kv := KVProcessor{
		Tag:        id,
		If:         constraintTranspiled,
		FieldSplit: " ",       // Default value in Logstash
		Field:      "message", // Default value in Logstash
	}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			kv.OnFailure = DealWithTagOnFailure(attr, id)
		case "target":
			kv.TargetField = getStringPointer(getStringAttributeString(attr))
		case "prefix":
			kv.Prefix = getStringPointer(getStringAttributeString(attr))
		case "field_split":
			kv.FieldSplit = getStringAttributeString(attr) // TODO: De-Escape chars???
		case "exclude_keys":
			kv.ExcludeKeys = getArrayStringAttributes(attr)
		case "include_keys":
			kv.IncludeKeys = getArrayStringAttributes(attr)
		case "include_brackets":
			kv.StripBrackets = !getBoolValue(attr)
		case "source":
			kv.Field = getStringAttributeString(attr)
		default:
			log.Printf("Attribute '%s' is currently not supported", attr.Name())

		}
	}
	// Add _kv_filter_error
	if len(kv.OnFailure) == 0 {
		kv.OnFailure = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_kv_filter_error", ast.DoubleQuoted)), id)
	}

	ingestProcessors = append(ingestProcessors, kv)

	return ingestProcessors
}

func DealWithMissingTranspiler(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	constraintTranspiled := transpileConstraint(constraint)
	if constraintTranspiled == nil {
		tmp := ""
		constraintTranspiled = &tmp
	}

	log.Printf("[WARN] Plugin %s is not yet supported. Consider Making a contribution :)\n", plugin.Name())

	return []IngestProcessor{}
}

var transpiler = map[string]map[string]TranspileProcessor{
	"input": {},
	"filter": {
		"mutate": DealWithMutate,
		"grok":   DealWithGrok,
		"kv":     DealWithKV,
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
			log.Printf("There is no handler for the plugin %s\n", c.Plugin().Name())
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

package transpile

import (
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.elastic.co/ecszerolog"

	// "strings"
	"bytes"
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
	logger := ecszerolog.New(os.Stderr)
	log.Logger = logger
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
			log.Warn().Msgf("%s %s %s", err1, res, reflect.TypeOf(res))

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

type TranspileProcessorV2 func(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor)

var transpilerV2 = map[string]map[string]TranspileProcessorV2{
	"input": {},
	"filter": {
		"mutate":  DealWithMutateV2,
		"drop":    DealWithDropV2,
		"date":    DealWithDateV2,
		"dissect": DealWithDissectV2,
		"grok":    DealWithGrokV2,
		"kv":      DealWithKVV2,
		"cidr":    DealWithCidrV2,
	},
	"output": {},
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
				log.Panic().Msg("Unexpected key of type not string")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute:
				values = append(values, tValue.Value())

			default:
				log.Panic().Msg("Unexpected key of type not string")
			}
		}

	default: // Unexpected Case --> PANIC
		log.Panic().Msg("Unexpected Case")
	}
	return keys, values
}

func getStringAttributeString(attr ast.Attribute) string {
	switch tattr := attr.(type) {
	case ast.StringAttribute:
		return tattr.Value()
	default:
		log.Panic().Msg("Not expected")
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
		log.Panic().Msg("I will only an array of strings")
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
				log.Panic().Msg("Expecting a string for the keys")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute:
				valueString = tValue.Value()
			default:
				log.Panic().Msg("Expecting a string")
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

func DealWithMutateAttributes(attr ast.Attribute, ingestProcessors []IngestProcessor, id string) []IngestProcessor {
	switch attr.Name() {

	case "capitalize":
		values := getArrayStringAttributes(attr)
		for _, value := range values {
			field := toElasticPipelineSelector(value)
			ingestProcessors = append(ingestProcessors, ScriptProcessor{
				Source: getStringPointer(
					fmt.Sprintf(
						`if(ctx.%s instanceof String) {
	ctx.%s = ctx.%s.substring(0, 1).toUpperCase() + ctx.%s.substring(1);
} else if(ctx.%s instanceof List) {
	ctx.%s = ctx.%s.stream().map(x -> x.substring(0, 1).toUpperCase() + x.substring(1)).collect(Collectors.toList());
}
/* Commented out, uncomment if you need to fail on erroneous type
else {
  throw new Exception("Cannot capitalize something that is not a string")
}*/`, field, field, field, field, field, field, field)),
				Description: getStringPointer(fmt.Sprintf("Capitalize field '%s'", field)),
				Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				If:          getStringPointer(getIfFieldDefined(field)),
			})
		}

	case "convert":
		keys, values := getHashAttributeKeyValue(attr)

		for i := range keys {
			if Contains([]string{"boolean", "integer_eu", "float_eu"}, values[i]) {
				log.Warn().Msgf("Mutate Convert to type '%s' semantics may be different in Elasticsearch Convert Processor", values[i])
			}
			ingestProcessors = append(ingestProcessors, ConvertProcessor{
				Description: getStringPointer(fmt.Sprintf("Convert field '%s' to '%s'", keys[i], values[i])),
				Field:       keys[i],
				Type:        LogstashConvertToConvertProcessorType[values[i]],
				Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
			})
		}

	// It is a common field
	case "rename":

		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			targetField := toElasticPipelineSelector(values[i])
			ingestProcessors = append(ingestProcessors,
				RenameProcessor{
					Description: getStringPointer(fmt.Sprintf("Rename field '%s' to '%s'", keys[i], targetField)),
					TargetField: targetField,
					Field:       keys[i],
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}
	case "copy":
		keys, values := getHashAttributeKeyValue(attr)

		for i := range keys {

			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					Description: getStringPointer(fmt.Sprintf("Copy value of field '%s' in field '%s'", keys[i], values[i])),
					CopyFrom:    keys[i],
					Field:       values[i],
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}
	case "uppercase", "lowercase":
		// Assuming only the field
		switch tAttributes := attr.(type) {
		case ast.ArrayAttribute:
			for _, el := range tAttributes.Attributes {
				field := getStringAttributeString(el)
				ingestProcessors = append(ingestProcessors,
					CaseProcessor{
						Type:        attr.Name(), // either uppercase or lowercase
						Description: getStringPointer(fmt.Sprintf("'%s' field '%s'", attr.Name(), field)),
						Field:       getStringAttributeString(el),
						Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
					})
			}

		default: // uppercase/lowercase require an Array
			log.Printf("Mutate filter attribute '%s' not supported", attr.Name())
		}

	case "gsub":
		// Assuming only the field
		switch tAttributes := attr.(type) {
		case ast.ArrayAttribute:

			gsubexpression := getArrayStringAttributes(tAttributes)

			if len(gsubexpression)%3 != 0 {
				log.Printf("Gsub expects triplets of (field, pattern, replacement), while %d params are given", len(gsubexpression))
			}

			for i := 0; i < len(gsubexpression); i += 3 {
				ingestProcessors = append(ingestProcessors,
					GsubProcessor{
						Description: getStringPointer(fmt.Sprintf("Field '%s': substitute '%s' with '%s'", gsubexpression[i], gsubexpression[i+1], gsubexpression[i+2])),
						Field:       gsubexpression[i],
						Pattern:     gsubexpression[i+1],
						Replacement: gsubexpression[i+2],
						Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
					})
			}
		}

	case "join":

		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				JoinProcessor{
					Description:   getStringPointer(fmt.Sprintf("Join array '%s' with separator '%s'", keys[i], values[i])),
					Separator:     values[i],
					Field:         keys[i],
					IgnoreFailure: false,
					Tag:           fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}
	case "split":
		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				SplitProcessor{
					Description: getStringPointer(fmt.Sprintf("Split field '%s' with separator '%s'", keys[i], values[i])),
					Separator:   values[i],
					Field:       keys[i],
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}

	case "strip":
		to_trim_fields := getArrayStringAttributes(attr)
		for _, field := range to_trim_fields {

			elasticField := toElasticPipelineSelector(field)

			ingestProcessors = append(ingestProcessors,
				TrimProcessor{
					Description: getStringPointer(fmt.Sprintf("Trim field '%s'", elasticField)),
					Field:       elasticField,
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				},
			)

		}

	case "coerce":
		keys, values := getHashAttributeKeyValue(attr)

		// newCondition := ""

		for i := range keys {
			field_is_null := getIfFieldIsDefinedAndEqualsValue(keys[i], nil)
			// if constraintTranspiled == nil {
			// 	newCondition = field_is_null
			// } else {
			// 	newCondition = field_is_null + " && (" + *constraintTranspiled + ")"
			// }
			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					Description: getStringPointer(fmt.Sprintf("Set field '%s' to value '%s' if null", keys[i], values[i])),
					If:          getStringPointer(field_is_null),
					Value:       values[i],
					Field:       keys[i],
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}

	case "replace":
		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					Description: getStringPointer(fmt.Sprintf("Replace/Create field '%s' with value '%s'", keys[i], values[i])),
					Value:       values[i],
					Field:       keys[i],
					Override:    true,
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}

	case "update":
		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					Description: getStringPointer(fmt.Sprintf("Replace/Create field '%s' with value '%s'", keys[i], values[i])),
					Value:       values[i],
					Field:       keys[i],
					Override:    true,
					Tag:         fmt.Sprintf("%s-%d", id, len(ingestProcessors)),
				})
		}

	default:
		log.Printf("Mutate of type '%s' not supported", attr.Name())

	}
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

const (
	ScriptContext = iota
	ProcessorContext
)

func toElasticPipelineSelectorExpression(s string, context int) string {
	newS := s
	// Strings of type foo_%{[afield]}
	field_finder := regexp.MustCompile(`\%\{([^\}]+)\}`)
	startWithSelector := true
	firstRun := true
	for _, m := range field_finder.FindAll([]byte(s), -1) {

		log.Info().Msg(toElasticPipelineSelector(string(m[2 : len(m)-1])))
		if context == ProcessorContext {
			newS = strings.Replace(newS, string(m), "{{{"+toElasticPipelineSelector(string(m[2:len(m)-1]))+"}}}", 1)
		} else if context == ScriptContext {
			var fieldValue = toElasticPipelineSelectorCondition(toElasticPipelineSelector(string(m[2 : len(m)-1])))

			pos := field_finder.FindStringIndex(newS)
			if firstRun && pos[0] != 0 {
				firstRun = false
				startWithSelector = false
			}

			if pos[0] > 0 {
				fieldValue = "' + " + fieldValue
			}
			if pos[1] < len(newS)-1 {
				fieldValue = fieldValue + " + '"
			}
			newS = strings.Replace(newS, string(m), fieldValue, 1)
		}
	}

	if context == ScriptContext && !startWithSelector {
		newS = "'" + newS
	}

	return newS
}

func getUniqueOnFailureAddField(id string) string {
	return "_TRANSPILER." + id
}

func getTranspilerOnFailureProcessor(id string) IngestProcessor {
	return SetProcessor{
		Field: getUniqueOnFailureAddField(id),
		Value: "Processor {{ _ingest.on_failure_processor_type }} with tag {{ _ingest.on_failure_processor_tag }} in pipeline {{ _ingest.on_failure_pipeline }} failed with message {{ _ingest.on_failure_message }}",
		Tag:   getUniqueOnFailureAddField(id),
	}
}

func getIfFieldDefined(field string) string {
	// newField := strings.Replace(field, ".", "?.", strings.Count(field, ".")-1)
	splittedField := strings.Split(field, ".")
	newFieldButLastMaybe := "ctx"
	newFieldButLast := "ctx"

	for _, sf := range splittedField[:len(splittedField)-1] {
		newFieldButLast = newFieldButLast + "." + sf
		newFieldButLastMaybe = newFieldButLastMaybe + "?." + sf
	}

	return fmt.Sprintf("%s.containsKey('%s')", newFieldButLastMaybe, splittedField[len(splittedField)-1])
}

func getIfFieldIsDefinedAndEqualsValue(field string, val *string) string {
	splittedField := strings.Split(field, ".")
	newFieldButLastMaybe := "ctx"

	for _, sf := range splittedField[:len(splittedField)-1] {
		newFieldButLastMaybe = newFieldButLastMaybe + "?." + sf
	}

	valString := ""
	if val == nil {
		valString = "null"
	} else {
		valString = fmt.Sprintf("\"%s\"", *val)
	}

	return fmt.Sprintf("%s.containsKey('%s') && ctx.%s == %s", newFieldButLastMaybe, splittedField[len(splittedField)-1], field, valString)
}

// processorsToPipeline convert a list of processors to a pipeline with name `name` if the length of the list execeeds the `threshold`
// Otherwise it returns the list as-is
func processorsToPipeline(ingestProcessors []IngestProcessor, name string, threshold int) []IngestProcessor {
	if len(ingestProcessors) <= threshold {
		return ingestProcessors
	} else {
		return []IngestProcessor{
			PipelineProcessor{
				Pipeline: IngestPipeline{
					Name:                name,
					Processors:          ingestProcessors,
					OnFailureProcessors: nil,
				},
				Name: name,
			},
		}
	}
}

func DealWithCommonAttributes(plugin ast.Plugin, constraintTranspiled *string, id string, threshold int) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}

	onSuccessCondition := getStringPointer(fmt.Sprintf("!%s", getIfFieldDefined(getUniqueOnFailureAddField(id))))

	for _, attr := range plugin.Attributes {
		if !Contains(CommonAttributes, attr.Name()) {
			continue // Ignore not common attributes
		}
		switch attr.Name() {
		// It is a common field
		case "add_field":
			keys, values := getHashAttributeKeyValue(attr)

			for i := range keys {

				value := toElasticPipelineSelectorExpression(values[i], ProcessorContext)

				ingestProcessors = append(ingestProcessors,
					SetProcessor{
						Description: getStringPointer(fmt.Sprintf("On Success of %s, add field '%s' with value '%s'", id, keys[i], value)),
						Value:       value,
						Field:       keys[i],
						Tag:         fmt.Sprintf("%s-%d-onSucc", id, len(ingestProcessors)),
					})
			}
		case "remove_field":
			ingestProcessors = append(ingestProcessors,
				RemoveProcessor{
					Field: getStringAttributeString(attr),
					Tag:   fmt.Sprintf("%s-%d-onSucc", id, len(ingestProcessors)),
				},
			)
		case "add_tag":
			ingestProcessors = append(ingestProcessors,
				AppendProcessor{
					Tag:   fmt.Sprintf("%s-%d-onSucc", id, len(ingestProcessors)),
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

	ingestProcessors = processorsToPipeline(ingestProcessors, fmt.Sprintf("%s-on-success", id), 1)

	for i := range ingestProcessors {
		log.Info().Msgf("[%d] = %s %s", i, constraintTranspiled, onSuccessCondition)
		ingestProcessors[i] = ingestProcessors[i].SetIf(constraintTranspiled, false)
		ingestProcessors[i] = ingestProcessors[i].SetIf(onSuccessCondition, true)
	}

	return ingestProcessors

}

func DealWithDropV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	proc := DropProcessor{
		Tag: id,
	}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "percentage":
			switch tattr := attr.(type) {
			case ast.NumberAttribute:
				value := int(tattr.Value())
				log.Info().Msgf("Percentage %d", value)
				// TODO Add seed?
				// TODO Make sure that random number is generated only on need
				proc = proc.SetIf(getStringPointer(fmt.Sprintf("new Random().nextInt(100) < %d", value)), true).(DropProcessor)
			}
		// Add if condition

		default:
			log.Printf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}

	ingestProcessors = append(ingestProcessors, proc)

	return ingestProcessors, onFailureProcessors
}

func DealWithDateV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	proc := DateProcessor{
		Tag: id,
	}

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id)
		case "target":
			proc.TargetField = getStringPointer(getStringAttributeString(attr))
		case "locale":
			log.Printf("Date filter is using %s %s. Please make sure it corresponds to Ingest Pipeline's one", attr.Name(), getStringAttributeString(attr))
			proc.Locale = getStringPointer(getStringAttributeString(attr))
		case "timezone":
			log.Printf("Date filter is using %s %s. Please make sure it corresponds to Ingest Pipeline's one", attr.Name(), getStringAttributeString(attr))
			proc.Timezone = getStringPointer(getStringAttributeString(attr))

		case "match":
			matchArray := getArrayStringAttributes(attr)
			proc.Field = matchArray[0]
			proc.Formats = matchArray[1:]

		default:
			log.Printf("Attribute '%s' is currently not supported", attr.Name())

		}
	}
	// Add _kv_filter_error
	if len(onFailureProcessors) == 0 {
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_data_parse_failure", ast.DoubleQuoted)), id)
	}

	ingestProcessors = append(ingestProcessors, proc)

	return ingestProcessors, onFailureProcessors
}

func DealWithGeoIPV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailurePorcessors := []IngestProcessor{}

	gp := GeoIPProcessor{
		Tag: id,
	}

	// TODO Add all properties
	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "fields":
			properties := getArrayStringAttributes(attr)
			gp.Properties = &properties

		case "source":
			gp.Field = getStringAttributeString(attr)

		case "target":
			gp.TargetField = getStringPointer(getStringAttributeString(attr))

		case "tag_on_failure":
			onFailurePorcessors = DealWithTagOnFailure(attr, id)

		default:
			log.Printf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}
	// Add _grok_parse_failure
	if len(gp.OnFailure) == 0 {
		onFailurePorcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_geoip_lookup_failure", ast.DoubleQuoted)), id)
	}

	ingestProcessors = append(ingestProcessors, gp)
	return ingestProcessors, onFailurePorcessors
}

func DealWithGrokV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailurePorcessors := []IngestProcessor{}

	gp := GrokProcessor{
		Tag: id,
	}

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
			onFailurePorcessors = DealWithTagOnFailure(attr, id)
		default:
			log.Printf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}
	// Add _grok_parse_failure
	if len(gp.OnFailure) == 0 {
		onFailurePorcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_grok_parse_failure", ast.DoubleQuoted)), id)
	}

	ingestProcessors = append(ingestProcessors, gp)
	return ingestProcessors, onFailurePorcessors
}

// CIDR Plugin of Logstash
// CIDR is only available in a script and there is no processor that can substitute it as of now
// Given the current TemplateMethod Pattern and how we deal in a generic way with onSuccessProcessors
// the implementation generates (overcomplicated, but semantically similar) processors:
//   - 1. A script fails (throws an Exception) if no address matches the CIDR expressions provided
//   - 2. The onFailureProcessor adds a field _TRANSPILER.<id>
//   - 3. If the field is not present the onSuccessProcessors are executed
func DealWithCidrV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessor := []IngestProcessor{}
	addresses := []string{}
	networks := []string{}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "address":
			addresses = getArrayStringAttributes(attr)
		case "network":
			networks = getArrayStringAttributes(attr)
		}
	}

	var b bytes.Buffer

	b.WriteString(fmt.Sprintf(`def cidrs = new CIDR[%d];`, len(networks)))
	for i, c := range networks {
		b.WriteString(fmt.Sprintf(`cidrs[%d] = new CIDR('%s');`, i, c))
	}
	elastic_addresses := []string{}
	for _, a := range addresses {
		elastic_addresses = append(elastic_addresses, toElasticPipelineSelectorExpression(a, ScriptContext))
	}

	b.WriteString(
		fmt.Sprintf(`
for (c in cidrs) {
	for (a in %s) {
		if (c.contains(a)) {
			return;
		}
	}
}
throw new Exception("Could not find CIDR value");
`, elastic_addresses))

	ingestProcessors = append(ingestProcessors, ScriptProcessor{
		Source: getStringPointer(b.String()),
		Tag:    id,
	})

	return ingestProcessors, onFailureProcessor
}

func DealWithMutateV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id)
		}
	}

	// Add default value for Tag_on_failure
	if len(onFailureProcessors) == 0 {
		onFailureProcessors = append(onFailureProcessors, DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_mutate_error", ast.DoubleQuoted)), id)...)
	}

	// Extract the attributes
	for _, attr := range plugin.Attributes {
		if attr.Name() == "tag_on_failure" {
			continue
		}
		ingestProcessors = DealWithMutateAttributes(attr, ingestProcessors, id)
	}

	log.Info().Msgf("Length: %d", len(ingestProcessors))

	return ingestProcessors, onFailureProcessors
}

// Generic function that deal with a single Logstash Plugin by using Template Method Pattern
func DealWithPlugin(section string, plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	id := getProcessorID(plugin)
	log.Info().Msgf("Plugin ID is %s", id)

	DealWithPluginFunction, ok := transpilerV2[section][plugin.Name()]
	if !ok {
		log.Warn().Msgf("There is no handler for the %s plugin of type '%s' (with id '%s')\nReturning an empty processors list", section, plugin.Name(), id)
		return []IngestProcessor{}
	}

	constraintTranspiled := transpileConstraint(constraint)

	onSuccessProcessors := DealWithCommonAttributes(plugin, constraintTranspiled, id, 1)

	noncommonattrs := []ast.Attribute{}

	for _, pa := range plugin.Attributes {
		if !Contains(CommonAttributes, pa.Name()) {
			noncommonattrs = append(noncommonattrs, pa)
		}
	}

	// PA is a Plugin with only Plugin-Specific attributes (no id, no add_field etc.)
	pa := ast.NewPlugin(plugin.Name(), noncommonattrs...)

	ingestProcessors, onFailureProcessors := DealWithPluginFunction(pa, id)

	// On Success Processors should be executed only when no Failure happened
	if len(onSuccessProcessors) > 0 {
		onFailureProcessors = append(onFailureProcessors, getTranspilerOnFailureProcessor(id))
	}

	// Mutate filter can only contain common attributes (e.g., add_field)
	// In this case we are always in the "OnSuccess" case, thus we can simplify the condition
	if len(ingestProcessors) == 0 { // There are only unsupported or the common attributes
		for i := range onSuccessProcessors {
			onSuccessProcessors[i] = onSuccessProcessors[i].SetIf(constraintTranspiled, false)
		}
	}

	// To keep a similar semantics as Logstash we create an additional pipeline
	// If we have more than one Processor that has been created by the plugin-specific function
	ingestProcessors = processorsToPipeline(ingestProcessors, id, 1)

	for i := range ingestProcessors {
		ingestProcessors[i] = ingestProcessors[i].SetIf(constraintTranspiled, true)
		ingestProcessors[i] = ingestProcessors[i].SetOnFailure(onFailureProcessors)
	}

	ingestProcessors = append(ingestProcessors, onSuccessProcessors...)

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

func DealWithKVV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	kv := KVProcessor{
		Tag:        id,
		FieldSplit: " ",       // Default value in Logstash
		Field:      "message", // Default value in Logstash
	}

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id)
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
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_kv_filter_error", ast.DoubleQuoted)), id)
	}
	ingestProcessors = append(ingestProcessors, kv)

	return ingestProcessors, onFailureProcessors
}

func DealWithDissectV2(plugin ast.Plugin, id string) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	proc := DissectProcessor{
		Tag: id,
	}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id)
		case "mapping":
			keys, values := getHashAttributeKeyValue(attr)
			if len(keys) != 1 {
				log.Printf("[Pos %s][Plugin %s] Attribute '%s' only one map is supported. Consider splitting the original in two dissect filters", plugin.Pos(), plugin.Name(), attr.Name())
			}
			proc.Field = keys[0]
			proc.Pattern = values[0]
		default:
			log.Printf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}
	// Add dissect failure default tag
	if len(proc.OnFailure) == 0 {
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_dissectfailure", ast.DoubleQuoted)), id)
	}

	ingestProcessors = append(ingestProcessors, proc)
	return ingestProcessors, onFailureProcessors
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
		Name:                "main-pipeline",
		Description:         "",
		Processors:          []IngestProcessor{},
		OnFailureProcessors: nil,
	}
	// apply func returns an ApplyPluginsFuncCondition object depending on the section
	applyFunc := func(section string) ApplyPluginsFuncCondition {
		return func(c *Cursor, constraint Constraints) {
			// fmt.Printf("Plugin: %s, Pos: %s\n", c.Plugin().Name(), c.Plugin().Pos())

			// f, ok := transpiler["filter"][c.Plugin().Name()]
			// if !ok {
			// 	log.Printf("There is no handler for the plugin %s\n", c.Plugin().Name())
			// 	f = DealWithMissingTranspiler
			// }
			// ip.Processors = append(ip.Processors, f(*c.Plugin(), constraint)...)

			ip.Processors = append(ip.Processors, DealWithPlugin(section, *c.Plugin(), constraint)...)

			plugin_names = append(plugin_names, c.Plugin().Name())
		}
	}

	for _, f := range c.Filter {
		MyIteration(f.BranchOrPlugins, NewConstraintLiteral(), applyFunc("filter"))
	}

	ips := getAllIngestPipeline(ip)

	fmt.Printf("{")
	for i, pipeline := range ips {
		fmt.Printf("\"%s\": %s ", pipeline.Name, pipeline)
		if i < len(ips)-1 {
			fmt.Printf(",")
		}
	}
	fmt.Printf("}")

}

func getAllIngestPipeline(main IngestPipeline) []IngestPipeline {
	ingestPipelines := []IngestPipeline{main}

	processors := main.Processors
	processors = append(processors, main.OnFailureProcessors...)

	for _, ip := range processors {
		switch typedIp := ip.(type) {
		case PipelineProcessor:
			ingestPipelines = append(ingestPipelines, getAllIngestPipeline(typedIp.Pipeline)...)
		}
	}
	return ingestPipelines
}

package transpile

import (
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.elastic.co/ecszerolog"

	"bytes"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"reflect"

	config "github.com/herrBez/baffo"
	"github.com/herrBez/baffo/internal/format"

	ast "github.com/herrBez/baffo/ast"

	"math/rand"
)

const TRANSPILER_PREFIX = "_TRANSPILER"

type Transpile struct {
	threshold                 int
	log_level                 zerolog.Level
	deal_with_error_locally   bool
	addDefaultGlobalOnFailure bool
	fidelity                  bool
}

func New(threshold int, log_level string, deal_with_error_locally bool, addDefaultGlobalOnFailure bool, fidelity bool) Transpile {
	return Transpile{
		threshold:                 threshold,
		log_level:                 level[strings.ToLower(log_level)],
		deal_with_error_locally:   deal_with_error_locally,
		addDefaultGlobalOnFailure: addDefaultGlobalOnFailure,
		fidelity:                  fidelity,
	}
}

var level = map[string]zerolog.Level{
	"info":        zerolog.InfoLevel,
	"information": zerolog.InfoLevel,
	"warn":        zerolog.WarnLevel,
	"warning":     zerolog.WarnLevel,
	"debug":       zerolog.DebugLevel,
	"error":       zerolog.ErrorLevel,
}

func (t Transpile) Run(args []string) error {
	logger := ecszerolog.New(os.Stderr)
	log.Logger = logger
	zerolog.SetGlobalLevel(t.log_level)

	var result *multierror.Error
	ips := []IngestPipeline{}

	for _, filename := range args {
		stat, err := os.Stat(filename)
		if err != nil {
			result = multierror.Append(result, errors.Errorf("%s: %v", filename, err))
			continue
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

			ips = append(ips, t.buildIngestPipeline(filename, tree)...)

		}
	}

	printPipeline(ips)

	if result != nil {
		result.ErrorFormat = format.MultiErr
		return result
	}

	return nil
}

type TranspileProcessor func(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor)

var transpiler = map[string]map[string]TranspileProcessor{
	"input": {},
	"filter": {
		"mutate":     DealWithMutate,
		"drop":       DealWithDrop,
		"date":       DealWithDate,
		"dissect":    DealWithDissect,
		"grok":       DealWithGrok,
		"kv":         DealWithKV,
		"cidr":       DealWithCidr,
		"geoip":      DealWithGeoIP,
		"translate":  DealWithTranslate,
		"useragent":  DealWithUserAgent,
		"urldecode":  DealWithURLDecode,
		"prune":      DealWithPrune,
		"syslog_pri": DealWithSyslogPri,
		"csv":        DealWithCSV,
		"json":       DealWithJSON,
		// "truncate":   DealWithTruncate,
	},
	"output": {
		"elasticsearch": DealWithOutputElasticsearch,
		"pipeline":      DealWithOutputPipeline,
	},
}

func transpileBoolExpression(bo ast.BooleanOperator) string {
	log.Debug().Msg("&&")
	switch bo.Op {
	case ast.NoOperator:
		return ""
	case ast.And:
		return ` && `
	case ast.Or:
		return ` || `
	default:
		fmt.Println("Unknown operator")
		os.Exit(1)

		//	case ast.Xor: ""
		// case ast.Nand:
	}

	return ""
}

func returnSubFields(sel string) []string {
	if sel[0] == '[' && sel[len(sel)-1] == ']' {
		return strings.Split(sel[1:len(sel)-1], "][")
	} else {
		return []string{sel}
	}
}

// This function converts a selector (e.g., [foo][bar]) to its Painless correspondent.
// We have two flavors of conversions:
//   - Nullable --> We return a nullable expression like ctx?.foo?.bar
//   - Nonnullable --> We return a non-nullable expression like ctx.foo.bar
//
// Special care should be put for special symbols like '@'. They don't allow
// to be used with dot notation.
// In principle we could drastically simplify the function by avoiding dot notation,
// but we preferred to keep it because it feels more natural for Painless users.
func toElasticPipelineSelectorWithNullable(sel string, nullable bool) string {
	// if the selector contains square brackets we need to convert them
	if sel[0] == '[' && sel[len(sel)-1] == ']' {
		parts := strings.Split(sel[1:len(sel)-1], "][")
		elasticSelector := "ctx"
		currentPath := ""
		for _, part := range parts {
			// e.g., field metadata
			if strings.HasPrefix(part, "@") {
				elasticSelector += ".getOrDefault('@metadata', null)"
				currentPath += fmt.Sprintf("['%s']", part)
			} else {
				elasticSelector += "?." + part
				currentPath += fmt.Sprintf(".%s", part)
			}
		}

		if nullable {
			return elasticSelector
		} else {
			return "ctx" + currentPath
		}
	} else {
		if strings.Contains(sel, "@") || strings.Contains(sel, ".") {
			if nullable {
				return fmt.Sprintf("ctx.getOrDefault('%s', null)", sel)
			} else {
				return fmt.Sprintf("ctx['%s']", sel)
			}
		} else {
			if nullable {
				return "ctx?." + sel
			} else {
				return "ctx." + sel
			}
		}
	}
}

// When using Selectors in conditions we need to check whether they are null or not and
// and afterward can use them
func toElasticPipelineSelectorCondition(sel string) string {
	return toElasticPipelineSelectorWithNullable(sel, true) + " != null && " + toElasticPipelineSelectorWithNullable(sel, false)
}

// This function should be used when translating expressions like set processors value
// where {{ @metadata.foo }} is allowed
func toElasticPipelineSelector(sel string) string {
	if sel[0] == '[' && sel[len(sel)-1] == ']' {
		return strings.ReplaceAll(sel[1:len(sel)-1], "][", ".")
	}
	return sel
}

func transpileRvalue(expr ast.Node) string {
	log.Debug().Msgf("%s %s", expr, reflect.TypeOf(expr))
	switch texpr := expr.(type) {
	case ast.StringAttribute:
		return "\"" + texpr.Value() + "\""
	case ast.Selector:
		return toElasticPipelineSelectorWithNullable(texpr.String(), true)

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

	return ""

}

func transpileCondition(c ast.Condition) string {
	var output string

	for _, expr := range c.Expression {

		log.Debug().Msgf("Here %s %s\n", expr, reflect.TypeOf(expr))
		switch texpr := expr.(type) {

		case ast.ConditionExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + bOpComparator + transpileCondition(texpr.Condition)
		case ast.NegativeConditionExpression:
			operator_converted := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + "!" + operator_converted + "(" + transpileCondition(texpr.Condition) + ")"

		case ast.NegativeSelectorExpression:
			operator_converted := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + "" + operator_converted + toElasticPipelineSelectorWithNullable(texpr.Selector.String(), true) + " == null"

		case ast.InExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + bOpComparator + transpileRvalue(texpr.RValue) + ".contains(" + transpileRvalue(texpr.LValue) + ")"

		case ast.NotInExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			output = output + "!" + bOpComparator + transpileRvalue(texpr.RValue) + ".contains(" + transpileRvalue(texpr.LValue) + ")"

		case ast.CompareExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			val := transpileRvalue(texpr.LValue)
			// Selector is a special case that we treat differently
			switch x := texpr.LValue.(type) {
			case ast.Selector:
				val = toElasticPipelineSelectorWithNullable(x.String(), true) + " != null && " + toElasticPipelineSelectorWithNullable(x.String(), false)
			}

			if bOpComparator != "" {
				output = output + bOpComparator + "(" + val + " " + texpr.CompareOperator.String() + " " + transpileRvalue(texpr.RValue) + ")"
			} else {
				output = output + "(" + val + " " + texpr.CompareOperator.String() + " " + transpileRvalue(texpr.RValue) + ")"
			}

		case ast.RegexpExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())
			val := ""
			switch x := texpr.RValue.(type) {
			case ast.StringAttribute:
				val = x.Value()
			case ast.Regexp:
				val = x.Regexp
			default:
				log.Panic().Msgf("Unexpected Case %T", x)
			}
			convertedSelector := ""
			switch x := texpr.LValue.(type) {
			case ast.Selector:
				convertedSelector = toElasticPipelineSelectorCondition(x.String())
			default:
				log.Panic().Msgf("Unexpected Case %T", x)
			}
			output = output + bOpComparator + convertedSelector + " =~ /" + val + "/"

		case ast.RvalueExpression:
			bOpComparator := transpileBoolExpression(texpr.BoolExpression.BoolOperator())

			val := transpileRvalue(texpr.RValue)

			switch x := texpr.RValue.(type) {
			case ast.Selector:
				val = toElasticPipelineSelectorWithNullable(x.String(), true) + " != null"
			}

			if bOpComparator != "" {
				output = output + bOpComparator + "(" + val + ")"
			} else { // No Operator is provided
				output = output + "(" + val + ")"
			}

		default:
			log.Warn().Msgf("Cannot convert %s %s", reflect.TypeOf(texpr), texpr)
		}
	}
	return output
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
				Source: pointer(
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
			}.WithIf(pointer(getIfFieldDefined(field)), false).
				WithDescription(fmt.Sprintf("Capitalize field '%s'", field)))
		}

	case "convert":
		keys, values := getHashAttributeKeyValue(attr)

		for i := range keys {
			if Contains([]string{"boolean", "integer_eu", "float_eu"}, values[i]) {
				log.Warn().Msgf("Mutate Convert to type '%s' semantics may be different in Elasticsearch Convert Processor", values[i])
			}
			ingestProcessors = append(ingestProcessors, ConvertProcessor{
				Field: keys[i],
				Type:  LogstashConvertToConvertProcessorType[values[i]],
			}.WithDescription(fmt.Sprintf("Convert field '%s' to '%s'", keys[i], values[i])))
		}

	// It is a common field
	case "rename":

		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			targetField := toElasticPipelineSelector(values[i])
			ingestProcessors = append(ingestProcessors,
				RenameProcessor{
					TargetField: targetField,
					Field:       keys[i],
				}.WithDescription(fmt.Sprintf("Rename field '%s' to '%s'", keys[i], targetField)))
		}
	case "copy":
		keys, values := getHashAttributeKeyValue(attr)

		for i := range keys {

			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					CopyFrom: keys[i],
					Field:    values[i],
				}.WithDescription(fmt.Sprintf("Copy value of field '%s' in field '%s'", keys[i], values[i])))
		}
	case "uppercase", "lowercase":
		// Assuming only the field
		switch tAttributes := attr.(type) {
		case ast.ArrayAttribute:
			for _, el := range tAttributes.Attributes {
				field := getStringAttributeString(el)
				ingestProcessors = append(ingestProcessors,
					CaseProcessor{
						Type:  attr.Name(), // either uppercase or lowercase
						Field: toElasticPipelineSelector(field),
					}.WithDescription(fmt.Sprintf("'%s' field '%s'", attr.Name(), field)))
			}

		default: // uppercase/lowercase require an Array
			log.Warn().Msgf("Mutate filter attribute '%s' not supported", attr.Name())
		}

	case "gsub":
		// Assuming only the field
		switch tAttributes := attr.(type) {
		case ast.ArrayAttribute:

			gsubexpression := getArrayStringAttributes(tAttributes)

			if len(gsubexpression)%3 != 0 {
				log.Warn().Msgf("Gsub expects triplets of (field, pattern, replacement), while %d params are given", len(gsubexpression))
			}

			for i := 0; i < len(gsubexpression); i += 3 {
				ingestProcessors = append(ingestProcessors,
					GsubProcessor{
						Field:       toElasticPipelineSelector(gsubexpression[i]),
						Pattern:     gsubexpression[i+1],
						Replacement: gsubexpression[i+2],
					}.WithDescription(fmt.Sprintf("Field '%s': substitute '%s' with '%s'", gsubexpression[i], gsubexpression[i+1], gsubexpression[i+2])))
			}
		}

	case "join":

		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				JoinProcessor{
					Separator:     values[i],
					Field:         keys[i],
					IgnoreFailure: false,
				}.WithDescription(fmt.Sprintf("Join array '%s' with separator '%s'", keys[i], values[i])))
		}
	case "split":
		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				SplitProcessor{
					Separator: values[i],
					Field:     keys[i],
				}.WithDescription(fmt.Sprintf("Split array '%s' with separator '%s'", keys[i], values[i])))
		}

	case "strip":
		to_trim_fields := getArrayStringAttributes(attr)
		for _, field := range to_trim_fields {

			elasticField := toElasticPipelineSelector(field)

			ingestProcessors = append(ingestProcessors,
				TrimProcessor{
					Field: elasticField,
				}.WithDescription(fmt.Sprintf("Trim field '%s'", elasticField)),
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
					Value: values[i],
					Field: keys[i],
				}.WithIf(pointer(field_is_null), true).
					WithDescription(fmt.Sprintf("Set field '%s' to value '%s' if null", keys[i], values[i])),
			)
		}

	case "replace":
		keys, values := getHashAttributeKeyValue(attr)
		for i := range keys {
			val, _ := toElasticPipelineSelectorExpression(values[i], ProcessorContext)

			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					Value:    val,
					Field:    keys[i],
					Override: true,
				}.WithDescription(fmt.Sprintf("Replace/Create field '%s' with value '%s'", keys[i], values[i])))
		}

	case "update":
		keys, values := getHashAttributeKeyValueUntyped(attr)
		for i := range keys {
			ingestProcessors = append(ingestProcessors,
				SetProcessor{
					Value:    values[i],
					Field:    keys[i],
					Override: true,
				}.WithDescription(fmt.Sprintf("Replace/Create field '%s' with value '%s'", keys[i], values[i])))
		}

	default:
		log.Warn().Msgf("Mutate of type '%s' not supported", attr.Name())

	}

	// Add Tags to all created processors
	for i := range ingestProcessors {
		ingestProcessors[i] = ingestProcessors[i].WithTag(fmt.Sprintf("%s-%d", id, len(ingestProcessors)))
	}

	return ingestProcessors
}

func DealWithTagOnFailure(attr ast.Attribute, id string, t Transpile) []IngestProcessor {
	// We deliberately ignore the tag_on_failure when the option is deactivate
	// The assumption is that a global processor will deal with this
	// This may potentially break the semantic compatibility (because the tag could be use in other places)
	// but it is the "elasticsearch" pipeline way of dealing with errors
	if !t.deal_with_error_locally {
		return []IngestProcessor{}
	}
	return []IngestProcessor{AppendProcessor{
		Field: "tags",
		Value: getArrayStringAttributes(attr),
	}.WithDescription("Append Tag on Failure").WithTag(fmt.Sprintf("append-tag-%s", id))}
}

var CommonAttributes = []string{"add_field", "remove_field", "add_tag", "id", "enable_metric", "periodic_flush", "remove_tag"}

const (
	ScriptContext = iota
	ProcessorContext
	DissectContext
	GrokContext
)

// Function that given an expression like "foo_%{[selector]}" returns the equivalent Elastic expression
// "foo_{{selector}}" and boolean to indicate whether the string depends on input or not
func toElasticPipelineSelectorExpression(s string, context int) (string, bool) {
	newS := s
	// Strings of type foo_%{[afield]}
	field_finder := regexp.MustCompile(`\%\{([^\}]+)\}`)
	startWithSelector := true
	firstRun := true
	matchFound := false
	for _, m := range field_finder.FindAll([]byte(s), -1) {
		matchFound = true
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
		} else if context == DissectContext {
			// Deal With the Optional Prefix Modifer (i.e., +, ?, *)
			dissectPrefixModifierFinder := regexp.MustCompile(`\%\{(\+|\?|\*)?(.*)\}`)

			rawPrefix := dissectPrefixModifierFinder.FindSubmatch(m)

			prefix := string(rawPrefix[1])
			field := string(rawPrefix[2])
			suffix := ""

			// Deal with the Optional Dissect Modifiers
			dissectSuffixModifierFinder := regexp.MustCompile(`(.*)(\->|/\d)+$`)

			rawSuffix := dissectSuffixModifierFinder.FindSubmatch(rawPrefix[2])

			if len(rawSuffix) > 0 {
				field = string(rawSuffix[1])
				suffix = string(rawSuffix[2])
			}

			newS = strings.Replace(newS, string(m), "%{"+prefix+toElasticPipelineSelector(string(field)[0:len(field)])+suffix+"}", 1)

		} else if context == GrokContext {
			// We can assume there are no other closing parenthesis
			// TODO: Check whether the subpatterns should be ([^:\}]+)
			grokPartsFinder := regexp.MustCompile(`\%\{([^:]+)(:[^:]+)?(:[^:]+)?\}`)

			rawGrokParts := grokPartsFinder.FindSubmatch(m)

			pattern := string(m)
			fieldName := ""
			convert := ""

			pattern = string(rawGrokParts[1])
			if len(rawGrokParts[2]) > 0 {
				fieldName = ":" + toElasticPipelineSelector(string(rawGrokParts[2])[1:])
			}
			if len(rawGrokParts[3]) > 0 {
				convert = string(rawGrokParts[3]) // TODO: Check if this is necessary
			}

			newS = strings.Replace(newS, string(m), "%{"+pattern+fieldName+convert+"}", 1)

		}
	}

	if context == ScriptContext && !startWithSelector {
		newS = "'" + newS
	}

	return newS, matchFound
}

func getUniqueOnFailureAddField(id string) string {
	return fmt.Sprintf("%s.%s", TRANSPILER_PREFIX, id)
}

func getTranspilerOnFailureProcessor(id string) IngestProcessor {
	return SetProcessor{
		Field: getUniqueOnFailureAddField(id),
		Value: "Processor {{ _ingest.on_failure_processor_type }} with tag {{ _ingest.on_failure_processor_tag }} in pipeline {{ _ingest.on_failure_pipeline }} failed with message {{ _ingest.on_failure_message }}",
	}.WithTag(getUniqueOnFailureAddField(id))
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

	if newFieldButLastMaybe == "ctx" {
		return fmt.Sprintf("ctx.containsKey('%s')", splittedField[len(splittedField)-1])
	} else {
		return fmt.Sprintf("%s != null && %s.containsKey('%s')", newFieldButLastMaybe, newFieldButLastMaybe, splittedField[len(splittedField)-1])
	}
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

func getIfFieldIsDefinedAndEmpty(field string) string {
	splittedField := strings.Split(field, ".")
	newFieldButLastMaybe := "ctx"

	for _, sf := range splittedField[:len(splittedField)-1] {
		newFieldButLastMaybe = newFieldButLastMaybe + "?." + sf
	}
	return fmt.Sprintf("%s.containsKey('%s') && ctx.%s.size() == 0", newFieldButLastMaybe, splittedField[len(splittedField)-1], field)
}

// processorsToPipeline convert a list of processors to a pipeline with name `name` if the length of the list execeeds the `threshold`
// Otherwise it returns the list as-is
func processorsToPipeline(ingestProcessors []IngestProcessor, name string, threshold int) []IngestProcessor {
	if len(ingestProcessors) <= threshold {
		return ingestProcessors
	} else {
		return []IngestProcessor{
			PipelineProcessor{
				Pipeline: &IngestPipeline{
					Name:                name,
					Processors:          ingestProcessors,
					OnFailureProcessors: nil,
				},
				Name: name,
			},
		}
	}
}

func DealWithCommonAttributes(plugin ast.Plugin) []IngestProcessor {
	ingestProcessors := []IngestProcessor{}

	for _, attr := range plugin.Attributes {
		if !Contains(CommonAttributes, attr.Name()) {
			continue // Ignore not common attributes
		}
		switch attr.Name() {
		// It is a common field
		case "add_field":
			keys, values := getHashAttributeKeyValueUntyped(attr)

			for i := range keys {

				var value interface{}

				switch values[i].(type) {
				case string:
					value, _ = toElasticPipelineSelectorExpression(values[i].(string), ProcessorContext)
				default:
					value = values[i]
				}

				ingestProcessors = append(ingestProcessors,
					SetProcessor{
						Value: value,
						Field: keys[i],
					},
				)
			}
		case "remove_field":
			fields := getArrayStringAttributeOrStringAttrubute(attr)
			for i := range fields {
				fields[i] = toElasticPipelineSelector(fields[i])
			}
			ingestProcessors = append(ingestProcessors,
				RemoveProcessor{
					Field: &fields,
				},
			)
		case "add_tag":
			ingestProcessors = append(ingestProcessors,
				AppendProcessor{
					Field: "tags",
					Value: getArrayStringAttributes(attr),
				},
			)

		case "remove_tag":
			tags := getArrayStringAttributes(attr)
			for _, t := range tags {
				ingestProcessors = append(ingestProcessors,
					ScriptProcessor{
						Source: pointer(
							fmt.Sprintf(
								`if(ctx?.tags != null && ctx.tags instanceof List) {
	ctx.tags.removeIf(x -> x == '%s')
}`, toElasticPipelineSelector(t),
							))},
				)
			}

		case "enable_metric", "periodic_flush": // N/A

		default:
			log.Warn().Msgf("Remove Tag (%s) is not yet supported", attr.Name())

		}
	}

	return ingestProcessors

}

func DealWithDrop(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	proc := DropProcessor{}.WithTag(id)

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "percentage":
			switch tattr := attr.(type) {
			case ast.NumberAttribute:
				value := int(tattr.Value())
				log.Info().Msgf("Percentage %d", value)
				// TODO Add seed?
				// TODO Make sure that random number is generated only on need
				proc = proc.WithIf(pointer(fmt.Sprintf("new Random().nextInt(100) < %d", value)), true).(DropProcessor)
			}
		// Add if condition

		default:
			log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}

	ingestProcessors = append(ingestProcessors, proc)

	return ingestProcessors, onFailureProcessors
}

func DealWithDate(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	proc := DateProcessor{}.WithTag(id).(DateProcessor)

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id, t)
		case "target":
			proc.TargetField = pointer(getStringAttributeString(attr))
		case "locale":
			log.Warn().Msgf("Date filter is using %s %s. Please make sure it corresponds to Ingest Pipeline's one", attr.Name(), getStringAttributeString(attr))
			proc.Locale = pointer(getStringAttributeString(attr))
		case "timezone":
			log.Warn().Msgf("Date filter is using %s %s. Please make sure it corresponds to Ingest Pipeline's one", attr.Name(), getStringAttributeString(attr))
			proc.Timezone = pointer(getStringAttributeString(attr))

		case "match":
			matchArray := getArrayStringAttributes(attr)
			proc.Field = toElasticPipelineSelector(matchArray[0])
			proc.Formats = matchArray[1:]

		default:
			log.Warn().Msgf("Attribute '%s' is currently not supported", attr.Name())

		}
	}
	// Add _kv_filter_error
	if len(onFailureProcessors) == 0 {
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_date_parse_failure", ast.DoubleQuoted)), id, t)
	}

	ingestProcessors = append(ingestProcessors, proc)

	return ingestProcessors, onFailureProcessors
}

func DealWithGeoIP(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailurePorcessors := []IngestProcessor{}
	properties := []string{}

	gp := GeoIPProcessor{}.WithTag(id).(GeoIPProcessor)

	// TODO Add all properties
	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "fields":
			properties = getArrayStringAttributes(attr)

		case "source":
			gp.Field = toElasticPipelineSelector(getStringAttributeString(attr))

		case "target":
			gp.TargetField = pointer(toElasticPipelineSelector(getStringAttributeString(attr)))

		case "tag_on_failure":
			onFailurePorcessors = DealWithTagOnFailure(attr, id, t)

		default:
			log.Warn().Msgf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}

	// Add _grok_parse_failure
	if len(gp.OnFailure) == 0 {
		onFailurePorcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_geoip_lookup_failure", ast.DoubleQuoted)), id, t)
	}

	// Fields are defined
	if len(properties) > 0 {
		asn_properties := []string{}
		other_properties := []string{}
		// Normalizing and dispatch in sub-arrays
		for i := range properties {
			properties[i] = strings.ToLower(properties[i])
			switch properties[i] {
			case "autonomous_system_number":
				asn_properties = append(asn_properties, "asn")
			case "autonomous_system_organization":
				asn_properties = append(asn_properties, "organization_name")
			default:
				other_properties = append(other_properties, properties[i])
			}
		}
		if len(asn_properties) > 0 {
			gp_asn := GeoIPProcessor{
				Field:        gp.Field,
				DatabaseFile: pointer("GeoLite2-ASN.mmdb"),
				Properties:   &asn_properties,
			}.WithTag(gp.GetTagOrDefault("") + "asn").(GeoIPProcessor)

			if gp.TargetField != nil {
				gp_asn.TargetField = pointer(*gp.TargetField + ".as")
			}
			ingestProcessors = append(ingestProcessors, gp_asn)
		}
		if len(other_properties) > 0 {
			gp_other := GeoIPProcessor{
				Field:      gp.Field,
				Properties: &other_properties,
			}.WithTag(id).(GeoIPProcessor)
			if gp.TargetField != nil {
				gp_other.TargetField = pointer(*gp.TargetField + ".geo")
			}
			ingestProcessors = append(ingestProcessors, gp_other)
		}
	}
	return ingestProcessors, onFailurePorcessors
}

func DealWithUserAgent(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailurePorcessors := []IngestProcessor{}

	ecs_compatibility := "v8"

	uap := UserAgentProcessor{}.WithTag(id).(UserAgentProcessor)

	// TODO Add all properties
	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "ecs_compatibility":
			ecs_compatibility = getStringAttributeString(attr)
			log.Info().Msgf("ECS COMPATIBILITY %s", ecs_compatibility)

		case "lru_cache_size":
			log.Info().Msg(`
				[useragent filter plugin] The attribute 'lru_cache_size' is set in Logstash.
				Elasticsearch support a per-node setting 'ingest.user_agent.cache_size'.
				More details can be found in the documentation https://www.elastic.co/guide/en/elasticsearch/reference/current/user-agent-processor.html#ingest-user-agent-settings
			`)

		case "regexes":
			uap.RegexFile = pointer(getStringAttributeString(attr))

		case "source":
			uap.Field = toElasticPipelineSelector(getStringAttributeString(attr))

		case "target":
			uap.TargetField = pointer(toElasticPipelineSelector(getStringAttributeString(attr)))

		default:
			log.Warn().Msgf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}

	// Add a TargetField is not already present based on ECS_Compatibility
	if uap.TargetField == nil {
		if ecs_compatibility == "disabled" {
			uap.TargetField = pointer("")
		} else if ecs_compatibility == "v8" || ecs_compatibility == "v1" {
			log.Debug().Msg("Nothing to do since the UserAgent Processor already uses user_agent as target field")
		}
	}
	ingestProcessors = append(ingestProcessors, uap)

	// Add Warning and Field renaming when ECS Compatibility is disabled
	if ecs_compatibility == "disabled" {

		log.Warn().Msg("Disabled ECS_Compatibility is only partially supported.")

		orig := []string{"os.name", "os.full", "os.version"}
		dest := []string{"os_name", "os_full", "os_version"}

		prefix := *uap.TargetField

		if len(prefix) > 0 {
			prefix = prefix + "."
		}

		if prefix+"original" != uap.Field {
			// While Elasticsearch copies the original event in the target field, Logstash does not
			field := []string{prefix + "original"}
			ingestProcessors = append(ingestProcessors, RemoveProcessor{
				Field: &field,
			}.WithTag(id+"fix-target-original").WithDescription("When ECS Compatibility is disabled, Logstash does not add a copy of the Field to Target"))
		}

		// Strictly Speaking these are onsucessprocessors and should be only executed on success
		for i := range orig {
			ingestProcessors = append(ingestProcessors, RenameProcessor{
				Field:         prefix + orig[i],
				TargetField:   prefix + dest[i],
				IgnoreFailure: true,
				IgnoreMissing: true,
			}.WithTag(id+"-rename-"+orig[i]))
		}
		// If prefix + os is empty, remove it
		field := []string{prefix + "os"}
		ingestProcessors = append(ingestProcessors, RemoveProcessor{
			Field: &field,
		}.
			WithTag(id+"-remove-"+prefix+"-os").
			WithIf(pointer(getIfFieldIsDefinedAndEmpty(prefix+"os")), true),
		)

		// Rename the device.name to device (to do so you need first to copy it and remove it)
		ingestProcessors = append(ingestProcessors, RenameProcessor{
			Field:       prefix + "device",
			TargetField: fmt.Sprintf("%s.%s.device", TRANSPILER_PREFIX, id),
		})
		ingestProcessors = append(ingestProcessors, RenameProcessor{
			TargetField: prefix + "device",
			Field:       fmt.Sprintf("%s.%s.device.name", TRANSPILER_PREFIX, id),
		})
		// Extract os_major, os_minor and os_patch from the os_version
		// An alternative approach is to use two dissect filter (once to match the complete major.minor.patch and if it fails major.minor)
		ingestProcessors = append(ingestProcessors, GrokProcessor{
			Field: prefix + "os_version",
			Patterns: []string{
				fmt.Sprintf("^%%{ALL_BUT_DOT:%sos_major}\\.%%{ALL_BUT_DOT:%sos_minor}(\\.%%{ALL_BUT_DOT:%sos_patch})?", prefix, prefix, prefix),
			},
			PatternDefinitions: map[string]string{
				"ALL_BUT_DOT": "[^\\.]+",
			},
		})

		// Extract major, minor and patch from the version
		// An alternative approach is to use two dissect filter (once to match the complete major.minor.patch and if it fails major.minor)
		ingestProcessors = append(ingestProcessors, GrokProcessor{
			Field: prefix + "version",
			Patterns: []string{
				fmt.Sprintf("^%%{ALL_BUT_DOT:%smajor}\\.%%{ALL_BUT_DOT:%sminor}(\\.%%{ALL_BUT_DOT:%spatch})?", prefix, prefix, prefix),
			},
			PatternDefinitions: map[string]string{
				"ALL_BUT_DOT": "[^\\.]+",
			},
		})

		ingestProcessors = append(ingestProcessors, SetProcessor{
			CopyFrom: prefix + "os_name",
			Field:    prefix + "os",
		})
	}
	return ingestProcessors, onFailurePorcessors
}

func DealWithGrok(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailurePorcessors := []IngestProcessor{}
	break_on_match := true

	gp := GrokProcessor{}.WithTag(id).(GrokProcessor)

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		case "match":
			helpPatterns := hashAttributeToMapArray(attr)
			// TODO: Deal with multiple keys, currently only the last is used
			for key := range helpPatterns {
				gp.Field = key
				gp.Patterns = helpPatterns[key]
				for i, _ := range gp.Patterns {
					gp.Patterns[i], _ = toElasticPipelineSelectorExpression(gp.Patterns[i], GrokContext)
				}
			}

		case "ecs_compatibility":
			gp.ECSCompatibility = getStringAttributeString(attr)
		case "pattern_definitions":
			gp.PatternDefinitions = hashAttributeToMap(attr)
		case "tag_on_failure":
			onFailurePorcessors = DealWithTagOnFailure(attr, id, t)
		case "break_on_match":
			break_on_match = getBoolValue(attr)

		default:
			log.Warn().Msgf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}
	// Add _grok_parse_failure
	if len(gp.OnFailure) == 0 {
		onFailurePorcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_grok_parse_failure", ast.DoubleQuoted)), id, t)
	}
	if !break_on_match {
		log.Warn().Msg("As of now only, break_on_match True is supported.")
		// TODO? To solve this issue, we would need to create a grok processor for each pattern
	}

	ingestProcessors = append(ingestProcessors, gp)
	return ingestProcessors, onFailurePorcessors
}

func DealWithURLDecode(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailurePorcessors := []IngestProcessor{}

	udp := URLDecodeProcessor{}.WithTag(id).(URLDecodeProcessor)

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		// It is a common field

		case "all_fields":
			allFields := getBoolValue(attr)
			if allFields {
				log.Warn().Msgf("URL Decoding all fields is not supported yet. Consider contributing :).")
			}
		case "field":
			udp.Field = getStringAttributeString(attr)
		default:
			log.Warn().Msgf("Attribute '%s' in Plugin '%s' is currently not supported", attr.Name(), plugin.Name())

		}
	}
	// Add _grok_parse_failure
	if len(udp.OnFailure) == 0 {
		onFailurePorcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_url_decode_field", ast.DoubleQuoted)), id, t)
	}

	ingestProcessors = append(ingestProcessors, udp)
	return ingestProcessors, onFailurePorcessors
}

// CIDR Plugin of Logstash
// CIDR is only available in a script and there is no processor that can substitute it as of now
// Given the current TemplateMethod Pattern and how we deal in a generic way with onSuccessProcessors
// the implementation generates (overcomplicated, but semantically similar) processors:
//   - 1. A script fails (throws an Exception) if no address matches the CIDR expressions provided
//   - 2. The onFailureProcessor adds a field _TRANSPILER.<id>
//   - 3. If the field is not present the onSuccessProcessors are executed
func DealWithCidr(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
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

	elastic_addresses := []string{}
	constant := true
	for _, a := range addresses {
		transformed_address, matchFound := toElasticPipelineSelectorExpression(a, ScriptContext)
		if matchFound {
			constant = false
		}

		elastic_addresses = append(elastic_addresses, transformed_address)

	}

	params := make(map[string]interface{})
	params["networks"] = networks

	addressOutput := fmt.Sprintf("%s", elastic_addresses)
	if constant {
		params["addresses"] = addresses
		addressOutput = "params.addresses"
	}

	var b bytes.Buffer

	b.WriteString(
		fmt.Sprintf(`
for (n in params.networks) {
	c = new CIDR(n)
	for (a in %s) {
		if (c.contains(a)) {
			return;
		}
	}
}
throw new Exception("Could not find CIDR value");
`, addressOutput))

	ingestProcessors = append(ingestProcessors, ScriptProcessor{
		Source: pointer(b.String()),
		Params: &params,
	}.WithTag(id))

	return ingestProcessors, onFailureProcessor
}

// func DealWithTruncate(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
// 	ingestProcessors := []IngestProcessor{}
// 	onFailureProcessor := []IngestProcessor{}
// 	var fields []string
// 	var lengthBytes uint64
// 	var err error
// 	for _, attr := range plugin.Attributes {
// 		switch attr.Name() {
// 		case "fields":
// 			fields = getArrayStringAttributeOrStringAttrubute(attr)
// 		case "length_bytes":
// 			rawLengthBytes := getStringAttributeString(attr)
// 			lengthBytes, err = strconv.ParseUint(rawLengthBytes, 10, 64)
// 			if err != nil {
// 				log.Warn().Msgf("[Plugin %s] the lengthBytes should be an integer %v", plugin.Name(), err)
// 			}
// 		}
// 	}

// }

func DealWithSyslogPri(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessor := []IngestProcessor{}
	ECSCompatibility := "v8"
	var field *string = nil
	useLabels := true
	facilityLabels := []string{"kernel", "user-level", "mail", "daemon", "security/authorization", "syslogd", "line printer", "network news", "uucp", "clock", "security/authorization", "ftp", "ntp", "log audit", "log alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}
	severityLabels := []string{"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}
	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "ecs_compatibility":
			ECSCompatibility = getStringAttributeString(attr)
		case "syslog_pri_field_name":
			field = pointer(getStringAttributeString(attr))
		case "severity_labels":
			severityLabels = getArrayStringAttributes(attr)
		case "facility_labels":
			facilityLabels = getArrayStringAttributes(attr)
		case "use_labels":
			useLabels = getBoolValue(attr)
		}
	}

	if field == nil {
		if ECSCompatibility == "disabled" {
			field = pointer("syslog_pri")
		} else if ECSCompatibility == "v1" || ECSCompatibility == "v8" {
			field = pointer("log.syslog.priority")
		}
	}

	setValuesString := ""

	log.Warn().Msgf("[Plugin %s] The Ingest processor script assumes that the field pri is already numeric and does not attempt to deal with other types", plugin.Name())
	extractValue := fmt.Sprintf(`
int pri = $('%s', 13);
int severity = pri & 0x7;
int facility = pri / 8;
`, *field)

	switch ECSCompatibility {
	case "disabled":
		setValuesString = `ctx.syslog_severity_code = severity;
ctx.syslog_facility_code = facility;`
	case "v1", "v8":
		setValuesString = `/* Make sure log.syslog.facility, log.syslog.priority are defined Maps */
field('log.syslog.severity.name', params.severity[severity]);
field('log.syslog.severity.code', severity);
`
	}

	useLabelsScript := ""
	switch ECSCompatibility {
	case "disabled":
		useLabelsScript = `ctx.syslog_facility_name = params.facility[facility];
ctx.syslog_severity_name = params.severity[severity];
		`
	case "v1", "v8":
		useLabelsScript = `field('log.syslog.facility.name', params.facility[facility]);
field('log.syslog.facility.code', facility);
`
	}

	proc := ScriptProcessor{}.WithTag(id).(ScriptProcessor)

	if useLabels {
		log.Debug().Msgf("UseLabels True")
		params := make(map[string]interface{})
		params["facility"] = facilityLabels
		params["severity"] = severityLabels
		setValuesString = fmt.Sprintf("%s\n%s", setValuesString, useLabelsScript)
		proc.Params = &params
	}
	proc.Source = pointer(fmt.Sprintf("%s\n%s", extractValue, setValuesString))

	ingestProcessors = append(ingestProcessors, proc)
	return ingestProcessors, onFailureProcessor
}

func DealWithMutate(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id, t)
		}
	}

	// Add default value for Tag_on_failure
	if len(onFailureProcessors) == 0 {
		onFailureProcessors = append(onFailureProcessors, DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_mutate_error", ast.DoubleQuoted)), id, t)...)
	}

	// Extract the attributes
	for _, attr := range plugin.Attributes {
		if attr.Name() == "tag_on_failure" {
			continue
		}
		ingestProcessors = DealWithMutateAttributes(attr, ingestProcessors, id)
	}

	// log.Debug().Msgf("Length: %d", len(ingestProcessors))

	return ingestProcessors, onFailureProcessors
}

// Generic function that deal with a single Logstash Plugin by using Template Method Pattern
func (t Transpile) DealWithPlugin(section string, plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	id := getProcessorID(plugin)
	log.Debug().Msgf("Plugin ID is %s", id)

	DealWithPluginFunction, ok := transpiler[section][plugin.Name()]
	if !ok {
		log.Warn().Msgf("There is no handler for the %s plugin of type '%s' (with id '%s')\nReturning an empty processors list", section, plugin.Name(), id)
		return []IngestProcessor{}
	}

	constraintTranspiled := transpileConstraint(constraint)

	onSuccessCondition := pointer(fmt.Sprintf("!%s", getIfFieldDefined(getUniqueOnFailureAddField(id))))
	onSuccessProcessors := DealWithCommonAttributes(plugin)
	for i := range onSuccessProcessors {
		// log.Info().Msgf("[%d] = %s %s", i, constraintTranspiled, onSuccessCondition)
		onSuccessProcessors[i] = onSuccessProcessors[i].WithIf(constraintTranspiled, false)
	}

	// If we deal with error
	if t.deal_with_error_locally {
		onSuccessProcessors = processorsToPipeline(onSuccessProcessors, fmt.Sprintf("%s-on-success", id), t.threshold)
		for i := range onSuccessProcessors {
			onSuccessProcessors[i] = onSuccessProcessors[i].WithIf(onSuccessCondition, true)
			onSuccessProcessors[i] = onSuccessProcessors[i].WithTag(fmt.Sprintf("%s-%d-onSucc", id, len(onSuccessProcessors)))
		}
	}
	// else we rely on a global on_failure and if the processor is successfully executed we can simply proceed

	noncommonattrs := []ast.Attribute{}

	for _, pa := range plugin.Attributes {
		if !Contains(CommonAttributes, pa.Name()) {
			noncommonattrs = append(noncommonattrs, pa)
		}
	}

	// PA is a Plugin with only Plugin-Specific attributes (no id, no add_field etc.)
	pa := ast.NewPlugin(plugin.Name(), noncommonattrs...)

	ingestProcessors, onFailureProcessors := DealWithPluginFunction(pa, id, t)

	// On Success Processors should be executed only when no Failure happened
	if len(onSuccessProcessors) > 0 && t.deal_with_error_locally {
		onFailureProcessors = append(onFailureProcessors, getTranspilerOnFailureProcessor(id))
	}

	// Mutate filter can only contain common attributes (e.g., add_field)
	// In this case we are always in the "OnSuccess" case, thus we can simplify the condition
	if len(ingestProcessors) == 0 { // There are only unsupported or the common attributes
		for i := range onSuccessProcessors {
			onSuccessProcessors[i] = onSuccessProcessors[i].WithIf(constraintTranspiled, false)
		}
	}

	// To keep a similar semantics as Logstash we create an additional pipeline
	// If we have more than t.threshold Processors that have been created by the plugin-specific function
	ingestProcessors = processorsToPipeline(ingestProcessors, id, t.threshold)

	for i := range ingestProcessors {
		ingestProcessors[i] = ingestProcessors[i].WithIf(constraintTranspiled, true)
		ingestProcessors[i] = ingestProcessors[i].WithOnFailure(onFailureProcessors)
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

func DealWithKV(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	kv := KVProcessor{
		FieldSplit: " ",       // Default value in Logstash
		Field:      "message", // Default value in Logstash
		ValueSplit: "=",       // Default value in Logstash
	}.WithTag(id).(KVProcessor)

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id, t)
		case "target":
			kv.TargetField = pointer(getStringAttributeString(attr))
		case "prefix":
			kv.Prefix = pointer(getStringAttributeString(attr))
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
		case "value_split":
			kv.ValueSplit = getStringAttributeString(attr)
		default:
			log.Warn().Msgf("Attribute '%s' is currently not supported", attr.Name())

		}
	}
	// Add _kv_filter_error
	if len(kv.OnFailure) == 0 {
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_kv_filter_error", ast.DoubleQuoted)), id, t)
	}
	ingestProcessors = append(ingestProcessors, kv)

	return ingestProcessors, onFailureProcessors
}

func DealWithJSON(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	json := JSONProcessor{}.WithTag(id).(JSONProcessor)

	for _, attr := range plugin.Attributes {
		if Contains(CommonAttributes, attr.Name()) {
			continue
		}
		switch attr.Name() {
		case "source":
			json.Field = getStringAttributeString(attr)
		case "target":
			json.TargetField = getStringAttributeString(attr)
		default:
			log.Warn().Msgf("Attribute '%s' is currently not supported", attr.Name())

		}
	}
	// Add _kv_filter_error
	if len(json.OnFailure) == 0 {
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_jsonparsefailure", ast.DoubleQuoted)), id, t)
	}
	ingestProcessors = append(ingestProcessors, json)

	return ingestProcessors, onFailureProcessors
}

func DealWithDissect(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}
	onSuccessProcessors := []IngestProcessor{}

	proc := DissectProcessor{
		// Dissect in Logstash always add a space in the appended information
		AppendSeparator: pointer(" "),
	}.WithTag(id).(DissectProcessor)

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id, t)
		case "convert_datatype":
			convertKeys, convertValues := getHashAttributeKeyValue(attr)
			convertdatatypeMap := map[string]string{
				"int":   "integer",
				"float": "float",
			}
			for i := range convertKeys {
				ttype := convertValues[i]

				cType, ok := convertdatatypeMap[ttype]

				if !ok {
					log.Warn().Msgf("Type %s not yet supported in convert_datatype", ttype)
				} else {
					onSuccessProcessors = append(onSuccessProcessors, ConvertProcessor{
						Field: convertKeys[i],
						Type:  cType,
					})
				}

			}

		case "mapping":
			keys, values := getHashAttributeKeyValue(attr)
			if len(keys) != 1 {
				log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' only one map is supported. Consider splitting the original in two dissect filters", plugin.Pos(), plugin.Name(), attr.Name())
			}
			proc.Field = keys[0]
			proc.Pattern, _ = toElasticPipelineSelectorExpression(values[0], DissectContext)
		default:
			log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}
	// Add dissect failure default tag
	if len(proc.OnFailure) == 0 {
		onFailureProcessors = DealWithTagOnFailure(ast.NewArrayAttribute("tag_on_failure", ast.NewStringAttribute("", "_dissectfailure", ast.DoubleQuoted)), id, t)
	}

	ingestProcessors = append(ingestProcessors, proc)
	ingestProcessors = append(ingestProcessors, onSuccessProcessors...)
	return ingestProcessors, onFailureProcessors
}

// **Heuristic** to determin if string is probably an regexp (excluding trivial constant strings)
func isProbablyRegexp(str string) bool {
	for _, c := range []string{"?", "*", "[", "]", "(", ")", "."} {
		if strings.Contains(str, c) {
			return true
		}
	}
	return false
}

func DealWithOutputPipeline(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "send_to":
			pipelines := getArrayStringAttributeOrStringAttrubute(attr)
			for _, p := range pipelines {
				ingestProcessors = append(ingestProcessors, PipelineProcessor{
					Name: p,
				})
			}

		default:
			log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}

	}
	return ingestProcessors, onFailureProcessors
}

func DealWithPrune(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	log.Warn().Msgf("Support for prune filter is really minimal: Only whitelist_names without regexps are supported")
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	var whiteListFields *[]string = nil
	// var interpolate *bool = nil

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "whitelist_names":
			tmp := getArrayStringAttributes(attr)
			whiteListFields = &tmp
		case "interpolate":
			tmp := getBoolValue(attr)
			// interpolate = &tmp
			log.Debug().Msgf("Prune with interpolate %v", tmp)
		// TODO: case whitelist_values:
		// TODO: case blacklist_values:
		// TODO: case blacklist_names:
		default:
			log.Error().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}

	if whiteListFields != nil {

		for _, w := range *whiteListFields {
			if isProbablyRegexp(w) {
				log.Error().Msgf("[Plugin %s] WhiteList field '%s' is probably a regexp. It is not supported", plugin.Name(), w)
			}
		}

		ingestProcessors = append(ingestProcessors, RemoveProcessor{
			Keep: *whiteListFields,
		}.WithTag(id))
	}

	return ingestProcessors, onFailureProcessors
}

func DealWithCSV(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	onSuccessProcessors := []IngestProcessor{}

	proc := CSVProcessor{Field: "message", EmptyValue: pointer("")}.WithTag(id).(CSVProcessor)

	prefix := ""

	autodetect_column_names := false

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "source":
			proc.Field = getStringAttributeString(attr)

		case "columns":
			proc.TargetFields = getArrayStringAttributeOrStringAttrubute(attr)
		case "autodetect_column_names":
			autodetect_column_names = getBoolValue(attr)
		case "separator":
			proc.Separator = pointer(getStringAttributeString(attr))
		case "quote_char":
			proc.Quote = pointer(getStringAttributeString(attr))

		// Deal with skip_empty_columns explicitely set
		case "skip_empty_columns":
			skip_empty_columns := getBoolValue(attr)
			if skip_empty_columns {
				proc.EmptyValue = nil
			} else {
				proc.EmptyValue = pointer("")
			}
		case "convert":
			keys, values := getHashAttributeKeyValue(attr)
			for i := range keys {
				switch values[i] {

				case "integer":
					onSuccessProcessors = append(onSuccessProcessors, ConvertProcessor{Field: keys[i], Type: values[i]})
				case "float":
					onSuccessProcessors = append(onSuccessProcessors, ConvertProcessor{Field: keys[i], Type: values[i]})
				default:
					log.Warn().Msgf("Convert: %s is not yet supported", values[i])
				}

				onSuccessProcessors = append(onSuccessProcessors, ConvertProcessor{Field: keys[i], Type: values[i]})
			}

		case "target":
			prefix = getStringAttributeString(attr)

		default:
			log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}

	if autodetect_column_names {
		log.Warn().Msgf("[Pos %s][Plugin %s] Autodetect column names (true) is not supported by Elasticsearch. Consider adding explicitely the columns", plugin.Pos(), plugin.Name())
	}

	// Apply the target if present
	if prefix != "" {
		for i := range proc.TargetFields {
			proc.TargetFields[i] = prefix + "." + proc.TargetFields[i]
		}
	}

	ingestProcessors = append(ingestProcessors, proc)
	ingestProcessors = append(ingestProcessors, onSuccessProcessors...)
	return ingestProcessors, onFailureProcessors
}

func DealWithTranslate(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	proc := ScriptProcessor{}.WithTag(id).(ScriptProcessor)

	params := make(map[string]interface{})

	var target *string = nil
	ECSCompatibility := "v8" // We assume ECS Compatibility
	var dictionary map[string]string = make(map[string]string)
	var source *string = nil

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		// It is a common field
		case "tag_on_failure":
			onFailureProcessors = DealWithTagOnFailure(attr, id, t)
		case "destination", "target":
			target = pointer(getStringAttributeString(attr))

		case "dictionary":

			keys, values := getHashAttributeKeyValue(attr)
			for i := range keys {
				dictionary[keys[i]] = values[i]
			}
			params["dictionary"] = dictionary

		case "ecs_compatibility":
			ECSCompatibility = getStringAttributeString(attr)

		case "field", "source":
			source = pointer(getStringAttributeString(attr))

		case "fallback":
			params["fallback"] = getStringAttributeString(attr)

		default:
			log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}
	}
	// Post-Condition: Given that source is mandatory, source variable will always be a string

	if target == nil {
		if ECSCompatibility == "disabled" {
			target = pointer("translation")
		} else {
			target = source
		}
	}
	// Post-Condition: Translation will always be a string

	proc.Params = &params

	var b bytes.Buffer

	// field := toElasticPipelineSelectorCondition(*source)
	field := toElasticPipelineSelector(*source)

	b.WriteString(fmt.Sprintf(`def tmp = params.dictionary[$('%s', '')];`, field))

	if _, ok := params["fallback"]; ok {
		b.WriteString(`if (tmp == null) { tmp = params.fallback; }`)
	}

	fieldToAssign := toElasticPipelineSelectorWithNullable(*target, false)
	// fieldToAssign := toElasticPipelineSelectorCondition(*target)

	// TODO: Add the creation of the substructure
	// createSubStructure := ""
	// subFields := returnSubFields(*target)
	// currentPath := ""
	// currentLogstashPath := ""
	// for i, f := range subFields {
	// 	if i == 0 {
	// 		currentLogstashPath += "[" + f + "]"
	// 	} else if i > 0 && i < len(subFields)-1 {
	// 		createSubStructure += fmt.Sprintf("; ctx.%s.putIfAbsent('%s', [:])", createSubStructure, toElasticPipelineSelectorWithNullable(currentLogstashPath, false), f)
	// 	}
	// }

	b.WriteString(fmt.Sprintf(`if (tmp != null) { %s = tmp; }`, fieldToAssign))

	proc.Source = pointer(b.String())

	proc.Description = pointer(fmt.Sprintf("Translate the field '%s' to field '%s'.", toElasticPipelineSelector(*source), toElasticPipelineSelector(*target)))

	log.Warn().Msgf("The Translate script %s produced, assumes: 1. that the target structure is already created.  Consider improving the script to create the structure if not present", id)
	ingestProcessors = append(ingestProcessors, proc)

	return ingestProcessors, onFailureProcessors
}

func DealWithMissingTranspiler(plugin ast.Plugin, constraint Constraints) []IngestProcessor {
	constraintTranspiled := transpileConstraint(constraint)
	if constraintTranspiled == nil {
		tmp := ""
		constraintTranspiled = &tmp
	}

	log.Warn().Msgf("[WARN] Plugin %s is not yet supported. Consider Making a contribution :)\n", plugin.Name())

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

// The Elasticsearch Output has a complex logic, we are (as of now) only interested in the pipeline used (if any)
func DealWithOutputElasticsearch(plugin ast.Plugin, id string, t Transpile) ([]IngestProcessor, []IngestProcessor) {
	ingestProcessors := []IngestProcessor{}
	onFailureProcessors := []IngestProcessor{}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "pipeline":
			pipeline, _ := toElasticPipelineSelectorExpression(attr.ValueString(), ProcessorContext)
			ingestProcessors = append(ingestProcessors, PipelineProcessor{
				Name: pipeline,
			})

		default:
			log.Warn().Msgf("[Pos %s][Plugin %s] Attribute '%s' is currently not supported", plugin.Pos(), plugin.Name(), attr.Name())
		}

	}
	return ingestProcessors, onFailureProcessors
}

func getDefaultTranspilerOnFailureProcessor() []IngestProcessor {
	return []IngestProcessor{
		SetProcessor{
			Field: "error.message",
			Value: "Processor {{ _ingest.on_failure_processor_type }} with tag {{ _ingest.on_failure_processor_tag }} in pipeline {{ _ingest.on_failure_pipeline }} failed with message {{ _ingest.on_failure_message }}",
		},
		AppendProcessor{
			Field: "event.kind",
			Value: []string{"pipeline_error"},
		},
	}
}

func (t Transpile) buildIngestPipeline(filename string, c ast.Config) []IngestPipeline {
	plugin_names := []string{}
	fname := path.Base(filename)
	ip := IngestPipeline{
		Name:                fmt.Sprintf("main-pipeline-%s", fname[:len(fname)-len(path.Ext(fname))]),
		Description:         fmt.Sprintf("Main Pipeline for the file '%s'", filename),
		Processors:          []IngestProcessor{},
		OnFailureProcessors: nil,
	}

	if t.addDefaultGlobalOnFailure {
		ip.OnFailureProcessors = getDefaultTranspilerOnFailureProcessor()
	}

	// apply func returns an ApplyPluginsFuncCondition object depending on the section
	applyFunc := func(section string) ApplyPluginsFuncCondition {
		var i int = 0
		return func(c *Cursor, constraint Constraints, ip *IngestPipeline) {
			log.Debug().Msgf(section)

			ip.Processors = append(ip.Processors, t.DealWithPlugin(section, *c.Plugin(), constraint)...)

			plugin_names = append(plugin_names, c.Plugin().Name())
			i += 1
		}
	}

	for _, f := range c.Filter {
		t.MyIteration(f.BranchOrPlugins, NewConstraintLiteral(), applyFunc("filter"), &ip)
	}
	// for _, f := range c.Output {
	// 	t.MyIteration(f.BranchOrPlugins, NewConstraintLiteral(), applyFunc("output"), &ip)
	// }

	ips := getAllIngestPipeline(ip)

	log.Debug().Msgf("Pipeline generated %d", len(ips))

	return ips

}

func printPipeline(ips []IngestPipeline) {
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
			if typedIp.Pipeline != nil {
				ingestPipelines = append(ingestPipelines, getAllIngestPipeline(*typedIp.Pipeline)...)
			}
		}
	}
	return ingestPipelines
}

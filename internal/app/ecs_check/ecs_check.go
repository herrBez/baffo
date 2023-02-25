package ecs_check

import (
	"os"
	// "log"
    "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"strings"
	"fmt"
	"regexp"
	"reflect"
	"path/filepath"

	"github.com/breml/logstash-config/ast/astutil"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	config "github.com/breml/logstash-config"
	"github.com/breml/logstash-config/internal/format"
	ast "github.com/breml/logstash-config/ast"
	"encoding/json"

)

type ECSCheck struct{}

func New() ECSCheck {
	return ECSCheck{}
}

func (f ECSCheck) Run(args []string) error {
	var result *multierror.Error

	var files []string

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// log.SetOutput(os.Stdout)


	for _, filename := range args {
		stat, err := os.Stat(filename)
		if err != nil {
			result = multierror.Append(result, errors.Errorf("%s: %v", filename, err))
		}
		if stat.IsDir() {
			filepath.Walk(filename, func(path string, info os.FileInfo, e error) error {
				if e != nil {
						return e
				}

				// check if it is a regular file (not dir)
				if info.Mode().IsRegular() {
					files = append(files, path)
				}
				return nil
			})
		} else {
			files = append(files, filename)
		}
	}

	if len(files) == 0 {
		log.Error().Msg("At least a file is expected")
		os.Exit(1)
	}

	global_cs := NewConfigStats()

	for _, filename := range files {

		res, err1 := config.ParseFile(filename, config.IgnoreComments(true))

		if err1 != nil {
			log.Warn().Msgf("Could not parse file '%s', because of '%s'. Ignored File", filename, err1)
			result = multierror.Append(result, errors.Errorf("%s: %v", filename, err1))
			continue
		} else {
			// fmt.Printf("%s\n", filename)
			var tree ast.Config = res.(ast.Config)

			cs := NewConfigStats()
			cs.Input = getAllFieldNamesUsedInPluginSection(tree.Input, "input")
			cs.Filter = getAllFieldNamesUsedInPluginSection(tree.Filter, "filter")
			cs.Output = getAllFieldNamesUsedInPluginSection(tree.Output, "output")

			cs.PipelineAddress = getPipelineAddress(tree.Input)
			if cs.PipelineAddress == "" {
				cs.PipelineAddress = filename
			}

			cs.PipelineOutput = getPipelineOutputAddress(tree.Output)

			log.Debug().Msg(cs.String())

			global_cs.merge(cs)
			// cs.Filename = filename
			// fmt.Println(createGraph(cs))
		}
	}


	fmt.Println(global_cs)

	if result != nil {
		result.ErrorFormat = format.MultiErr
		return result
	}

	return nil
}


type GetFieldsEnvs func(ast.Node) ([]string, []string)


func pairWiseAppendUnique(tf * []string, te * []string, n ast.Node, fs GetFieldsEnvs) {
	tmpFields, tmpEnvs := fs(n)
	*tf = appendUnique(*tf, tmpFields...)
	*te = appendUnique(*te, tmpEnvs...)
}


func collectConditionFields(n ast.Node) ([] string, []string) {

	var fields [] string;
	var envs [] string;

	log.Warn().Msgf("TYPOF%s: %s", n, reflect.TypeOf(n))

	switch node := n.(type) {



	case ast.Condition:
		for _, expression := range node.Expression {
			pairWiseAppendUnique(&fields, &envs, expression, collectConditionFields)
			// &fields = appendUnique(&fields, collectConditionFields(expression)...)
		}

	case ast.ConditionExpression:
		pairWiseAppendUnique(&fields, &envs, node.Condition, collectConditionFields)

	case ast.NegativeConditionExpression:
		pairWiseAppendUnique(&fields, &envs, node.Condition, collectConditionFields)
		// &fields = appendUnique(&fields, collectConditionFields(node.Condition)...)

	case ast.NegativeSelectorExpression:
		pairWiseAppendUnique(&fields, &envs, node.Selector, collectConditionFields)

	case ast.InExpression:
		pairWiseAppendUnique(&fields, &envs, node.LValue, collectConditionFields)
		pairWiseAppendUnique(&fields, &envs, node.RValue, collectConditionFields)

	case ast.NotInExpression:
		pairWiseAppendUnique(&fields, &envs, node.LValue, collectConditionFields)
		pairWiseAppendUnique(&fields, &envs, node.RValue, collectConditionFields)

	case ast.RvalueExpression:
		pairWiseAppendUnique(&fields, &envs, node.RValue, collectConditionFields)

	case ast.CompareExpression:
		pairWiseAppendUnique(&fields, &envs, node.LValue, collectConditionFields)
		pairWiseAppendUnique(&fields, &envs, node.RValue, collectConditionFields)
		// node.CompareOperator cannot cannot contain &fields nor &envs
		// pairWiseAppendUnique(&fields, &envs, node.CompareOperator, collectConditionFields)


	case ast.RegexpExpression:
		log.Warn().Msgf("Regexp %s", node)
		pairWiseAppendUnique(&fields, &envs, node.LValue, collectConditionFields)
		pairWiseAppendUnique(&fields, &envs, node.RValue, collectConditionFields)


		// node.RegexpOperator cannot contain &fields nor &envs
		// pairWiseAppendUnique(&fields, &envs, node.RegexpOperator, collectConditionFields)

	case ast.Selector:
		fields = appendUnique(fields, node.String())
	case ast.StringAttribute:
		tmpFields, tmpEnvs := extractFieldsFromString(node.Value())
		fields = appendUnique(fields, tmpFields...)
		envs = appendUnique(fields, tmpEnvs...)

	case ast.NumberAttribute:
		// A number attribute (i.e., a number literal) cannot contain a variable. Do Nothing
	case ast.Regexp:
		// A regexp expression cannot contain a variable. Do Nothing...

	case ast.ArrayAttribute:
		for _, attr := range node.Attributes {
			pairWiseAppendUnique(&fields, &envs, attr, collectConditionFields)
		}
	default:
		log.Panic().Msgf("Unknown type `%s`", reflect.TypeOf(node))
	}
	return fields, envs
}

func extractFieldsFromString(s string) ([] string, []string) {
	field_finder := regexp.MustCompile(`\%\{[^\}]+\}`)
	env_variable_finder := regexp.MustCompile(`\$\{[^\}]+\}`)

	var envs []string;
	var fields []string;

	for _, m:= range field_finder.FindAll([]byte(s), -1) {
		rawstring := string(m[2:len(m)-1])
		// log.Println("Match found %s", rawstring)
		fields = append(fields, rawstring)

	}

	for _, m:= range env_variable_finder.FindAll([]byte(s), -1) {

		rawstring := string(m[2:len(m)-1])

		// log.Println("Env Variable found %s", rawstring)
		res := strings.Split(rawstring, ":")
		switch len(res) {
		case 1:
			envs = append(envs, res[0])
		case 2:
			envs = append(envs, res[0])

		default:
			log.Printf("D: %s", res)
		}

	}
	return fields, envs
}


func getAllFieldsNamesUsedInAttribute(attr ast.Attribute, keep_key bool) ([] string, []string) {
	var fields [] string
	var envs [] string

	switch t := attr.(type) {

	case ast.StringAttribute:
		log.Debug().Msgf("String attribute %s and its value %s", t, t.Value())
		fields, envs = extractFieldsFromString(t.Value())
		// fields = append(fields, t.Name())


	case ast.NumberAttribute:
		log.Debug().Msgf("Number attribute %f", t.Value())

	case ast.HashAttribute:
		log.Debug().Msgf("Hash attribute %v", t)
		for _, entry := range t.Entries {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(entry.Value, keep_key)
			fields = append(fields, tmpFields...)
			envs = append(envs, tmpEnvs...)
			if keep_key {
				key_string := entry.Key.ValueString()

				tmpFields, tmpEnvs = extractFieldsFromString(key_string[1:len(key_string)-1])

				fields = append(fields, tmpFields...)
				envs = append(envs, tmpEnvs...)
			}

		}

	case ast.ArrayAttribute:
		log.Debug().Msgf("Array attribute %v", t)
		for _, element := range t.Attributes {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(element, keep_key)
			fields = append(fields, tmpFields...)
			envs = append(envs, tmpEnvs...)
		}

	default:
		log.Warn().Msgf("Unknown Attribute Type `%s`", reflect.TypeOf(t))
	}
	return fields, envs
}

func contains(arr [] string, s string) bool {
	for _, el := range(arr) {
		if(s == el) {
			return true
		}
	}
	return false
}



func getAttributeValue(attr ast.Attribute) string {
	switch t := attr.(type) {

	case ast.StringAttribute:
		return t.Value()
	default:
		log.Panic().Msgf("The attribute %s should be of type string?", t.Name())
	}
	return ""
}

func getAllFieldNamesUsedInPluginSection(plugin_section []ast.PluginSection, section string) (PluginSectionStats) {
	psStats := NewPluginSectionStats()

	byteValue, err := os.ReadFile("./internal/app/ecs_check/ecs_compatibility.json")

	if err != nil {
		log.Panic().Msg("Could not open file")
	}
	var ecsCDF ECSCompatibilityDefinedFields
	json.Unmarshal(byteValue, &ecsCDF)

	applyPluginFunc := func(c *astutil.Cursor) {

		pluginPsStats := NewPluginSectionStats()

		plugin := c.Plugin()
		pluginPsStats.AddPluginNames(section + "-" + plugin.Name())

		// Get rid of default attributes
		var common_attr_list []ast.Attribute

		var plugin_specific_attr []ast.Attribute

		var ecs_compatibility_value = "disabled" // TODO Inherit it from somewhere else

		for _, attr := range plugin.Attributes {
			if contains([]string{"add_field", "add_tag", "enable_metric", "id", "periodic_flush", "remove_field", "remove_tag"}, attr.Name()) {
				common_attr_list = append(common_attr_list, attr)
			} else if attr.Name() == "ecs_compatibility" {
				ecs_compatibility_value = getAttributeValue(attr)
			} else {
				plugin_specific_attr = append(plugin_specific_attr, attr)
			}
		}

		// Add static information on fields added by ecs_compatibility



		val, ok := ecsCDF.getSectionMap(section)[plugin.Name()][ecs_compatibility_value]
		if ok {
			pluginPsStats.AddFieldsAddedByThePlugin(val...)
		} else {
			log.Printf("We don't have ecs_compatibility info about the plugin %s-%s", section, plugin.Name())
		}

		// Deal with Common Attributes that can be defined in any plugin
		for _, attr := range common_attr_list {
			switch attr.Name() {
				// Common Option
				// HashKey --> Field
				// HashValue --> Deal with expansion
			case "add_field", "remove_field":
				log.Debug().Msg(attr.String())
				tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, true)
				pluginPsStats.AddFieldsUsedByThePlugin(tmpFields...)
				pluginPsStats.AddPluginEnvs(tmpEnvs...)

			case "add_tag", "remove_tag":
				log.Debug().Msg(attr.String())
				tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, false)
				pluginPsStats.AddFieldsUsedByThePlugin(tmpFields...)
				pluginPsStats.AddPluginEnvs(tmpEnvs...)

			default:
				// enable_metric, id, periodic_flush
				// Do nothing --> they cannot contain any fields
			}
		}

		myFunc, found := globalPluginMap[section][plugin.Name()]

		if found  {
			if plugin != nil {
				log.Debug().Msgf("Plugin %s has a func", plugin.Name())
				myFunc(&pluginPsStats, *plugin)
			}
		} else { // Apply Default-Unknown Case. Get all Values as fields
			log.Warn().Msgf("The plugin %s-%s is not known. Consider contributing :). In the meantime all strings will be treated as potential fields", section, plugin.Name())
			DealWithGenericPlugin(&pluginPsStats, *plugin)
		}


		for _, f := range psStats.Fields {
			if strings.Contains(f, ".") {
				log.Printf("Warning: field %s contain dots and does not using Logstash's Field Selector convention")
			}
		}
		// fmt.Println(plugin.Pos())
		fmt.Println(pluginPsStats)

		psStats.merge(pluginPsStats)

	}

	applyConditionFunc := func(c *ast.Condition) {
		tmpFields, tmpEnvs := collectConditionFields(*c)
		psStats.AddConditionFields(tmpFields...)
		psStats.AddConditionEnvs(tmpEnvs...)
	}

	for _, element := range plugin_section {
		astutil.ApplyPluginsOrBranch(element.BranchOrPlugins, applyPluginFunc, applyConditionFunc)
	}
	return psStats;
}



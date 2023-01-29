package ecs_check

import (
	"os"
	"log"
	"strings"
	// "fmt"
	"github.com/breml/logstash-config/ast/astutil"



	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	config "github.com/breml/logstash-config"
	"github.com/breml/logstash-config/internal/format"
	"reflect"


	ast "github.com/breml/logstash-config/ast"
	"regexp"


)

type ECSCheck struct{}

func New() ECSCheck {
	return ECSCheck{}
}


func (f ECSCheck) Run(args []string) error {
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
			log.Println(reflect.TypeOf(tree))



			var input_plugin_names[] string = getAllPluginNames(tree.Input)
			var filter_plugin_names[] string = getAllPluginNames(tree.Filter)
			var output_plugin_names[] string = getAllPluginNames(tree.Output)

			var input_fields, input_envs = getAllFieldNamesUsedInConditions(tree.Input)
			var filter_fields, filter_envs = getAllFieldNamesUsedInConditions(tree.Filter)
			var output_fields, output_envs = getAllFieldNamesUsedInConditions(tree.Output)



			// Analyze Input
			log.Println("=== INPUT ===")
			log.Printf("PluginNames: %s", input_plugin_names)
			log.Printf("Fields: %s", input_fields)
			log.Printf("ENVS: %s", input_envs)


			// Analyze Filter
			log.Println("=== FILTER ===")
			log.Printf("PluginNames: %s", filter_plugin_names)
			log.Printf("Fields: %s", filter_fields)
			log.Printf("ENVS: %s", filter_envs)

			// Analyze Output
			log.Println("=== OUTPUT ===")
			log.Printf("PluginNames: %s", output_plugin_names)
			log.Printf("Fields: %s", output_fields)
			log.Printf("ENVS: %s", output_envs)


		}
	}

	if result != nil {
		result.ErrorFormat = format.MultiErr
		return result
	}

	return nil
}


func getAllPluginNames(plugin_section []ast.PluginSection) []string {
	var plugin_names[] string
	applyFunc := func(c *astutil.Cursor) {
		// count++
		plugin_names = append(plugin_names, c.Plugin().Name())
	}

	for _, element := range plugin_section {
		astutil.ApplyPlugins(element.BranchOrPlugins, applyFunc)
	}
	return plugin_names;
}



type ApplyFunc func(c *ast.Node)


func collectFields(n ast.Node) [] string {

	var variables [] string;
	var values [] string;

	// log.Println("Collecting Variables")

	// log.Println(reflect.TypeOf(n))



	switch node := n.(type) {

	case ast.Condition:
		for _, expression := range node.Expression {
			variables = append(variables, collectFields(expression)...)
		}

	case ast.ConditionExpression:
		variables = append(variables, collectFields(ast.ConditionExpression(node).Condition)...)

	case ast.NegativeConditionExpression:
		variables = append(variables, collectFields(node.Condition)...)

	case ast.NegativeSelectorExpression:
		variables = append(variables, collectFields(node.Selector)...)

	case ast.InExpression:
		variables = append(variables, collectFields(node.LValue)...)
		variables = append(variables, collectFields(node.RValue)...)

	case ast.NotInExpression:
		variables = append(variables, collectFields(node.LValue)...)
		variables = append(variables, collectFields(node.RValue)...)

	case ast.RvalueExpression:
		variables = append(variables, collectFields(node.RValue)...)

	case ast.CompareExpression:
		variables = append(variables, collectFields(node.LValue)...)
		variables = append(variables, collectFields(node.CompareOperator)...)
		variables = append(variables, collectFields(node.RValue)...)

	case ast.RegexpExpression:
		variables = append(variables, collectFields(node.LValue)...)
		variables = append(variables, collectFields(node.RegexpOperator)...)
		variables = append(variables, collectFields(node.RValue)...)

	case ast.Selector:

		variables = append(variables, node.String())

		// for _, element := range node.Elements {
		// 	variables = append(variables, collectFields(element)...)
		// }

	// case ast.SelectorElement:
	// 	log.Println(node)

	case ast.StringAttribute:
		//log.Println("HO TROVATO STRING")
		values = append(values, node.Value())

	case ast.CompareOperator:
		// do nothing


	default:
		log.Printf("Unknown type `%s`", reflect.TypeOf(node))
	}

	// log.Println(values)

	return variables
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

		log.Println("Env Variable found %s", rawstring)
		res := strings.Split(rawstring, ":")
		switch len(res) {
		case 1:
			// log.Printf("1: %s", res)
			envs = append(envs, res[0])
		case 2:
			// log.Printf("ENVVAR: %s, ENVVARDEFAULTVALUE: %s", res[0], res[1])
			envs = append(envs, res[0])

		default:
			log.Printf("D: %s", res)
		}

	}
	return fields, envs
}


func getAllFieldsNamesUsedInAttribute(attr ast.Attribute) ([] string, []string) {
	var fields [] string
	var envs [] string



	switch t := attr.(type) {
	// case ast.PluginAttribute:
	// 	log.Printf("Plugin attribute %s", attr)

	case ast.StringAttribute:
		log.Printf("String attribute %s", t.Value())
		fields, envs = extractFieldsFromString(t.Value())


	case ast.NumberAttribute:
		log.Printf("Number attribute %f", t.Value())

	case ast.HashAttribute:
		log.Println("Hash attribute %v", t)
		for _, entry := range t.Entries {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(entry.Value)
			fields = append(fields, tmpFields...)
			envs = append(envs, tmpEnvs...)
		}

	case ast.ArrayAttribute:
		log.Println("Array attribute %v", t)
		for _, element := range t.Attributes {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(element)
			fields = append(fields, tmpFields...)
			envs = append(envs, tmpEnvs...)
		}

	default:
		log.Printf("Unknown Attribute Type `%s`", reflect.TypeOf(t))
	}
	return fields, envs
}


func getAllFieldNamesUsedInConditions(plugin_section []ast.PluginSection) ([]string, []string) {
	var fields[] string
	var envs[] string

	applyFunc := func(c *astutil.Cursor) {
		p := c.Plugin()

		for _, attr := range p.Attributes {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr)
			fields = append(fields, tmpFields...)
			envs = append(envs, tmpEnvs...)
		}

		log.Printf("Fields: %s", fields)
		log.Printf("Env %s", envs)

	}

	applyConditionFunc := func(c *ast.Condition) {
		fields = append(fields, collectFields(*c)...)
	}

	for _, element := range plugin_section {
		astutil.ApplyPluginsOrBranch(element.BranchOrPlugins, applyFunc, applyConditionFunc)
	}
	return fields, envs;
}



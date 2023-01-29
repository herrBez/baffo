package ecs_check

import (
	"os"
	"log"
	"strings"
	"fmt"
	"bytes"
	"regexp"
	"reflect"

	"github.com/breml/logstash-config/ast/astutil"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	config "github.com/breml/logstash-config"
	"github.com/breml/logstash-config/internal/format"
	ast "github.com/breml/logstash-config/ast"



)

type ECSCheck struct{}

func New() ECSCheck {
	return ECSCheck{}
}

type ConfigStats struct {
	Input PluginSectionStats
	Filter PluginSectionStats
	Output PluginSectionStats
}

type PluginSectionStats struct {
	PluginNames []string // Name of the Plugin
	PluginFields [] string // Fields used in the Plugin Definition
	PluginEnvs [] string // Env variables used in the Plugin Definition

	ConditionFields [] string // Fields used in the Branch Conditions
	ConditionEnvs [] string // Env variables used in the Branch Condition

	Fields []string // Cumulative Fields
	Envs []string // Cumulative Env Variables
}

func NewConfigStats() ConfigStats {
	return ConfigStats {
		Input: NewPluginSectionStats(),
		Filter: NewPluginSectionStats(),
		Output: NewPluginSectionStats(),
	}
}




func (cs ConfigStats) GlobalStats() PluginSectionStats {
	ps := NewPluginSectionStats()

	ps.merge(cs.Input)
	ps.merge(cs.Filter)
	ps.merge(cs.Output)

	return ps
}


func (c ConfigStats) String() string {
	var s bytes.Buffer

	s.WriteString("===INPUT===\n")
	s.WriteString(c.Input.String())
	s.WriteString("\n===\n")
	s.WriteString("===FILTER===\n")
	s.WriteString(c.Filter.String())
	s.WriteString("\n===\n")
	s.WriteString("\n===OUTPUT===\n")
	s.WriteString(c.Output.String())
	s.WriteString("\n===\n")
	s.WriteString("\n===CUMULATIVE===\n")
	s.WriteString(c.GlobalStats().String())
	s.WriteString("\n===\n")

	return s.String()
}

func NewPluginSectionStats() PluginSectionStats {
	return PluginSectionStats {
	}
}




func (ps PluginSectionStats) String() string {
	var s bytes.Buffer

	s.WriteString("[Plugin Names     ]:")
	fmt.Fprintf(&s, "%s", ps.PluginNames)
	s.WriteString("\n")
	s.WriteString("[Plugin Fields    ]:")
	fmt.Fprintf(&s, "%s", ps.PluginFields)
	s.WriteString("\n")
	s.WriteString("[Plugin Envs      ]:")
	fmt.Fprintf(&s, "%s", ps.PluginEnvs)
	s.WriteString("\n")
	s.WriteString("[Condition Fields ]:")
	fmt.Fprintf(&s, "%s", ps.ConditionFields)
	s.WriteString("\n")
	s.WriteString("[Condition Envs   ]:")
	fmt.Fprintf(&s, "%s", ps.ConditionEnvs)
	s.WriteString("\n")
	s.WriteString("[Cumulative Fields]:")
	fmt.Fprintf(&s, "%s", ps.Fields)
	s.WriteString("\n")
	s.WriteString("[Cumulative Envs  ]:")
	fmt.Fprintf(&s, "%s", ps.Envs)
	// s.WriteString(ps.Envs)

	return s.String()
}



func (pss *PluginSectionStats) AddPluginNames(names ...string) {
	pss.PluginNames = append(pss.PluginNames, names...)
}

func (pss *PluginSectionStats) AddPluginFields(names ...string) {
	pss.PluginFields = append(pss.PluginFields, names...)
	pss.Fields = append(pss.Fields, names...)
}


func (pss *PluginSectionStats) AddConditionFields(names ...string) {
	pss.ConditionFields = append(pss.ConditionFields, names...)
	pss.Fields = append(pss.Fields, names...)
}

func (pss *PluginSectionStats) AddPluginEnvs(names ...string) {
	pss.PluginEnvs = append(pss.PluginEnvs, names...)
	pss.Envs = append(pss.Envs, names...)
}


func (pss *PluginSectionStats) AddConditionEnvs(names ...string) {
	pss.ConditionEnvs = append(pss.ConditionEnvs, names...)
	pss.Envs = append(pss.Envs, names...)
}


func (pss *PluginSectionStats) merge(other PluginSectionStats) {
	// N.B. There are input, filter and output plugins with the same name (e.g., elasticsearch)
	pss.AddPluginNames(other.PluginNames...)
	pss.AddPluginFields(other.PluginFields...)
	pss.AddPluginEnvs(other.PluginEnvs...)
	pss.AddConditionFields(other.ConditionFields...)
	pss.AddConditionEnvs(other.ConditionEnvs...)
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
			cs := NewConfigStats()

			cs.Input = getAllFieldNamesUsedInConditions(tree.Input)
			cs.Filter = getAllFieldNamesUsedInConditions(tree.Filter)
			cs.Output = getAllFieldNamesUsedInConditions(tree.Output)

			log.Println(cs)

		}
	}

	if result != nil {
		result.ErrorFormat = format.MultiErr
		return result
	}

	return nil
}


func collectFields(n ast.Node) [] string {

	var variables [] string;
	var values [] string;

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


func getAllFieldNamesUsedInConditions(plugin_section []ast.PluginSection) (PluginSectionStats) {
	psStats := NewPluginSectionStats()

	applyPluginFunc := func(c *astutil.Cursor) {
		plugin := c.Plugin()
		psStats.AddPluginNames(plugin.Name())

		for _, attr := range plugin.Attributes {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr)
			psStats.AddPluginFields(tmpFields...)
			psStats.AddPluginEnvs(tmpEnvs...)
		}
	}

	applyConditionFunc := func(c *ast.Condition) {
		psStats.AddConditionFields(collectFields(*c)...)
	}

	for _, element := range plugin_section {
		astutil.ApplyPluginsOrBranch(element.BranchOrPlugins, applyPluginFunc, applyConditionFunc)
	}

	log.Println(psStats);

	return psStats;
}



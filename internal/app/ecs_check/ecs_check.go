package ecs_check

import (
	"os"
	"log"
	"strings"
	"fmt"
	"bytes"
	"regexp"
	"reflect"
	"path/filepath"

	"github.com/breml/logstash-config/ast/astutil"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	config "github.com/breml/logstash-config"
	"github.com/breml/logstash-config/internal/format"
	ast "github.com/breml/logstash-config/ast"
	// "github.com/breml/logstash-config/ecs_check/ecs_check_utils"



)

type ECSCheck struct{}

func New() ECSCheck {
	return ECSCheck{}
}

type ConfigStats struct {
	Input PluginSectionStats
	Filter PluginSectionStats
	Output PluginSectionStats
	PipelineOutput []string // List of Output Pipelines
	PipelineAddress string // List of Input Pipelines
	Filename string // Filename
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

func (cs * ConfigStats) merge(other ConfigStats) {
	cs.Input.merge(other.Input)
	cs.Filter.merge(other.Filter)
	cs.Output.merge(other.Output)
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


func appendUnique(arr []string, names ...string) []string {
	for _, name := range names {
		found := false
		for _, el := range arr {
			if el == name {
				found = true
				break
			}
		}
		if !found {
			arr = append(arr, name)
		}
	}
	return arr
}



func (pss *PluginSectionStats) AddPluginNames(names ...string) {
	pss.PluginNames = appendUnique(pss.PluginNames, names...)
}

func normalizeField(s string) string {
	if len(s) == 0 {
		return s
	}

	var tmp string = s
	// Convert to dotted notation
	// tmp = strings.Replace(s, "][", ".", -1)
	// tmp = strings.Replace(tmp, "[", "", 1)
	// tmp = strings.Replace(tmp, "]", "", 1)

	// Convert to Logstash's selector notation
	// if s[0] != '[' {
	// 	tmp = "[" + s + "]"
	// }
	return tmp
}

func normalizeFields(arr []string) []string {
	var res []string

	for _, el := range arr {
		res = append(res, normalizeField(el))
	}
	return res
}

func (pss *PluginSectionStats) AddPluginFields(names ...string) {
	pss.PluginFields = appendUnique(pss.PluginFields, normalizeFields(names)...)
	pss.Fields = appendUnique(pss.Fields, normalizeFields(names)...)
}


func (pss *PluginSectionStats) AddConditionFields(names ...string) {

	pss.ConditionFields = appendUnique(pss.ConditionFields, normalizeFields(names)...)
	pss.Fields = appendUnique(pss.Fields, normalizeFields(names)...)
}

func (pss *PluginSectionStats) AddPluginEnvs(names ...string) {
	pss.PluginEnvs = appendUnique(pss.PluginEnvs, names...)
	pss.Envs = appendUnique(pss.Envs, names...)
}


func (pss *PluginSectionStats) AddConditionEnvs(names ...string) {
	pss.ConditionEnvs = appendUnique(pss.ConditionEnvs, names...)
	pss.Envs = appendUnique(pss.Envs, names...)
}


func (pss *PluginSectionStats) merge(other PluginSectionStats) {
	// N.B. There are input, filter and output plugins with the same name (e.g., elasticsearch)
	pss.AddPluginNames(other.PluginNames...)
	pss.AddPluginFields(other.PluginFields...)
	pss.AddPluginEnvs(other.PluginEnvs...)
	pss.AddConditionFields(other.ConditionFields...)
	pss.AddConditionEnvs(other.ConditionEnvs...)
}

func WalkAllFilesInDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, e error) error {
			if e != nil {
					return e
			}

			// check if it is a regular file (not dir)
			if info.Mode().IsRegular() {
					fmt.Println("file name:", info.Name())
					fmt.Println("file path:", path)
			}
			return nil
	})
}



func (f ECSCheck) Run(args []string) error {
	var result *multierror.Error


	var files []string



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

	global_cs := NewConfigStats()

	for _, filename := range files {


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
			// fmt.Printf("%s\n", filename)
			var tree ast.Config = res.(ast.Config)
			log.Println(reflect.TypeOf(tree))

			cs := NewConfigStats()
			cs.Input = getAllFieldNamesUsedInConditions(tree.Input, "input")
			cs.Filter = getAllFieldNamesUsedInConditions(tree.Filter, "filter")
			cs.Output = getAllFieldNamesUsedInConditions(tree.Output, "output")

			cs.PipelineAddress = getPipelineAddress(tree.Input)
			if cs.PipelineAddress == "" {
				cs.PipelineAddress = filename
			}

			cs.PipelineOutput = getPipelineOutputAddress(tree.Output)

			log.Println(cs)

			global_cs.merge(cs)
			// cs.Filename = filename
			// fmt.Println(createGraph(cs))


		}
	}

	log.Println("---------------")

	log.Println(global_cs)

	if result != nil {
		result.ErrorFormat = format.MultiErr
		return result
	}

	return nil
}


func collectFields(n ast.Node) [] string {

	var fields [] string;


	switch node := n.(type) {

	case ast.Condition:
		for _, expression := range node.Expression {
			fields = append(fields, collectFields(expression)...)
		}

	case ast.ConditionExpression:
		fields = append(fields, collectFields(node.Condition)...)

	case ast.NegativeConditionExpression:
		fields = append(fields, collectFields(node.Condition)...)

	case ast.NegativeSelectorExpression:
		fields = append(fields, collectFields(node.Selector)...)

	case ast.InExpression:
		fields = append(fields, collectFields(node.LValue)...)
		fields = append(fields, collectFields(node.RValue)...)

	case ast.NotInExpression:
		fields = append(fields, collectFields(node.LValue)...)
		fields = append(fields, collectFields(node.RValue)...)

	case ast.RvalueExpression:
		fields = append(fields, collectFields(node.RValue)...)

	case ast.CompareExpression:
		fields = append(fields, collectFields(node.LValue)...)
		fields = append(fields, collectFields(node.CompareOperator)...)
		fields = append(fields, collectFields(node.RValue)...)

	case ast.RegexpExpression:
		fields = append(fields, collectFields(node.LValue)...)
		fields = append(fields, collectFields(node.RegexpOperator)...)
		fields = append(fields, collectFields(node.RValue)...)

	case ast.Selector:
		fields = append(fields, node.String())
	case ast.StringAttribute:
		// values = append(values, node.Value())

	case ast.CompareOperator:
		// do nothing

	case ast.RegexpOperator:
		// do nothing

	case ast.NumberAttribute:
		// do nothing

	case ast.Regexp:
		// do nothing

	case ast.ArrayAttribute:
		// TODO: Iterate over array attribute

	default:
		log.Panicf("Unknown type `%s`", reflect.TypeOf(node))
	}
	return fields
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
		log.Printf("String attribute %s and its value %s", t, t.Value())
		fields, envs = extractFieldsFromString(t.Value())
		// fields = append(fields, t.Name())


	case ast.NumberAttribute:
		log.Printf("Number attribute %f", t.Value())

	case ast.HashAttribute:
		log.Println("Hash attribute %v", t)
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
		log.Println("Array attribute %v", t)
		for _, element := range t.Attributes {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(element, keep_key)
			fields = append(fields, tmpFields...)
			envs = append(envs, tmpEnvs...)
		}

	default:
		log.Printf("Unknown Attribute Type `%s`", reflect.TypeOf(t))
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

func getPipelineAddress(plugin_section []ast.PluginSection) (string) {
	var pipelineAddress string

	applyPluginFunc := func(c *astutil.Cursor) {
		plugin := c.Plugin()

		if plugin.Name() == "pipeline" {
			for _, attr := range plugin.Attributes {
				if attr.Name() == "address" {
					switch t := attr.(type) {

					case ast.StringAttribute:
						pipelineAddress = t.Value()
					default:
						log.Panicf("Known translate attribute should be of type string?")
					}
				}
			}
		}
	}

	for _, element := range plugin_section {
		astutil.ApplyPlugins(element.BranchOrPlugins, applyPluginFunc)
	}

	return pipelineAddress
}

func getPipelineOutputAddress(plugin_section []ast.PluginSection) ([]string) {
	var OutputPipelines []string
	var count int = 0

	applyPluginFunc := func(c *astutil.Cursor) {
		plugin := c.Plugin()

		if plugin.Name() == "pipeline" {
			for _, attr := range plugin.Attributes {
				if attr.Name() == "send_to" {
					switch t := attr.(type) {

					case ast.StringAttribute:
						OutputPipelines = append(OutputPipelines, t.Value())
					default:
						log.Panicf("Known translate attribute should be of type string?")
					}
				}
			}
		} else {
			count += 1
			OutputPipelines = append(OutputPipelines, fmt.Sprintf("%s-%d", plugin.Name(), count))
		}
	}

	for _, element := range plugin_section {
		astutil.ApplyPlugins(element.BranchOrPlugins, applyPluginFunc)
	}

	return OutputPipelines
}


type DealWithPlugin func(ps * PluginSectionStats, plugin ast.Plugin)




var inputFilterPluginMap = map[string]DealWithPlugin {
	"pipeline": DealWithPluginWithoutFields,
}

var filterPluginMap = map[string]DealWithPlugin{
	"grok": DealWithGrok,
	"dissect": DealWithDissect,
	"translate": DealWithTranslate,
}

var outputFilterPluginMap = map[string]DealWithPlugin{
	"elasticsearch": DealWithOutputElasticsearch,
	"pipeline": DealWithPluginWithoutFields,
}

var globalPluginMap = map[string](map[string]DealWithPlugin) {
	"input": inputFilterPluginMap,
	"filter": filterPluginMap,
	"output": outputFilterPluginMap,
}



func getAllFieldNamesUsedInConditions(plugin_section []ast.PluginSection, section string) (PluginSectionStats) {
	psStats := NewPluginSectionStats()

	applyPluginFunc := func(c *astutil.Cursor) {
		plugin := c.Plugin()
		psStats.AddPluginNames(plugin.Name())

		// Get rid of default attributes
		var common_attr_list []ast.Attribute

		var plugin_specific_attr []ast.Attribute

		for _, attr := range plugin.Attributes {
			if contains([]string{"add_field", "add_tag", "enable_metric", "id", "periodic_flush", "remove_field", "remove_tag"}, attr.Name()) {
				common_attr_list = append(common_attr_list, attr)
			} else {
				plugin_specific_attr = append(plugin_specific_attr, attr)
			}
		}

		for _, attr := range common_attr_list {
			switch attr.Name() {
				// Common Option
				// HashKey --> Field
				// HashValue --> Deal with expansion
			case "add_field", "remove_field":
				log.Println(attr)
				tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, true)
				psStats.AddPluginFields(tmpFields...)
				psStats.AddPluginEnvs(tmpEnvs...)

			case "add_tag", "remove_tag":
				log.Println(attr)
				tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, false)
				psStats.AddPluginFields(tmpFields...)
				psStats.AddPluginEnvs(tmpEnvs...)

			default:
				// add_tag, enable_metric, id, periodic_flush
				// Do nothing --> they cannot contain anything interesting
			}
		}

		myFunc, found := globalPluginMap[section][plugin.Name()]

		if found  {
			if plugin != nil {
				log.Println(plugin.Name())
				myFunc(&psStats, *plugin)
			}
		} else { // Apply Default-Unknown Case
			DealWithGenericPlugin(&psStats, *plugin)
		}


		for _, f := range psStats.Fields {
			if strings.Contains(f, ".") {
				log.Printf("Warning: field %s contain dots and does not using Logstash's Field Selector convention")
			}
		}

	}

	applyConditionFunc := func(c *ast.Condition) {
		psStats.AddConditionFields(collectFields(*c)...)
	}

	for _, element := range plugin_section {
		astutil.ApplyPluginsOrBranch(element.BranchOrPlugins, applyPluginFunc, applyConditionFunc)
	}
	return psStats;
}


// https://mermaid.live/edit
func createGraph(cs ConfigStats) string {
	var s bytes.Buffer

	//  s.WriteString("graph TD\n")
	for _, output := range cs.PipelineOutput {
		if cs.PipelineAddress != "" {
			s.WriteString(cs.PipelineAddress)
		} else {
			s.WriteString(cs.Filename)
		}
		s.WriteString(" --> ")
		s.WriteString(output)
		s.WriteString("\n")
	}


	return s.String()
}

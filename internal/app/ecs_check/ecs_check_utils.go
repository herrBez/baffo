package ecs_check

import (
	// "os"
	"strings"
	"fmt"
	"bytes"
	// "regexp"
	// "reflect"
	"github.com/rs/zerolog/log"

	"github.com/breml/logstash-config/ast/astutil"
	// "github.com/hashicorp/go-multierror"
	// "github.com/pkg/errors"
	// config "github.com/breml/logstash-config"
	// "github.com/breml/logstash-config/internal/format"
	ast "github.com/breml/logstash-config/ast"

	// "path/filepath"

)


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

	FieldsAddedByThePlugin []string // Fields added by the plugin

	FieldsUsedByThePlugin [] string // Fields used in the Plugin Definition
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
	s.WriteString("[Fields Added     ]")
	fmt.Fprintf(&s, "%s", ps.FieldsAddedByThePlugin)
	s.WriteString("\n")
	s.WriteString("[Fields Used      ]:")
	fmt.Fprintf(&s, "%s", ps.FieldsUsedByThePlugin)
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

func (pss *PluginSectionStats) AddFieldsUsedByThePlugin(names ...string) {
	pss.FieldsUsedByThePlugin = appendUnique(pss.FieldsUsedByThePlugin, normalizeFields(names)...)
	pss.Fields = appendUnique(pss.Fields, normalizeFields(names)...)
}

func (pss *PluginSectionStats) AddFieldsAddedByThePlugin(names ...string) {
	pss.FieldsAddedByThePlugin = appendUnique(pss.FieldsAddedByThePlugin, names...)
	// TODO Add to "Fields"
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
	pss.AddFieldsAddedByThePlugin(other.FieldsAddedByThePlugin...)
	pss.AddFieldsUsedByThePlugin(other.FieldsUsedByThePlugin...)
	pss.AddPluginEnvs(other.PluginEnvs...)
	pss.AddConditionFields(other.ConditionFields...)
	pss.AddConditionEnvs(other.ConditionEnvs...)
}


type ECSCompatibilityDefinedFields struct {
	Input map[string]map[string][]string `json:"input"`
	Filter map[string]map[string][]string  `json:"filter"`
	Output map[string]map[string][]string `json:"output"`
}

// type AddedPluginField struct{
// 	V8 []string `json:"v8"`
// 	Disabled []string `json: "disabled"`
// }


type DealWithPlugin func(ps * PluginSectionStats, plugin ast.Plugin)


var inputFilterPluginMap = map[string]DealWithPlugin {
	"pipeline": DealWithPluginWithoutFields,
	"beats": DealWithPluginWithoutFields,
	"file": DealWithPluginWithoutFields,
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


// Pipeline input, output do not contain fields
func DealWithPluginWithoutFields(psStats * PluginSectionStats, plugin ast.Plugin) {
	// Do Nothing
}

func DealWithGenericPlugin(psStats * PluginSectionStats, plugin ast.Plugin) {
	for _, attr := range plugin.Attributes {
		tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, false)
		psStats.AddFieldsUsedByThePlugin(tmpFields...)
		psStats.AddPluginEnvs(tmpEnvs...)
	}
}


func DealWithTranslate(psStats * PluginSectionStats, plugin ast.Plugin) {
	for _, attr := range plugin.Attributes {
		if contains([]string {"iterate_on", "source", "target", "destination"}, attr.Name()) {
			switch t := attr.(type) {

			case ast.StringAttribute:
				psStats.AddFieldsUsedByThePlugin(t.Value())

			default:
				log.Panic().Msgf("Known translate attribute '%s' should be of type string?", attr.Name())
			}

		}
	}
}

func DealWithInputFile(psStats * PluginSectionStats, plugin ast.Plugin) {
	// ecs_compatibility = "disabled" // TODO: Take the default?
	// for _, attr := range plugin.Attributes {
	// 	if attr.Name() == "ecs_compatibility" {
	// 		if attr.Value() == "disabled" {
	// 			psStats.AddedPluginFields = append(psStats.AddedPluginFields, []string{"[host][name]", "[log][file][path]"})
	// 		} else {
	// 			psStats.AddedPluginFields = append(psStats.AddedPluginFields, []string{"[host][name]", "[log][file][path]"})
	// 		}
	// 	}
	// }
}

// Grok-Match Attribute should be treated differently
func DealWithGrok(psStats * PluginSectionStats, plugin ast.Plugin) {

	for _, attr := range plugin.Attributes {
		if attr.Name() == "match" {
			tmpFields, _ := getAllFieldsNamesUsedInAttribute(attr, false)

			log.Debug().Msgf("Extracted the following %d raw grok fields %s", len(tmpFields), tmpFields)

			// Grok Match expression are in the form %{TEST:[foo]}
			// After the getAllFieldsNamesUsedInAttribute TEST:[foo]
			// We need to extract the field list [foo]
			for _, tf := range tmpFields {

				res := strings.Split(tf, ":")

				switch len(res) {
				case 1:
					// It is only a pattern the fields can be find in the logstash-pattern-core
					log.Printf("Warning [Line %d]: the pattern `%s` relies on ecs_compatibility", attr.Pos().Line, res[0])
				case 2:
					psStats.AddFieldsUsedByThePlugin(res[1])

				case 3:
					// %{PATTERN:FIELD:TYPE}
					psStats.AddFieldsAddedByThePlugin(res[1])

				default:
					log.Panic().Msgf("Grok: unexpected filter with %s", res)
				}
			}
		} else {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, false)
			psStats.AddFieldsUsedByThePlugin(tmpFields...)
			psStats.AddPluginEnvs(tmpEnvs...)
		}
	}
}

func DealWithDissect(psStats * PluginSectionStats, plugin ast.Plugin) {

	for _, attr := range plugin.Attributes {
		if(attr.Name() == "mapping") {

			tmpFields, _ := getAllFieldsNamesUsedInAttribute(attr, false)

			// Grok Match expression are in the form %{TEST:[foo]}
			// After the getAllFieldsNamesUsedInAttribute TEST:[foo]
			// We need to extract the field list [foo]
			for _, tf := range tmpFields {

				ttf := strings.Replace(tf, "->", "", -1)
				ttf = strings.Replace(ttf, "+", "", -1)
				ttf = strings.Replace(ttf, "?", "", -1)
				psStats.AddFieldsUsedByThePlugin(ttf)
			}

	} else {
		tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, false)
		psStats.AddFieldsUsedByThePlugin(tmpFields...)
		psStats.AddPluginEnvs(tmpEnvs...)
	}
	}
}

func DealWithOutputElasticsearch(psStats * PluginSectionStats, plugin ast.Plugin) {
	for _, attr := range plugin.Attributes {
		if contains(
			[]string {"action", "api_key",
			"bulk_path", "cacert", "ca_trusted_fingerprint",
			"cloud_auth", "cloud_id", "data_stream_auto_routing",
			"data_stream_sync_fields", "dlq_custom_code", "dlq_on_failed_indexname_interpolation",
			"doc_as_upsert", "ecs_compatibility", "http_compression", "ilm_enabled",
			"ilm_pattern", "ilm_policy", "ilm_rollover_alias", "keystore", "keystore_password", "manage_template",
			"parameters", "password", "path", "pool_max", "pool_max_per_route", "resurrect_delay", "retry_initial_interval",
			"retry_max_interval", "retry_on_conflict", "silence_errors_in_log", "timeout", "truststore_password", "user", "validate_after_inactivity", "version",
			"version_type"}, attr.Name()) ||
			strings.HasPrefix(attr.Name(), "script") || strings.HasPrefix(attr.Name(), "sniff") || strings.HasPrefix(attr.Name(), "ssl") ||
			strings.HasPrefix(attr.Name(), "template") {
			// Ignore
		} else {
			tmpFields, tmpEnvs := getAllFieldsNamesUsedInAttribute(attr, false)
			psStats.AddFieldsUsedByThePlugin(tmpFields...)
			psStats.AddPluginEnvs(tmpEnvs...)
		}
	}
}



// Func to extract the pipeline address if available
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
						log.Panic().Msg("Known translate attribute should be of type string?")
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

// Func to extract the pipeline output if available
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
						log.Panic().Msgf("Known translate attribute should be of type string?")
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


// Func to create a pipeline-to-pipeline communication graph on https://mermaid.live/edit
func createGraph(cs ConfigStats) string {
	var s bytes.Buffer

	s.WriteString("graph TD\n")
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
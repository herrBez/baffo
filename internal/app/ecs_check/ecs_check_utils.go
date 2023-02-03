package ecs_check

import (
	// "os"
	"log"
	"strings"
	// "fmt"
	// "bytes"
	// "regexp"
	// "reflect"

	// "github.com/breml/logstash-config/ast/astutil"
	// "github.com/hashicorp/go-multierror"
	// "github.com/pkg/errors"
	// config "github.com/breml/logstash-config"
	// "github.com/breml/logstash-config/internal/format"
	ast "github.com/breml/logstash-config/ast"

	// "path/filepath"

)

type ECSCompatibilityDefinedFields struct {
	Input map[string]map[string][]string `json:"input"`
	Filter map[string]map[string][]string  `json:"filter"`
	Output map[string]map[string][]string `json:"output"`
}

// type AddedPluginField struct{
// 	V8 []string `json:"v8"`
// 	Disabled []string `json: "disabled"`
// }

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
				log.Panicf("Known translate attribute should be of type string?")
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

			log.Printf("Aiuto %s", tmpFields)

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

				default:
					log.Panic("D: %s", res)
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

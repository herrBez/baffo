package transpile

import (
	"strconv"

	ast "github.com/herrBez/logstash-config/ast"
	"github.com/rs/zerolog/log"
)

// Utility File that contains all utility functions to deal with Logstash Attributes

func hashAttributeToMapArray(attr ast.Attribute) map[string][]string {
	m := map[string][]string{}
	switch tattr := attr.(type) {
	case ast.HashAttribute:
		for _, entry := range tattr.Entries {
			var keyString string
			var values []string

			switch tKey := entry.Key.(type) {
			case ast.StringAttribute:
				keyString = tKey.Value()
			default:
				log.Panic().Msg("Expecting a string for the keys")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute:
				values = []string{getStringAttributeString(tValue)}
			case ast.ArrayAttribute:
				values = getArrayStringAttributes(tValue)
			default:
				log.Panic().Msg("Expecting a string")
			}

			m[keyString] = values
		}
	}
	return m
}

func getBoolValue(attr ast.Attribute) bool {
	rawString := getStringAttributeString(attr)
	if rawString == "true" {
		return true
	} else if rawString == "false" {
		return false
	}
	log.Panic().Msg("Unexpected")
	return false
}

func getHashAttributeKeyValueUntyped(attr ast.Attribute) ([]string, []interface{}) {
	var keys []string
	var values []interface{}
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

				if tValue.Value() == "true" || tValue.Value() == "false" {
					bv, _ := strconv.ParseBool(tValue.Value())

					values = append(values, bv)
				} else {
					values = append(values, toElasticPipelineSelector(tValue.Value()))
				}

			case ast.NumberAttribute:

				values = append(values, tValue.Value())

			default:
				log.Panic().Msg("Unexpected value type of type not string")
			}
		}
	// // For the Rename use-case
	// case ast.ArrayAttribute:
	// 	arrays := getArrayStringAttributes(attr)
	// 	if len(arrays)%2 != 0 {
	// 		log.Panic().Msg("Hash expected but an uneven list is provided")
	// 	}
	// 	for i := 0; i < len(arrays); i += 2 {
	// 		keys = append(keys, arrays[i])
	// 		values = append(values, arrays[i+1])
	// 	}

	default: // Unexpected Case --> PANIC
		log.Panic().Msgf("Unexpected Case %s", attr.String())
	}
	return keys, values
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
				values = append(values, toElasticPipelineSelector(tValue.Value()))
			case ast.NumberAttribute:
				// TODO: Fix the return value of the function or add a new function
				log.Warn().Msg("Converting a number to string")
				values = append(values, tValue.ValueString())

			default:
				log.Panic().Msg("Unexpected value type of type not string")
			}
		}
	// For the Rename use-case
	case ast.ArrayAttribute:
		arrays := getArrayStringAttributes(attr)
		if len(arrays)%2 != 0 {
			log.Panic().Msg("Hash expected but an uneven list is provided")
		}
		for i := 0; i < len(arrays); i += 2 {
			keys = append(keys, arrays[i])
			values = append(values, arrays[i+1])
		}

	default: // Unexpected Case --> PANIC
		log.Panic().Msgf("Unexpected Case %s", attr.String())
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
	case ast.StringAttribute:
		values = append(values, getStringAttributeString(tattr))

	default:
		log.Panic().Msg("I will only an array of strings")
	}
	return values
}

func getArrayStringAttributeOrStringAttrubute(attr ast.Attribute) []string {
	var values []string
	switch tattr := attr.(type) {
	case ast.ArrayAttribute:
		for _, el := range tattr.Attributes {
			values = append(values, getStringAttributeString(el))
		}
	case ast.StringAttribute:
		values = append(values, getStringAttributeString(attr))
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

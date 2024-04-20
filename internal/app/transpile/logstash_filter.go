package transpile

import (
	"log"

	ast "github.com/breml/logstash-config/ast"
)

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
				log.Panicf("Expecting a string for the keys")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute:
				values = []string{getStringAttributeString(tValue)}
			case ast.ArrayAttribute:
				values = getArrayStringAttributes(tValue)
			default:
				log.Panicf("Expecting a string")
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
	log.Panicf("Unexpected")
	return false
}

package transpile

import (
	"log"

	ast "github.com/breml/logstash-config/ast"
)

type CommonFilterAttributes struct {
	AddField      map[string]string
	AddTag        []string
	EnableMetric  bool
	ID            string
	PeriodicFlush bool
	RemoveField   []string
	RemoveTag     []string
}

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

func NewCommonFilterAttributes(plugin ast.Plugin) CommonFilterAttributes {
	id, err := plugin.ID()
	if err != nil {
		// Autogenerate plugin-id
		id = plugin.Name() + "-" + randomString(2)
	}

	cfa := CommonFilterAttributes{
		ID: id,
	}

	for _, attr := range plugin.Attributes {
		switch attr.Name() {
		case "id": // Do nothing already dealt with
		case "add_field":
			cfa.AddField = hashAttributeToMap(attr)
		case "remove_field":
			cfa.RemoveField = getArrayStringAttributes(attr)
		case "add_tags":
			cfa.AddTag = getArrayStringAttributes(attr)
		case "remove_tags":
			cfa.RemoveTag = getArrayStringAttributes(attr)
		case "enable_metrics":
			cfa.EnableMetric = getBoolValue(attr)
		case "periodic_flush":
			cfa.PeriodicFlush = getBoolValue(attr)
			// Ignore all other attributes
		}
	}
	return cfa
}

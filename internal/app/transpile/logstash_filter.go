package transpile 

import (
ast "github.com/breml/logstash-config/ast"
"log"
)

type CommonFilterAttributes struct {
	AddField map[string]string
	AddTag []string
	EnableMetric bool
	ID           string 
	PeriodicFlush bool 
	RemoveField   []string
	RemoveTag []string
}


type GrokFilterPlugin struct {
	BreakOnMatch bool 
	ECSCompatibility string
	KeepEmptyCaptures bool
	Match map[string][]string // Single strings will be written in an array
	NamedCapturesOnly bool
	Overwrite bool 
	PatternDefinitions map[string]string 
	PatternsDir []string
	PatternsFileGlob []string 
	TagOnFailure []string 
	TimeoutMillis int 
	TimeoutScope string 
	CommonAttributes CommonFilterAttributes
}


func getStringPointer(s string) *string {
	t := s 
	return &t
}


func hashAttributeToMapArray(attr ast.Attribute) map[string][]string {
	m := map[string][]string{}
	switch tattr := attr.(type) {
	case ast.HashAttribute:
		for _, entry := range tattr.Entries {
			var keyString string
			var values []string
			
			switch tKey := entry.Key.(type) {
			case ast.StringAttribute: keyString = tKey.Value()
			default: log.Panicf("Expecting a string for the keys")
			}

			switch tValue := entry.Value.(type) {
			case ast.StringAttribute: values = []string{getStringAttributeString(tValue)}
			case ast.ArrayAttribute: values = getArrayStringAttributes(tValue)
			default: log.Panicf("Expecting a string")
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
		case "add_field": cfa.AddField = hashAttributeToMap(attr)
		case "remove_field": cfa.RemoveField = getArrayStringAttributes(attr)
		case "add_tags": cfa.AddTag = getArrayStringAttributes(attr)
		case "remove_tags": cfa.RemoveTag = getArrayStringAttributes(attr)
		case "enable_metrics": cfa.EnableMetric = getBoolValue(attr)
		case "periodic_flush": cfa.PeriodicFlush = getBoolValue(attr)

		}
	}
	return cfa
}

func NewGrok(plugin ast.Plugin) {
	// Default Values
	gfp := GrokFilterPlugin{
		ECSCompatibility: "v8",
		CommonAttributes: NewCommonFilterAttributes(plugin),
	}

	for _, attr := range plugin.Attributes {
		
		switch attr.Name() {
		// It is a common field
		case "match":
			gfp.Match = hashAttributeToMapArray(attr)
		case "ecs_compatibility":
			gfp.ECSCompatibility = getStringAttributeString(attr)
		case "pattern_definitions":
			gfp.PatternDefinitions = hashAttributeToMap(attr)
		case "tag_on_failure":
			gfp.TagOnFailure = getArrayStringAttributes(attr)
			
		}
	}
}
package ecs_check

import (
	"os"
	"log"
	// "strings"
	// "fmt"
	"github.com/breml/logstash-config/ast/astutil"



	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	config "github.com/breml/logstash-config"
	"github.com/breml/logstash-config/internal/format"
	"reflect"
	
	
	ast "github.com/breml/logstash-config/ast"

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

			// Analyze Input
			log.Println(input_plugin_names)
			log.Println(filter_plugin_names)
			log.Println(output_plugin_names)
		
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
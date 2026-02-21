package ecs_check

import (
	"fmt"
	"log"
	"os"

	// "strings"
	// "fmt"
	"github.com/herrBez/baffo/ast/astutil"

	"errors"
	"reflect"

	config "github.com/herrBez/baffo"

	ast "github.com/herrBez/baffo/ast"
)

type ECSCheck struct{}

func New() ECSCheck {
	return ECSCheck{}
}

func (f ECSCheck) Run(args []string) error {
	var result error
	for _, filename := range args {
		stat, err := os.Stat(filename)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%s: %v", filename, err))
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
			// 		err = fmt.Errorf("%s: %v\n%s", filename, err, errMsg)
			// 	}
			// }
			// result = errors.Join(result, fmt.Errorf("%s: %v", filename, err))
			// continue
		} else {
			var tree ast.Config = res.(ast.Config)
			log.Println(reflect.TypeFor[ast.Config]())

			var input_plugin_names []string = getAllPluginNames(tree.Input)
			var filter_plugin_names []string = getAllPluginNames(tree.Filter)
			var output_plugin_names []string = getAllPluginNames(tree.Output)

			// Analyze Input
			log.Println(input_plugin_names)
			log.Println(filter_plugin_names)
			log.Println(output_plugin_names)

		}
	}

	if result != nil {
		return result
	}

	return nil
}

func getAllPluginNames(plugin_section []ast.PluginSection) []string {
	var plugin_names []string
	applyFunc := func(c *astutil.Cursor) {
		// count++
		plugin_names = append(plugin_names, c.Plugin().Name())
	}

	for _, element := range plugin_section {
		astutil.ApplyPlugins(element.BranchOrPlugins, applyFunc)
	}
	return plugin_names
}

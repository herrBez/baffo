package check

import (
	"fmt"
	"os"
	"strings"

	"errors"

	config "github.com/herrBez/baffo"
)

type Check struct{}

func New() Check {
	return Check{}
}

func (f Check) Run(args []string) error {
	var result error

	for _, filename := range args {
		stat, err := os.Stat(filename)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("%s: %v", filename, err))
		}
		if stat.IsDir() {
			continue
		}

		_, err = config.ParseFile(filename, config.IgnoreComments(true))
		if err != nil {
			if errMsg, hasErr := config.GetFarthestFailure(); hasErr {
				if !strings.Contains(err.Error(), errMsg) {
					err = fmt.Errorf("%s: %v\n%s", filename, err, errMsg)
				}
			}
			result = errors.Join(result, fmt.Errorf("%s: %v", filename, err))
			continue
		}
	}

	if result != nil {
		return result
	}

	return nil
}

package util

import (
	"errors"
	"fmt"
	"os"

	"codeberg.org/iklabib/kaleng/model"
	"github.com/elastic/go-ucfg/yaml"
)

func LoadConfig(path string) (model.KalengConfig, error) {
	var config model.KalengConfig

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			MessageBail("config file does not exist")
		} else {
			MessageBail("failed to check config file")
		}
	}

	// yaml is super set of json anyway
	cfg, err := yaml.NewConfigWithFile(path)
	if err != nil {
		return config, nil
	}

	if err := cfg.Unpack(&config); err != nil {
		return config, err
	}

	return config, nil
}

var INTERNAL_ERROR = -1

func Bail(err error) {
	if err != nil {
		format := "{\"stdout\":\"\",\"stderr\":\"\"\"message\":\"%v\",\"metric\":{\"signal\":0,\"exit_code\":-1,\"sys_time\":0,\"time\":0},\"status\":false}\n"
		fmt.Printf(format, err)
		os.Exit(INTERNAL_ERROR)
	}
}

func MessageBail(msg string) {
	format := "{\"stdout\":\"\",\"stderr\":\"\"\"message\":\"%s\",\"metric\":{\"signal\":0,\"exit_code\":-1,\"sys_time\":0,\"time\":0},\"status\":false}\n"
	fmt.Printf(format, msg)
	os.Exit(INTERNAL_ERROR)
}

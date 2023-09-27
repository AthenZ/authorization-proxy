/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/AthenZ/authorization-proxy/v4/usecase"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// Version is set by the build command via LDFLAGS
var Version string

// params is the data model for Authorization Proxy command line arguments.
type params struct {
	configFilePath string
	showVersion    bool
}

// parseParams parses command line arguments to params object.
func parseParams() (*params, error) {
	p := new(params)
	f := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	f.StringVar(&p.configFilePath,
		"f",
		"/etc/athenz/provider/config.yaml",
		"authorization-proxy config yaml file path")
	f.BoolVar(&p.showVersion,
		"version",
		false,
		"show authorization-proxy version")

	err := f.Parse(os.Args[1:])
	if err != nil {
		return nil, errors.Wrap(err, "Parse Failed")
	}

	return p, nil
}

// run starts the daemon and listens for OS signal.
func run(cfg config.Config) []error {
	g := glg.Get().SetMode(glg.NONE)

	switch cfg.Log.Level {
	case "":
		// disable logging
	case "fatal":
		g = g.SetLevelMode(glg.FATAL, glg.STD)
	case "error":
		g = g.SetLevelMode(glg.FATAL, glg.STD).
			SetLevelMode(glg.ERR, glg.STD)
	case "warn":
		g = g.SetLevelMode(glg.FATAL, glg.STD).
			SetLevelMode(glg.ERR, glg.STD).
			SetLevelMode(glg.WARN, glg.STD)
	case "info":
		g = g.SetLevelMode(glg.FATAL, glg.STD).
			SetLevelMode(glg.ERR, glg.STD).
			SetLevelMode(glg.WARN, glg.STD).
			SetLevelMode(glg.INFO, glg.STD)
	case "debug":
		g = g.SetLevelMode(glg.FATAL, glg.STD).
			SetLevelMode(glg.ERR, glg.STD).
			SetLevelMode(glg.WARN, glg.STD).
			SetLevelMode(glg.INFO, glg.STD).
			SetLevelMode(glg.DEBG, glg.STD)
	default:
		return []error{errors.New("invalid log level")}
	}

	if !cfg.Log.Color {
		g.DisableColor()
	}

	daemon, err := usecase.New(cfg)
	if err != nil {
		return []error{errors.Wrap(err, "usecase returned error")}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err = daemon.Init(ctx); err != nil {
		return []error{errors.Wrap(err, "daemon init error")}
	}

	ech := daemon.Start(ctx)
	sigCh := make(chan os.Signal, 1)

	defer func() {
		close(sigCh)
		// close(ech)
	}()

	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	isSignal := false
	for {
		select {
		case sig := <-sigCh:
			glg.Infof("authorization proxy received signal: %v", sig)
			isSignal = true
			cancel()
			glg.Warn("authorization proxy main process shutdown...")
		case errs := <-ech:
			if !isSignal || len(errs) != 1 || errs[0] != ctx.Err() {
				return errs
			}
			return nil
		}
	}
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			if _, ok := err.(runtime.Error); ok {
				panic(err)
			}
			glg.Error(err)
		}
	}()

	p, err := parseParams()
	if err != nil {
		glg.Fatal(errors.Wrap(err, "parseParams returned error"))
		return
	}

	if p.showVersion {
		glg.Infof("authorization-proxy version -> %s", getVersion())
		glg.Infof("authorization-proxy config version -> %s", config.GetVersion())
		return
	}

	cfg, err := config.New(p.configFilePath)
	if err != nil {
		glg.Fatal(errors.Wrap(err, "config instance create error"))
		return
	}

	// check versions between configuration file and config.go
	if cfg.Version != config.GetVersion() {
		glg.Fatal(errors.New("invalid sidecar configuration version"))
		return
	}

	errs := run(*cfg)
	if len(errs) > 0 {
		var emsg string
		for _, err = range errs {
			emsg += "\n" + err.Error()
		}
		glg.Fatal(emsg)
		return
	}
	glg.Info("authorization proxy main process shutdown success")
	/*
		For some reason, if only Sidecar has terminated while the main application continues to run,
		the exit status is set to 1 to prevent the main application from continuing to operate alone.
		During the development of Sidecar, we found a pattern where even if some containers within a Pod in Kubernetes exit with status 0,
		the Pod as a whole continues to operate.
		By setting the exit status of Sidecar to 1,
		it is expected that the entire Pod will be restarted from the Kubernetes side under any circumstances.
	*/
	os.Exit(1)
}

func getVersion() string {
	if Version == "" {
		return "development version"
	}
	return Version
}

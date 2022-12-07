package main

import (
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AthenZ/authorization-proxy/v4/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

func TestParseParams(t *testing.T) {
	type test struct {
		name       string
		beforeFunc func()
		checkFunc  func(*params) error
		checkErr   bool
	}
	tests := []test{
		func() test {
			return test{
				name: "check parseParams set default value",
				beforeFunc: func() {
					os.Args = []string{""}
				},
				checkFunc: func(p *params) error {
					if p.configFilePath != "/etc/athenz/provider/config.yaml" {
						return errors.Errorf("unexpected file path. got: %s, want: /etc/athenz/provider/config.yaml", p.configFilePath)
					}
					if p.showVersion != false {
						return errors.Errorf("unexpected showVersion flag. got: %v, want : false", p.showVersion)
					}
					return nil
				},
				checkErr: false,
			}
		}(),
		func() test {
			return test{
				name: "check parse error",
				checkFunc: func(p *params) error {
					return nil
				},
				beforeFunc: func() {
					os.Args = []string{"", "-="}
				},
				checkErr: true,
			}
		}(),
		func() test {
			return test{
				name: "check parseParams set user flags",
				beforeFunc: func() {
					os.Args = []string{"", "-f", "/dummy/path", "-version", "true"}
				},
				checkFunc: func(p *params) error {
					if p.configFilePath != "/dummy/path" {
						return errors.Errorf("unexpected file path. got: %s, want: /dummy/path", p.configFilePath)
					}
					if p.showVersion != true {
						return errors.Errorf("unexpected showVersion flag. got: %v, want: true", p.showVersion)
					}

					return nil
				},
				checkErr: false,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func(oldArgs []string) {
				// restore os.Args
				os.Args = oldArgs
			}(os.Args)
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}

			got, err := parseParams()
			if err != nil && !tt.checkErr {
				t.Errorf("unexpected error: %v", err)
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("checkFunc() error: %v", err)
			}
		})
	}
}

func Test_run(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	type test struct {
		name      string
		args      args
		checkFunc func([]error) error
	}
	tests := []test{
		{
			name: "run with log level, default",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.NONE,
					glg.NONE,
					glg.NONE,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, fatal",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "fatal",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.NONE,
					glg.NONE,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, error",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "error",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.NONE,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, warn",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "warn",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.STD,
					glg.NONE,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, info",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "info",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.STD,
					glg.STD,
					glg.NONE,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log level, debug",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "debug",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				g := glg.Get()
				got := []glg.MODE{
					g.GetCurrentMode(glg.FATAL),
					g.GetCurrentMode(glg.ERR),
					g.GetCurrentMode(glg.WARN),
					g.GetCurrentMode(glg.INFO),
					g.GetCurrentMode(glg.DEBG),
				}
				want := []glg.MODE{
					glg.STD,
					glg.STD,
					glg.STD,
					glg.STD,
					glg.STD,
				}
				if !reflect.DeepEqual(got, want) {
					return errors.Errorf("got: %v, want: %v", got, want)
				}
				return nil
			},
		},
		{
			name: "run with log color",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "invalid://url",
					},
					Log: config.Log{
						Level: "info",
						Color: true,
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				wantExitingErr := "usecase returned error: cannot newAuthzD(cfg): error creating authorizerd: Unsupported scheme, only support HTTP or HTTPS"
				if gotErrs == nil || gotErrs[0].Error() != wantExitingErr {
					return errors.Errorf("Unexpected exit: %v", gotErrs)
				}

				// glg.logger.isColor is private, cannot test
				return nil
			},
		},
		{
			name: "invalid log level",
			args: args{
				cfg: config.Config{
					Log: config.Log{
						Level: "invalid",
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				want := "invalid log level"
				if len(gotErrs) != 1 {
					return errors.New("len(gotErrs) != 1")
				}
				if gotErrs[0].Error() != want {
					return errors.Errorf("gotErrs: %v, want: %v", gotErrs[0], want)
				}
				return nil
			},
		},
		{
			name: "run error",
			args: args{
				cfg: config.Config{
					Authorization: config.Authorization{
						PublicKey: config.PublicKey{
							RefreshPeriod: "dummy",
						},
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				want := `usecase returned error: cannot newAuthzD(cfg): error create pubkeyd: invalid refresh period: time: invalid duration "dummy"`
				if len(gotErrs) != 1 {
					return errors.New("len(gotErrs) != 1")
				}
				if gotErrs[0].Error() != want {
					return errors.Errorf("gotErr: %v, want: %v", gotErrs[0], want)
				}
				return nil
			},
		},
		{
			name: "daemon init error",
			args: args{
				cfg: config.Config{
					Athenz: config.Athenz{
						URL: "127.0.0.1",
					},
					Authorization: config.Authorization{
						RoleToken: config.RoleToken{
							Enable: true,
						},
					},
				},
			},
			checkFunc: func(gotErrs []error) error {
				want1 := "daemon init error: error when processing pubkey: Error updating ZMS athenz pubkey: error fetch public key entries: error make http request: Get \"https://127.0.0.1/domain/sys.auth/service/zms\": dial tcp 127.0.0.1:443: connect: connection refused"
				want2 := "daemon init error: error when processing pubkey: Error updating ZTS athenz pubkey: error fetch public key entries: error make http request: Get \"https://127.0.0.1/domain/sys.auth/service/zts\": dial tcp 127.0.0.1:443: connect: connection refused"
				if len(gotErrs) != 1 {
					return errors.New("len(gotErrs) != 1")
				}
				if gotErrs[0].Error() != want1 && gotErrs[0].Error() != want2 {
					return errors.Errorf("gotErrs: %v, want: %v", gotErrs[0], want1)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErrs := run(tt.args.cfg)
			if err := tt.checkFunc(gotErrs); err != nil {
				t.Errorf("run() fails: %v", err)
			}
		})
	}
}

func Test_getVersion(t *testing.T) {
	tests := []struct {
		name       string
		want       string
		beforeFunc func()
	}{
		{
			name:       "default",
			want:       "development version",
			beforeFunc: func() {},
		},
		{
			name: "Version already set",
			want: "1.2.333",
			beforeFunc: func() {
				Version = "1.2.333"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}
			if got := getVersion(); got != tt.want {
				t.Errorf("getVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_main(t *testing.T) {
	type test struct {
		name       string
		beforeFunc func()
		afterFunc  func()
	}
	tests := []test{
		func() test {
			var oldArgs []string
			return test{
				name: "show version",
				beforeFunc: func() {
					oldArgs = os.Args
					os.Args = []string{"authorization-proxy", "-version"}
				},
				afterFunc: func() {
					os.Args = oldArgs
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer tt.afterFunc()
			tt.beforeFunc()
			main()
		})
	}
}

func Test_mainExitCode(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		signal       os.Signal
		wantExitCode int
	}{
		{
			name: "normal exit",
			args: []string{
				"-version",
			},
			signal:       nil,
			wantExitCode: 0,
		},
		{
			name: "undefined flag",
			args: []string{
				"-undefined_flag",
			},
			signal:       nil,
			wantExitCode: 1,
		},
		{
			name: "run with log error",
			args: []string{
				"-f",
				"./test/data/invalid_log_config.yaml",
			},
			signal:       nil,
			wantExitCode: 1,
		},
		// TODO: need Athenz public key endpoint mock
		/*
			{
				name: "run till termination SIGINT",
				args: []string{
					"-f",
					"./test/data/valid_config.yaml",
				},
				signal:       syscall.SIGINT,
				wantExitCode: 1,
			},
			{
				name: "run till termination SIGTERM",
				args: []string{
					"-f",
					"./test/data/valid_config.yaml",
				},
				signal:       syscall.SIGTERM,
				wantExitCode: 1,
			},
		*/
	}

	rc := os.Getenv("RUN_CASE")
	if rc != "" {
		c, err := strconv.Atoi(rc)
		if err != nil {
			panic(err)
		}
		tt := tests[c]

		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()
		os.Args = append([]string{"authorization-proxy"}, tt.args...)

		if tt.signal != nil {
			// send signal
			go func() {
				proc, err := os.FindProcess(os.Getpid())
				if err != nil {
					panic(err)
				}

				time.Sleep(200 * time.Millisecond)
				proc.Signal(tt.signal)
			}()
		}

		// run main
		main()
		return
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outbuf, errbuf strings.Builder

			cmd := exec.Command(os.Args[0], "-test.run=Test_mainExitCode")
			cmd.Stdout = &outbuf
			cmd.Stderr = &errbuf
			cmd.Env = append(os.Environ(), "RUN_CASE="+strconv.Itoa(i))
			err := cmd.Run()
			exitCode := cmd.ProcessState.ExitCode()
			if exitCode != tt.wantExitCode {
				t.Errorf("main() err = %v, stdout = %s, stderr = %s, exit code = %v, wantExitCode %v", err, outbuf.String(), errbuf.String(), exitCode, tt.wantExitCode)
			}
		})
	}
}

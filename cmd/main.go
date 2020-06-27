package main

import (
	"errors"
	"fmt"
	"github.com/micromata/dave/app"
	"github.com/micromata/dave/cmd/subcmd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/webdav"
	syslog "log"
	"net/http"
	"os"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Run: func(*cobra.Command, []string) {
		run()
	},
}

func init(){
	RootCmd.AddCommand(subcmd.PasswdCmd)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(){

	config := app.ParseConfig()

	// Set formatter for logrus
	formatter := &log.TextFormatter{}
	log.SetFormatter(formatter)

	// Set formatter for default log outputs
	logger := log.New()
	logger.Formatter = formatter
	writer := logger.Writer()
	defer func (){ _ = writer.Close() }()
	syslog.SetOutput(writer)

	wdHandler := &webdav.Handler{
		Prefix: config.Prefix,
		FileSystem: &app.Dir{
			Config: config,
		},
		LockSystem: webdav.NewMemLS(),
		Logger: func(request *http.Request, err error) {
			if config.Log.Error && err != nil {
				log.Error(err)
			}
		},
	}

	_app := &app.App{
		Config:  config,
		Handler: wdHandler,
	}

	http.Handle("/", wrapRecovery(app.NewBasicAuthWebdavHandler(_app)))
	connAddr := fmt.Sprintf("%s:%s", config.Address, config.Port)

	if config.TLS != nil {
		log.WithFields(log.Fields{
			"address":  config.Address,
			"port":     config.Port,
			"security": "TLS",
		}).Info("Server is starting and listening")
		log.Fatal(http.ListenAndServeTLS(connAddr, config.TLS.CertFile, config.TLS.KeyFile, nil))

	} else {
		log.WithFields(log.Fields{
			"address":  config.Address,
			"port":     config.Port,
			"security": "none",
		}).Info("Server is starting and listening")
		log.Fatal(http.ListenAndServe(connAddr, nil))
	}
}

func wrapRecovery(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				switch t := err.(type) {
				case string:
					log.WithError(errors.New(t)).Error("An error occurred handling a webdav request")
				case error:
					log.WithError(t).Error("An error occurred handling a webdav request")
				}
			}
		}()

		handler.ServeHTTP(w, r)
	})
}

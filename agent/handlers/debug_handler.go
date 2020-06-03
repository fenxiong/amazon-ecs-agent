package handlers

import (
	"net/http"
	_ "net/http/pprof"

	"github.com/cihub/seelog"
)

const (
	debugAddress = "127.0.0.1:51660"
)

func init() {
	go func() {
		seelog.Info("debug server started on ", debugAddress)
		err := http.ListenAndServe(debugAddress, nil)
		if err != nil {
			seelog.Error("debug server crashed: ", err)
		}
	}()
}

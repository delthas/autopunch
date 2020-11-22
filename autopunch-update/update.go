package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func version() (string, error) {
	f, err := os.Open(versionFile)
	if err != nil {
		return "", fmt.Errorf("opening version file: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return "", fmt.Errorf("reading version file: %v", err)
	}
	return sc.Text(), nil
}

var file, versionFile string

func main() {
	logOut := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	logErr := log.New(os.Stdout, "err: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lmsgprefix)

	flag.StringVar(&file, "file", "", "path to file to serve")
	flag.StringVar(&versionFile, "version-file", "", "path to file containing version of file")
	listen := flag.String("listen", "", "listen address (eg :80)")
	flag.Parse()
	if *listen == "" {
		logErr.Fatalf("-listen must not be empty")
	}

	http.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if r.Method != "GET" {
			logErr.Printf("unexpected method: %v from %v", r.Method, r.RemoteAddr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		remoteVersion := r.URL.Query().Get("version")
		localVersion, err := version()
		if err != nil {
			logErr.Printf("failed reading local version: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logOut.Printf("%v: %q => %q", r.RemoteAddr, remoteVersion, localVersion)
		if localVersion == remoteVersion {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f, err := os.Open(file)
		if err != nil {
			logErr.Printf("failed opening local file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	server := &http.Server{
		Addr:         *listen,
		ErrorLog:     logErr,
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 5 * time.Minute,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logErr.Printf("failed serving on %q: %v", *listen, err)
	}
}

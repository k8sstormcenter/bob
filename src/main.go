package main

import (
	// "log" // This import seems unused.
	"os"
	"github.com/k8sstormcenter/bobctl/src/cmd" // 
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}


// export PATH="/usr/local/opt/go/libexec/bin:$PATH"
// go version go1.24.4 darwin/amd64
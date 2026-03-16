Error: unknown flag: --ks-namespace
Usage:
  bobctl attack [flags]

Flags:
      --attack-suite string   path to AttackSuite YAML (required)
      --format string         output format: table, json, markdown (default "table")
  -h, --help                  help for attack
      --service string        K8s service name for proxy routing (e.g. webapp-mywebapp)
      --service-port int      K8s service port for proxy routing (default 8080)
      --timeout string        HTTP request timeout (default "10s")
      --type string           attack type: cmdinject, lfi, ssrf, sqli, or all (default "all")
      --url string            direct base URL of the target service (e.g. http://localhost:8081)

Global Flags:
      --kubeconfig string   path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
  -n, --namespace string    Kubernetes namespace (default "default")
  -v, --verbose             verbose output


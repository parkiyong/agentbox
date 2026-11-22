package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/parkiyong/agentbox/pkg/proxy"
	"github.com/parkiyong/agentbox/pkg/sandbox"
	"github.com/parkiyong/agentbox/pkg/sandbox/docker"
	"github.com/parkiyong/agentbox/pkg/sandbox/firecracker"
	"github.com/parkiyong/agentbox/pkg/sandbox/k8s"
	"github.com/parkiyong/agentbox/pkg/sandbox/local"
)

func main() {
	var (
		driverName   = flag.String("driver", envOrDefault("AGENTBOX_DRIVER", "docker"), "SandboxDriver: local | docker | firecracker | k8s-gvisor | k8s-kata")
		proxyListen  = flag.String("proxy-listen", envOrDefault("AGENTBOX_PROXY_LISTEN", "127.0.0.1:8081"), "Host-Side Security Proxy listen addr (tcp or unix:///...)")
		egressListen = flag.String("egress-listen", envOrDefault("AGENTBOX_EGRESS_LISTEN", "127.0.0.1:8082"), "Host-Side Egress Firewall listen addr")
		controlPlane = flag.String("control-plane", envOrDefault("AGENTBOX_CONTROL_PLANE_URL", "https://api.agentbox.dev"), "Control Plane URL (outbound tunnel; zero inbound ports required)")
		mtlsCert     = flag.String("mtls-cert", os.Getenv("AGENTBOX_MTLS_CERT"), "Client TLS certificate path for outbound mTLS")
		mtlsKey      = flag.String("mtls-key", os.Getenv("AGENTBOX_MTLS_KEY"), "Client TLS key path for outbound mTLS")
		mtlsCA       = flag.String("mtls-ca", os.Getenv("AGENTBOX_MTLS_CA"), "CA certificate path for outbound mTLS")
		dataDir      = flag.String("data-dir", envOrDefault("AGENTBOX_RUNNER_DATA_DIR", "/tmp/agentbox-runner"), "Local runner workspace/snapshot directory")
		mockLLM      = flag.Bool("mock-llm", false, "Use deterministic MockSWEProvider instead of upstream LLM")
	)
	flag.Parse()

	drv, err := buildDriver(*driverName, *dataDir)
	if err != nil {
		log.Fatalf("initialize sandbox driver %q: %v", *driverName, err)
	}

	llmProvider, providerLabel := proxy.NewAutoProviderFromEnv(*mockLLM)
	log.Printf("agentbox-runner: LLM provider=%s", providerLabel)

	var gitBroker proxy.GitTokenBroker
	if tok := os.Getenv("AGENTBOX_GIT_TOKEN"); tok != "" {
		gitBroker = &proxy.StaticGitTokenBroker{Token: tok}
	}

	hostProxy := proxy.NewHostProxyServer(proxy.Config{
		LLMProvider: llmProvider,
		GitBroker:   gitBroker,
		Secrets:     proxy.NewMapSecretStore(nil),
	})
	proxy.RegisterBYOCProvidersFromEnv(hostProxy.LLM)
	if err := hostProxy.Start(*proxyListen, *egressListen); err != nil {
		log.Fatalf("start host security proxy: %v", err)
	}
	defer hostProxy.Close(context.Background())

	cpClient, err := buildMTLSClient(*mtlsCert, *mtlsKey, *mtlsCA)
	if err != nil {
		log.Fatalf("configure outbound mTLS client: %v", err)
	}

	log.Printf("agentbox-runner started: driver=%s proxy=%s egress=%s control_plane=%s",
		drv.Name(), hostProxy.APIBaseURL(), hostProxy.EgressProxyURL(), *controlPlane)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Outbound heartbeat loop to Control Plane (zero inbound ports required in BYOC VPC).
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("agentbox-runner shutting down cleanly")
			return
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, *controlPlane+"/healthz", nil)
			if resp, err := cpClient.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
}

func buildDriver(name, dataDir string) (sandbox.SandboxDriver, error) {
	switch name {
	case "local":
		return local.NewDriver(dataDir)
	case "docker":
		return docker.NewDriver(dataDir)
	case "firecracker":
		return firecracker.NewDriver(
			dataDir,
			envOrDefault("AGENTBOX_FC_KERNEL", "/var/lib/agentbox/vmlinux"),
			envOrDefault("AGENTBOX_FC_ROOTFS", "/var/lib/agentbox/rootfs.ext4"),
		)
	case "k8s-gvisor":
		return k8s.NewDriver(
			envOrDefault("KUBERNETES_API_SERVER", "https://kubernetes.default.svc"),
			envOrDefault("AGENTBOX_K8S_NAMESPACE", "agentbox"),
			"gvisor",
			os.Getenv("KUBERNETES_TOKEN"),
		), nil
	case "k8s-kata":
		return k8s.NewDriver(
			envOrDefault("KUBERNETES_API_SERVER", "https://kubernetes.default.svc"),
			envOrDefault("AGENTBOX_K8S_NAMESPACE", "agentbox"),
			"kata",
			os.Getenv("KUBERNETES_TOKEN"),
		), nil
	default:
		return nil, fmt.Errorf("unknown driver %q", name)
	}
}

func buildMTLSClient(certFile, keyFile, caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load mTLS keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read mTLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

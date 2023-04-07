package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/consul/agent/config"
	"github.com/hashicorp/consul/agent/hcp"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

func TestBootstrapConfigLoader(t *testing.T) {
	baseLoader := func(source config.Source) (config.LoadResult, error) {
		return config.Load(config.LoadOpts{
			DefaultConfig: source,
			HCL: []string{
				`server = true`,
				`data_dir = "/tmp/consul-data"`,
			},
		})
	}

	bootstrapLoader := func(source config.Source) (config.LoadResult, error) {
		return bootstrapConfigLoader(baseLoader, &RawBootstrapConfig{
			ConfigJSON:      `{"bootstrap_expect": 8}`,
			ManagementToken: "test-token",
		})(source)
	}

	result, err := bootstrapLoader(nil)
	require.NoError(t, err)

	// bootstrap_expect and management token are injected from bootstrap config received from HCP.
	require.Equal(t, 8, result.RuntimeConfig.BootstrapExpect)
	require.Equal(t, "test-token", result.RuntimeConfig.Cloud.ManagementToken)

	// Response header is always injected from a constant.
	require.Equal(t, "x-consul-default-acl-policy", result.RuntimeConfig.HTTPResponseHeaders[accessControlHeaderName])
}

func Test_finalizeRuntimeConfig(t *testing.T) {
	type testCase struct {
		rc       *config.RuntimeConfig
		cfg      *RawBootstrapConfig
		verifyFn func(t *testing.T, rc *config.RuntimeConfig)
	}
	run := func(t *testing.T, tc testCase) {
		finalizeRuntimeConfig(tc.rc, tc.cfg)
		tc.verifyFn(t, tc.rc)
	}

	tt := map[string]testCase{
		"set header if not present": {
			rc: &config.RuntimeConfig{},
			cfg: &RawBootstrapConfig{
				ManagementToken: "test-token",
			},
			verifyFn: func(t *testing.T, rc *config.RuntimeConfig) {
				require.Equal(t, "test-token", rc.Cloud.ManagementToken)
				require.Equal(t, "x-consul-default-acl-policy", rc.HTTPResponseHeaders[accessControlHeaderName])
			},
		},
		"append to header if present": {
			rc: &config.RuntimeConfig{
				HTTPResponseHeaders: map[string]string{
					accessControlHeaderName: "Content-Encoding",
				},
			},
			cfg: &RawBootstrapConfig{
				ManagementToken: "test-token",
			},
			verifyFn: func(t *testing.T, rc *config.RuntimeConfig) {
				require.Equal(t, "test-token", rc.Cloud.ManagementToken)
				require.Equal(t, "Content-Encoding,x-consul-default-acl-policy", rc.HTTPResponseHeaders[accessControlHeaderName])
			},
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func TestLoadConfig_Persistence(t *testing.T) {
	type testCase struct {
		// resourceID is the HCP resource ID. If set, a server is considered to be cloud-enabled.
		resourceID string

		// devMode indicates whether the loader should not have a data directory.
		devMode bool

		// verifyFn issues case-specific assertions.
		verifyFn func(t *testing.T, rc *config.RuntimeConfig)
	}

	run := func(t *testing.T, tc testCase) {
		dir, err := os.MkdirTemp(os.TempDir(), "bootstrap-test-")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(dir) })

		s := hcp.NewMockHCPServer()
		s.AddEndpoint(TestEndpoint())

		// Use an HTTPS server since that's what the HCP SDK expects for auth.
		srv := httptest.NewTLSServer(s)
		defer srv.Close()

		caCert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
		require.NoError(t, err)

		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		clientTLS := &tls.Config{RootCAs: pool}

		baseOpts := config.LoadOpts{
			HCL: []string{
				`server = true`,
				fmt.Sprintf(`http_config = { response_headers = { %s = "Content-Encoding" } }`, accessControlHeaderName),
				fmt.Sprintf(`cloud { client_id="test" client_secret="test" hostname=%q auth_url=%q resource_id=%q }`,
					srv.Listener.Addr().String(), srv.URL, tc.resourceID),
			},
		}
		if tc.devMode {
			baseOpts.DevMode = boolPtr(true)
		} else {
			baseOpts.HCL = append(baseOpts.HCL, fmt.Sprintf(`data_dir = %q`, dir))
		}

		baseLoader := func(source config.Source) (config.LoadResult, error) {
			baseOpts.DefaultConfig = source
			return config.Load(baseOpts)
		}

		ui := cli.NewMockUi()

		// Load initial config to check whether bootstrapping from HCP is enabled.
		initial, err := baseLoader(nil)
		require.NoError(t, err)

		// Override the client TLS config so that the test server can be trusted.
		initial.RuntimeConfig.Cloud.WithTLSConfig(clientTLS)
		client, err := hcp.NewClient(initial.RuntimeConfig.Cloud)
		require.NoError(t, err)

		loader, err := LoadConfig(context.Background(), client, initial.RuntimeConfig.DataDir, baseLoader, ui)
		require.NoError(t, err)

		// Load the agent config with the potentially wrapped loader.
		fromRemote, err := loader(nil)
		require.NoError(t, err)

		// HCP-enabled cases should fetch from HCP on the first run of LoadConfig.
		require.Contains(t, ui.OutputWriter.String(), "Fetching configuration from HCP")

		// Run case-specific verification.
		tc.verifyFn(t, fromRemote.RuntimeConfig)

		if tc.devMode {
			// Re-running the bootstrap func below isn't relevant to dev mode
			// since they don't have a data directory to load data from.
			return
		}

		// Run LoadConfig again to exercise the logic of loading config from disk.
		loader, err = LoadConfig(context.Background(), client, initial.RuntimeConfig.DataDir, baseLoader, ui)
		require.NoError(t, err)

		// HCP-enabled cases should fetch from disk on the second run.
		require.Contains(t, ui.OutputWriter.String(), "Loaded HCP configuration from local disk")
	}

	tt := map[string]testCase{
		"dev mode": {
			devMode: true,

			resourceID: "organization/0b9de9a3-8403-4ca6-aba8-fca752f42100/" +
				"project/0b9de9a3-8403-4ca6-aba8-fca752f42100/" +
				"consul.cluster/new-cluster-id",

			verifyFn: func(t *testing.T, rc *config.RuntimeConfig) {
				require.Empty(t, rc.DataDir)

				// Dev mode should have persisted certs since they can't be inlined.
				require.NotEmpty(t, rc.TLS.HTTPS.CertFile)
				require.NotEmpty(t, rc.TLS.HTTPS.KeyFile)
				require.NotEmpty(t, rc.TLS.HTTPS.CAFile)

				// Find the temporary directory they got stored in.
				dir := filepath.Dir(rc.TLS.HTTPS.CertFile)

				// Ensure we only stored the TLS materials.
				entries, err := os.ReadDir(dir)
				require.NoError(t, err)
				require.Len(t, entries, 3)

				haveFiles := make([]string, 3)
				for i, entry := range entries {
					haveFiles[i] = entry.Name()
				}

				wantFiles := []string{caFileName, certFileName, keyFileName}
				require.ElementsMatch(t, wantFiles, haveFiles)
			},
		},
		"new cluster": {
			resourceID: "organization/0b9de9a3-8403-4ca6-aba8-fca752f42100/" +
				"project/0b9de9a3-8403-4ca6-aba8-fca752f42100/" +
				"consul.cluster/new-cluster-id",

			// New clusters should have received and persisted the whole suite of config.
			verifyFn: func(t *testing.T, rc *config.RuntimeConfig) {
				entries, err := os.ReadDir(filepath.Join(rc.DataDir, subDir))
				require.NoError(t, err)
				require.Len(t, entries, 4)

				files := []string{
					filepath.Join(rc.DataDir, subDir, configFileName),
					filepath.Join(rc.DataDir, subDir, caFileName),
					filepath.Join(rc.DataDir, subDir, certFileName),
					filepath.Join(rc.DataDir, subDir, keyFileName),
				}
				for _, name := range files {
					_, err := os.Stat(name)
					require.NoError(t, err)
				}

				require.Equal(t, filepath.Join(rc.DataDir, subDir, certFileName), rc.TLS.HTTPS.CertFile)
				require.Equal(t, filepath.Join(rc.DataDir, subDir, keyFileName), rc.TLS.HTTPS.KeyFile)
				require.Equal(t, filepath.Join(rc.DataDir, subDir, caFileName), rc.TLS.HTTPS.CAFile)
			},
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

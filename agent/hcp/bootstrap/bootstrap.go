// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package bootstrap handles bootstrapping an agent's config from HCP. It must be a
// separate package from other HCP components because it has a dependency on
// agent/config while other components need to be imported and run within the
// server process in agent/consul and that would create a dependency cycle.
package bootstrap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/consul/agent/config"
	"github.com/hashicorp/consul/agent/hcp"
	"github.com/hashicorp/consul/lib"
	"github.com/hashicorp/consul/lib/retry"
)

const (
	subDir = "hcp-config"

	caFileName              = "server-tls-cas.pem"
	certFileName            = "server-tls-cert.pem"
	configFileName          = "server-config.json"
	existingClusterFileName = "existing-cluster"
	keyFileName             = "server-tls-key.pem"
	tokenFileName           = "hcp-management-token"
)

type ConfigLoader func(source config.Source) (config.LoadResult, error)

// UI is a shim to allow the agent command to pass in it's mitchelh/cli.UI so we
// can output useful messages to the user during bootstrapping. For example if
// we have to retry several times to bootstrap we don't want the agent to just
// stall with no output which is the case if we just returned all intermediate
// warnings or errors.
type UI interface {
	Output(string)
	Warn(string)
	Info(string)
	Error(string)
}

// RawBootstrapConfig contains the Consul config as a raw JSON string and the management token
// which either was retrieved from persisted files or from the bootstrap endpoint
type RawBootstrapConfig struct {
	ConfigJSON      string
	ManagementToken string
}

// LoadConfig will attempt to load previously-fetched config from disk and fall back to
// fetch from HCP servers if the local data is incomplete.
// It must be passed a (CLI) UI implementation so it can deliver progress
// updates to the user, for example if it is waiting to retry for a long period.
func LoadConfig(ctx context.Context, client hcp.Client, dataDir string, loader ConfigLoader, ui UI) (ConfigLoader, error) {
	ui.Output("Loading configuration from HCP")

	// See if we have existing config on disk
	//
	// OPTIMIZE: We could probably be more intelligent about config loading.
	// The currently implemented approach is:
	// 1. Attempt to load data from disk
	// 2. If that fails or the data is incomplete, block indefinitely fetching remote config.
	//
	// What if instead we had the following flow:
	// 1. Attempt to fetch config from HCP.
	// 2. If that fails, fall back to data on disk from last fetch.
	// 3. If that fails, go into blocking loop to fetch remote config.
	//
	// This should allow us to more gracefully transition cases like when
	// an existing cluster is linked, but then wants to receive TLS materials
	// at a later time. Currently, if we observe the existing-cluster marker we
	// don't attempt to fetch any additional configuration from HCP.

	cfg, ok := loadPersistedBootstrapConfig(dataDir, ui)
	if !ok {
		ui.Info("Fetching configuration from HCP servers")

		var err error
		cfg, err = fetchBootstrapConfig(ctx, client, dataDir, ui)
		if err != nil {
			return nil, fmt.Errorf("failed to bootstrap from HCP: %w", err)
		}
		ui.Info("Configuration fetched from HCP and saved on local disk")

	} else {
		ui.Info("Loaded HCP configuration from local disk")

	}

	// Create a new loader func to return
	newLoader := bootstrapConfigLoader(loader, cfg)
	return newLoader, nil
}

// bootstrapConfigLoader is a ConfigLoader for passing bootstrap JSON config received from HCP
// to the config.builder. ConfigLoaders are functions used to build an agent's RuntimeConfig
// from various sources like files and flags. This config is contained in the config.LoadResult.
//
// The flow to include bootstrap config from HCP as a loader's data source is as follows:
//
//  1. A base ConfigLoader function (baseLoader) is created on agent start, and it sets the input
//     source argument as the DefaultConfig.
//
//  2. When a server agent can be configured by HCP that baseLoader is wrapped in this bootstrapConfigLoader.
//
//  3. The bootstrapConfigLoader calls that base loader with the bootstrap JSON config as the
//     default source. This data will be merged with other valid sources in the config.builder.
//
//  4. The result of the call to baseLoader() below contains the resulting RuntimeConfig, and we do some
//     additional modifications to attach data that doesn't get populated during the build in the config pkg.
//
// Note that since the ConfigJSON is stored as the baseLoader's DefaultConfig, its data is the first
// to be merged by the config.builder and could be overwritten by user-provided values in config files or
// CLI flags. However, values set to RuntimeConfig after the baseLoader call are final.
func bootstrapConfigLoader(baseLoader ConfigLoader, cfg *RawBootstrapConfig) ConfigLoader {
	return func(source config.Source) (config.LoadResult, error) {
		// Don't allow any further attempts to provide a DefaultSource. This should
		// only ever be needed later in client agent AutoConfig code but that should
		// be mutually exclusive from this bootstrapping mechanism since this is
		// only for servers. If we ever try to change that, this clear failure
		// should alert future developers that the assumptions are changing rather
		// than quietly not applying the config they expect!
		if source != nil {
			return config.LoadResult{},
				fmt.Errorf("non-nil config source provided to a loader after HCP bootstrap already provided a DefaultSource")
		}

		// Otherwise, just call to the loader we were passed with our own additional
		// JSON as the source.
		//
		// OPTIMIZE: We could check/log whether any fields set by the remote config were overwritten by a user-provided flag.
		res, err := baseLoader(config.FileSource{
			Name:   "HCP Bootstrap",
			Format: "json",
			Data:   cfg.ConfigJSON,
		})
		if err != nil {
			return res, fmt.Errorf("failed to load HCP Bootstrap config: %w", err)
		}

		finalizeRuntimeConfig(res.RuntimeConfig, cfg)
		return res, nil
	}
}

const (
	accessControlHeaderName  = "Access-Control-Expose-Headers"
	accessControlHeaderValue = "x-consul-default-acl-policy"
)

// finalizeRuntimeConfig will set additional HCP-specific values that are not
// handled by the config.builder.
func finalizeRuntimeConfig(rc *config.RuntimeConfig, cfg *RawBootstrapConfig) {
	rc.Cloud.ManagementToken = cfg.ManagementToken

	// HTTP response headers are modified for the HCP UI to work.
	if rc.HTTPResponseHeaders == nil {
		rc.HTTPResponseHeaders = make(map[string]string)
	}
	prevValue, ok := rc.HTTPResponseHeaders[accessControlHeaderName]
	if !ok {
		rc.HTTPResponseHeaders[accessControlHeaderName] = accessControlHeaderValue
	} else {
		rc.HTTPResponseHeaders[accessControlHeaderName] = prevValue + "," + accessControlHeaderValue
	}
}

// fetchBootstrapConfig will fetch boostrap configuration from remote servers and persist it to disk.
// It will retry until successful or a terminal error condition is found (e.g. permission denied).
func fetchBootstrapConfig(ctx context.Context, client hcp.Client, dataDir string, ui UI) (*RawBootstrapConfig, error) {
	w := retry.Waiter{
		MinWait: 1 * time.Second,
		MaxWait: 5 * time.Minute,
		Jitter:  retry.NewJitter(50),
	}

	var bsCfg *hcp.BootstrapConfig

	for {
		// Note we don't want to shadow `ctx` here since we need that for the Wait
		// below.
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		resp, err := client.FetchBootstrap(reqCtx)
		if err != nil {
			ui.Error(fmt.Sprintf("failed to fetch bootstrap config from HCP, will retry in %s: %s",
				w.NextWait().Round(time.Second), err))
			if err := w.Wait(ctx); err != nil {
				return nil, err
			}
			// Finished waiting, restart loop
			continue
		}
		bsCfg = resp
		break
	}

	shouldPersist := true
	if dataDir == "" {
		// Agent in dev mode, we still need somewhere to persist the certs
		// temporarily though to be able to start up at all since we don't support
		// inline certs right now. Use temp dir
		tmp, err := os.MkdirTemp(os.TempDir(), "consul-dev-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir for certificates: %w", err)
		}
		dataDir = tmp
		shouldPersist = false
	}

	// Persist the TLS cert files from the response since we need to refer to them
	// as disk files either way.
	if err := persistTLSCerts(dataDir, bsCfg); err != nil {
		return nil, fmt.Errorf("failed to persist TLS certificates to dir %q: %w", dataDir, err)
	}
	// Update the config JSON to include those TLS cert files
	cfgJSON, err := injectTLSCerts(dataDir, bsCfg.ConsulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to inject TLS Certs into bootstrap config: %w", err)
	}

	// Persist the final config we need to add for restarts. Assuming this wasn't
	// a tmp dir to start with.
	if shouldPersist {
		if err := persistBootstrapConfig(dataDir, cfgJSON); err != nil {
			return nil, fmt.Errorf("failed to persist bootstrap config to dir %q: %w", dataDir, err)
		}
	}

	return &RawBootstrapConfig{
		ConfigJSON:      cfgJSON,
		ManagementToken: bsCfg.ManagementToken,
	}, nil
}

func persistTLSCerts(dataDir string, bsCfg *hcp.BootstrapConfig) error {
	dir := filepath.Join(dataDir, subDir)

	if bsCfg.TLSCert == "" || bsCfg.TLSCertKey == "" {
		return fmt.Errorf("unexpected bootstrap response from HCP: missing TLS information")
	}

	// Create a subdir if it's not already there
	if err := lib.EnsurePath(dir, true); err != nil {
		return err
	}

	// Write out CA cert(s). We write them all to one file because Go's x509
	// machinery will read as many certs as it finds from each PEM file provided
	// and add them separaetly to the CertPool for validation
	f, err := os.OpenFile(filepath.Join(dir, caFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	bf := bufio.NewWriter(f)
	for _, caPEM := range bsCfg.TLSCAs {
		bf.WriteString(caPEM + "\n")
	}
	if err := bf.Flush(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, certFileName), []byte(bsCfg.TLSCert), 0600); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte(bsCfg.TLSCertKey), 0600); err != nil {
		return err
	}

	return nil
}

func injectTLSCerts(dataDir string, bootstrapJSON string) (string, error) {
	// Parse just to a map for now as we only have to inject to a specific place
	// and parsing whole Config struct is complicated...
	var cfg map[string]interface{}

	if err := json.Unmarshal([]byte(bootstrapJSON), &cfg); err != nil {
		return "", err
	}

	// Inject TLS cert files
	cfg["ca_file"] = filepath.Join(dataDir, subDir, caFileName)
	cfg["cert_file"] = filepath.Join(dataDir, subDir, certFileName)
	cfg["key_file"] = filepath.Join(dataDir, subDir, keyFileName)

	jsonBs, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}

	return string(jsonBs), nil
}

func persistBootstrapConfig(dataDir, cfgJSON string) error {
	// Persist the important bits we got from bootstrapping. The TLS certs are
	// already persisted, just need to persist the config we are going to add.
	name := filepath.Join(dataDir, subDir, configFileName)
	return os.WriteFile(name, []byte(cfgJSON), 0600)
}

func loadPersistedBootstrapConfig(dataDir string, ui UI) (*RawBootstrapConfig, bool) {
	// Check if the files all exist
	files := []string{
		filepath.Join(dataDir, subDir, configFileName),
		filepath.Join(dataDir, subDir, caFileName),
		filepath.Join(dataDir, subDir, certFileName),
		filepath.Join(dataDir, subDir, keyFileName),
	}
	hasSome := false
	for _, name := range files {
		if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
			// At least one required file doesn't exist, failed loading. This is not
			// an error though
			if hasSome {
				ui.Warn("ignoring incomplete local bootstrap config files")
			}
			return nil, false
		}
		hasSome = true
	}

	name := filepath.Join(dataDir, subDir, configFileName)
	jsonBs, err := os.ReadFile(name)
	if err != nil {
		ui.Warn(fmt.Sprintf("failed to read local bootstrap config file, ignoring local files: %s", err))
		return nil, false
	}

	// Check this looks non-empty at least
	jsonStr := strings.TrimSpace(string(jsonBs))
	// 50 is arbitrary but config containing the right secrets would always be
	// bigger than this in JSON format so it is a reasonable test that this wasn't
	// empty or just an empty JSON object or something.
	if len(jsonStr) < 50 {
		ui.Warn("ignoring incomplete local bootstrap config files")
		return nil, false
	}

	// TODO we could parse the certificates and check they are still valid here
	// and force a reload if not. We could also attempt to parse config and check
	// it's all valid just in case the local config was really old and has
	// deprecated fields or something?
	return &RawBootstrapConfig{
		ConfigJSON: jsonStr,
	}, true
}

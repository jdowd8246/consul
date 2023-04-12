// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hcp

import (
	"github.com/hashicorp/consul/agent/hcp/config"
	"github.com/hashicorp/consul/agent/hcp/scada"
	"github.com/hashicorp/go-hclog"
)

// Deps contains the interfaces that the rest of Consul core depends on for HCP integration.
type Deps struct {
	Client   Client
	Provider scada.Provider
}

func NewDeps(cfg config.CloudConfig, logger hclog.Logger) (d Deps, err error) {
	d.Client, err = NewClient(cfg)
	if err != nil {
		return
	}

	// TODO: init HCP sink here and inject it into the telmetry lib package.
	// For the purposes of hacking, I will be doing it directly in the lib/telemetry package.

	d.Provider, err = scada.New(cfg, logger.Named("hcp.scada"))
	return
}

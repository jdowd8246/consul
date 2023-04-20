package controller

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"

	"github.com/hashicorp/consul/internal/resource"
	"github.com/hashicorp/consul/proto-public/pbresource"
)

// Manager is responsible for scheduling the execution of controllers.
type Manager struct {
	client pbresource.ResourceServiceClient
	logger hclog.Logger

	raftLeader atomic.Bool

	mu          sync.Mutex
	running     bool
	controllers []Controller
	leaseChans  []chan struct{}
}

// NewManager creates a Manager. logger will be used by the Manager, and as the
// base logger for controllers when one is not specified using WithLogger.
func NewManager(client pbresource.ResourceServiceClient, logger hclog.Logger) *Manager {
	return &Manager{
		client: client,
		logger: logger,
	}
}

// Register the given controller to be executed by the Manager. Cannot be called
// once the Manager is running.
func (m *Manager) Register(ctrl Controller) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		panic("cannot register additional controllers after calling Run")
	}

	if ctrl.reconciler == nil {
		panic(fmt.Sprintf("cannot register controller without a reconciler %s", ctrl))
	}

	m.controllers = append(m.controllers, ctrl)
}

// Run the Manager and start executing controllers until the given context is
// canceled. Cannot be called more than once.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		panic("cannot call Run more than once")
	}
	m.running = true

	for _, desc := range m.controllers {
		logger := desc.logger
		if logger == nil {
			logger = m.logger.With("managed_type", resource.ToGVK(desc.managedType))
		}

		runner := &controllerRunner{
			ctrl:   desc,
			client: m.client,
			logger: logger,
		}
		go newSupervisor(runner.run, m.newLeaseLocked(desc)).run(ctx)
	}
}

// SetRaftLeader notifies the Manager of Raft leadership changes. Controllers
// are currently only executed on the Raft leader, so calling this method will
// cause the Manager to spin them up/down acordingly.
func (m *Manager) SetRaftLeader(leader bool) {
	m.raftLeader.Store(leader)

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ch := range m.leaseChans {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (m *Manager) newLeaseLocked(ctrl Controller) Lease {
	if ctrl.placement == PlacementEachServer {
		return eternalLease{}
	}

	ch := make(chan struct{}, 1)
	m.leaseChans = append(m.leaseChans, ch)
	return &raftLease{m: m, ch: ch}
}

type raftLease struct {
	m  *Manager
	ch <-chan struct{}
}

func (l *raftLease) Held() bool             { return l.m.raftLeader.Load() }
func (l *raftLease) Watch() <-chan struct{} { return l.ch }

type eternalLease struct{}

func (eternalLease) Held() bool             { return true }
func (eternalLease) Watch() <-chan struct{} { return nil }

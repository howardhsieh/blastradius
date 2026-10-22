package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/provider"
)

// DefaultProbeTimeout bounds the whole probe phase.
const DefaultProbeTimeout = 60 * time.Second

// ProbeTarget is one host --probe would contact and how many credentials
// of which service it would send there.
type ProbeTarget struct {
	Host    string
	Service string
	Count   int
}

// ProbePlan is what --probe is about to do, computed from the offline
// result before any request is made so the user can be told first.
type ProbePlan struct {
	// Targets, sorted by host, is the consent list.
	Targets []ProbeTarget
	// Skipped explains credentials that will not be probed and why, one
	// line each (GitHub Enterprise hosts and clusters not opted in, AWS
	// secrets without a key ID ...). Kinds that are never probed (SSH
	// keys, SSO sessions) are not listed.
	Skipped []string
	jobs    []probeJob
}

type probeJob struct {
	index  int
	prober provider.Prober
	hosts  []string
}

// Credentials is how many credentials the plan will send somewhere.
func (p *ProbePlan) Credentials() int { return len(p.jobs) }

// Hosts is the de-duplicated, sorted host list.
func (p *ProbePlan) Hosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range p.Targets {
		if !seen[t.Host] {
			seen[t.Host] = true
			out = append(out, t.Host)
		}
	}
	sort.Strings(out)
	return out
}

// probeConfig turns the options into the provider-level configuration,
// keeping any test transport already installed on env.
func probeConfig(env *provider.Env, opt Options) *provider.ProbeConfig {
	cfg := env.Probe
	if cfg == nil {
		cfg = &provider.ProbeConfig{}
	}
	cfg.Hosts = opt.ProbeHosts
	cfg.Clusters = opt.ProbeClusters
	if cfg.Timeout == 0 {
		cfg.Timeout = provider.DefaultProbeTimeout
	}
	return cfg
}

// PlanProbe decides which credentials of res will be probed and where.
// It makes no network request.
func PlanProbe(env *provider.Env, res *Result, opt Options) *ProbePlan {
	env.Probe = probeConfig(env, opt)
	plan := &ProbePlan{}
	counts := map[ProbeTarget]int{}
	for i, c := range res.Credentials {
		p, hosts, skip := provider.ProbeTargets(env, c)
		if len(hosts) == 0 {
			if skip != "" {
				plan.Skipped = append(plan.Skipped, fmt.Sprintf("%s (%s): %s", c.ID, c.Location, skip))
			}
			continue
		}
		plan.jobs = append(plan.jobs, probeJob{index: i, prober: p, hosts: hosts})
		for _, h := range hosts {
			counts[ProbeTarget{Host: h, Service: c.Service}]++
		}
	}
	for t, n := range counts {
		t.Count = n
		plan.Targets = append(plan.Targets, t)
	}
	sort.Slice(plan.Targets, func(i, j int) bool {
		if plan.Targets[i].Host != plan.Targets[j].Host {
			return plan.Targets[i].Host < plan.Targets[j].Host
		}
		return plan.Targets[i].Service < plan.Targets[j].Service
	})
	return plan
}

// RunProbe executes the plan: each credential is sent to its service, the
// answer is attached as Reach, severities are refined and the result is
// rated again. Probe failures become Problems; nothing aborts the scan.
func RunProbe(ctx context.Context, env *provider.Env, res *Result, plan *ProbePlan, opt Options) {
	if plan == nil || len(plan.jobs) == 0 {
		res.Offline = false
		return
	}
	total := opt.ProbeTimeout
	if total <= 0 {
		total = DefaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	cfg := probeConfig(env, opt)
	env.Probe = cfg

	type outcome struct {
		reach *cred.Reach
		err   error
	}
	outcomes := make([]outcome, len(plan.jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for j, job := range plan.jobs {
		wg.Add(1)
		go func(j int, job probeJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				outcomes[j].err = fmt.Errorf("skipped: --probe-timeout %s reached", total)
				return
			}
			pctx, pcancel := context.WithTimeout(ctx, cfg.Timeout)
			defer pcancel()
			r, err := job.prober.Probe(pctx, env, res.Credentials[job.index])
			outcomes[j] = outcome{reach: r, err: err}
		}(j, job)
	}
	wg.Wait()

	hosts := map[string]bool{}
	for j, job := range plan.jobs {
		c := &res.Credentials[job.index]
		o := outcomes[j]
		if o.err != nil {
			res.Problems = append(res.Problems, provider.Problem{
				Location: c.ID + " (" + c.Location + ")",
				Err:      "probe " + strings.Join(job.hosts, ",") + ": " + o.err.Error(),
			})
			continue
		}
		if o.reach == nil {
			continue
		}
		c.Reach = o.reach
		for _, h := range strings.Split(o.reach.Host, ", ") {
			if h != "" {
				hosts[h] = true
			}
		}
		refine(c)
	}
	for h := range hosts {
		res.ProbedHosts = append(res.ProbedHosts, h)
	}
	sort.Strings(res.ProbedHosts)
	res.Offline = false
	res.rate()
}

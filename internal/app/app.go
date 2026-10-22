package app

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dnstapir/tapir-analyse-lib/common"
	"github.com/dnstapir/tapir-analyse-lib/libtapir"
)

const c_N_HANDLERS = 3
const c_NATS_DELIM = common.NATS_DELIM
const c_DEFAULT_DOMAIN_MIN_TOTAL = 50
const c_DEFAULT_GLOBAL_MIN_TOTAL = 100
const c_DEFAULT_ANALYZE_EVERY = 10
const c_DEFAULT_MIN_TVD = 0.4
const c_DEFAULT_ALPHA = 1e-13
const c_MIN_EXPECTED = 5.0 // usual rule of thumb for the chi-squared approximation

// TODO: add threshold config entry
type Conf struct {
	Debug               bool     `toml:"debug"`
	Interval            int      `toml:"interval"`
	IgnoreSuffixes      []string `toml:"ignore_suffixes"`
	IncludeInvalidETLDs bool     `toml:"include_invalid_etlds"`
	DomainMinTotal      uint64   `toml:"domain_min_total"`
	GlobalMinTotal      uint64   `toml:"global_min_total"`
	AnalyzeEvery        uint64   `toml:"analyze_every"` // re-test each time the domain total is a multiple of this
	MinTvd              float64  `toml:"min_tvd"`
	Alpha               float64  `toml:"alpha"` // significance level, e.g. 0.001
	Tag                 string   `toml:"tag"`
	AnalystID           string
	Log                 common.Logger
	NatsHandle          nats
}

type appHandle struct {
	id                  string
	includeInvalidETLDs bool
	ignoreSuffixes      []string
	domainMinTotal      uint64
	globalMinTotal      uint64
	analyzeEvery        uint64
	minTvd              float64
	alpha               float64
	tag                 string
	observation         string
	log                 common.Logger
	natsHandle          nats
	exitCh              chan<- common.Exit
	pm
}

type pm struct {
}

type job struct {
	isTick bool
	msg    common.NatsMsg
}

type nats interface {
	ActivateSubscription(context.Context) (<-chan common.NatsMsg, error)
	SetObservation(context.Context, string, string) error
	IncrCounter(context.Context, string) (uint64, error)
	GetPrivate(context.Context, string) (string, error)
	SetPrivate(context.Context, string, string) error
	ListPrivateKeys(context.Context, string) ([]string, error)
	SetTagStr(context.Context, string, string, string) error
	Shutdown() error
}

// Chi-squared test functions
func sumCounts(m map[string]uint64) uint64 {
	var s uint64
	for _, v := range m {
		s += v
	}
	return s
}

// normalize turns counts into proportions summing to 1.
func normalize(counts map[string]uint64) map[string]float64 {
	out := make(map[string]float64, len(counts))
	total := sumCounts(counts)
	if total == 0 {
		return out
	}
	for k, v := range counts {
		out[k] = float64(v) / float64(total)
	}
	return out
}

// totalVariation is half the L1 distance between two normalized
// distributions: 0 = identical, 1 = completely disjoint.
func totalVariation(p, q map[string]float64) float64 {
	var sum float64
	for k, pv := range p {
		sum += math.Abs(pv - q[k])
	}
	for k, qv := range q {
		if _, ok := p[k]; !ok {
			sum += qv
		}
	}
	return sum / 2
}

// chiSquaredPValue returns P(X >= x) for a chi-squared variable with df
// degrees of freedom. Exact for df 1 and 2, Wilson-Hilferty approximation when above df 2.
func chiSquaredPValue(x float64, df int) float64 {
	if x <= 0 || df < 1 {
		return 1
	}
	switch df {
	case 1:
		return math.Erfc(math.Sqrt(x / 2))
	case 2:
		return math.Exp(-x / 2)
	}

	k := float64(df)
	z := (math.Cbrt(x/k) - (1 - 2/(9*k))) / math.Sqrt(2/(9*k))
	return 0.5 * math.Erfc(z/math.Sqrt2)
}

// chiSquaredTest checks whether the domain's qtype counts are consistent with
// the qtype distribution of all other traffic (global minus domain).
func chiSquaredTest(domain, global map[string]uint64) (stat float64, df int, p float64, ok bool) {
	// The domain is part of global, so the reference is everyone else
	ref := make(map[string]uint64, len(global))
	for q, g := range global {
		if d := domain[q]; g > d {
			ref[q] = g - d
		}
	}

	cats := make(map[string]struct{})
	for q := range domain {
		cats[q] = struct{}{}
	}
	for q := range ref {
		cats[q] = struct{}{}
	}

	nObs := float64(sumCounts(domain))
	nRef := float64(sumCounts(ref))
	if nObs == 0 || nRef == 0 {
		return 0, 0, 1, false
	}
	k := float64(len(cats))

	var obs, exp []float64
	var obsOther, expOther float64
	for q := range cats {
		// add-one smoothing so no expected count is zero
		e := nObs * (float64(ref[q]) + 1) / (nRef + k)
		o := float64(domain[q])
		if e < c_MIN_EXPECTED {
			obsOther += o // pool rare qtypes into one bucket
			expOther += e
		} else {
			obs = append(obs, o)
			exp = append(exp, e)
		}
	}
	if expOther > 0 {
		obs = append(obs, obsOther)
		exp = append(exp, expOther)
	}

	if len(exp) < 2 {
		fmt.Errorf("ChiSq: len(exp) > 2: %s", len(exp))
		return 0, 0, 1, false
	}

	for i := range exp {
		d := obs[i] - exp[i]
		stat += d * d / exp[i]
	}
	df = len(exp) - 1

	return stat, df, chiSquaredPValue(stat, df), true
}

func qtypeDistKey(date, domain, counter string) string {
	parts := []string{date}
	if domain == "global" {
		parts = append(parts, "global", counter)
	} else {
		parts = append(parts, libtapir.FlipDomainName(domain), counter)
	}
	return common.NormalizeNatsSubject(strings.Join(parts, common.NATS_DELIM))
}

func Create(conf Conf) (*appHandle, error) {
	a := new(appHandle)

	if conf.Log == nil {
		return nil, common.ErrBadHandle
	}
	a.log = conf.Log

	if conf.NatsHandle == nil {
		return nil, common.ErrBadHandle
	}
	a.natsHandle = conf.NatsHandle

	if conf.AnalystID == "" {
		a.log.Error("Bad analyst ID during creation")
		return nil, common.ErrBadParam
	}
	a.id = conf.AnalystID

	a.includeInvalidETLDs = conf.IncludeInvalidETLDs
	a.log.Debug("Observations will be sent out for invalid eTLDs: %t", a.includeInvalidETLDs)

	for _, s := range conf.IgnoreSuffixes {
		suf := libtapir.NormalizeDomainNameSuffix(s)
		if suf == "" {
			continue
		}
		a.ignoreSuffixes = append(a.ignoreSuffixes, suf)
	}

	a.domainMinTotal = cmp.Or(conf.DomainMinTotal, c_DEFAULT_DOMAIN_MIN_TOTAL)
	a.globalMinTotal = cmp.Or(conf.GlobalMinTotal, c_DEFAULT_GLOBAL_MIN_TOTAL)
	a.analyzeEvery = cmp.Or(conf.AnalyzeEvery, c_DEFAULT_ANALYZE_EVERY)
	a.alpha = cmp.Or(conf.Alpha, c_DEFAULT_ALPHA)
	a.minTvd = cmp.Or(conf.MinTvd, c_DEFAULT_MIN_TVD)

	if a.analyzeEvery == 0 {
		a.analyzeEvery = 1 // also avoids a modulo by zero
	}

	if a.alpha <= 0 || a.alpha >= 1 {
		a.alpha = c_DEFAULT_ALPHA
	}

	if conf.Tag == "" {
		a.log.Error("Bad tag during creation")
		return nil, common.ErrBadParam
	}
	a.tag = conf.Tag

	a.log.Debug("Main app debug logging enabled")
	return a, nil
}

func (a *appHandle) Run(ctx context.Context, exitCh chan<- common.Exit) {
	var natsChan <-chan common.NatsMsg
	var err error
	a.exitCh = exitCh
	jobChan := make(chan job, 10)

	natsChan, err = a.natsHandle.ActivateSubscription(ctx)
	if err != nil {
		a.log.Error("Couldn't activate NATS subscription: '%s'", err)
		a.exitCh <- common.Exit{ID: a.id, Err: err}
		return
	}

	var wg sync.WaitGroup
	for range c_N_HANDLERS {
		wg.Go(func() {
			for j := range jobChan {
				a.handleJob(ctx, j)
			}
			a.log.Info("Worker done!")
		})
	}

MAIN_APP_LOOP:
	for {
		select {
		case natsMsg, ok := <-natsChan:
			if !ok {
				a.log.Warning("NATS channel closed")
				natsChan = nil
			} else {
				a.log.Debug("Incoming NATS message")
				j := job{
					msg: natsMsg,
				}
				select {
				case jobChan <- j:
				case <-ctx.Done():
					break MAIN_APP_LOOP
				}
			}
		case <-ctx.Done():
			a.log.Info("Stopping main worker thread")
			break MAIN_APP_LOOP
		}
	}

	close(jobChan)

	wg.Wait()

	err = a.natsHandle.Shutdown()
	if err != nil {
		a.log.Error("Encountered '%s' during NATS shutdown", err)
	}

	a.exitCh <- common.Exit{ID: a.id, Err: err}
	a.log.Info("Main app shutdown done")
	return
}

func (a *appHandle) handleJob(ctx context.Context, j job) {
	a.handleMsg(ctx, j.msg)
}

func (a *appHandle) readQtypeCounts(ctx context.Context, date, scope string) (map[string]uint64, error) {
	keys, err := a.natsHandle.ListPrivateKeys(ctx, qtypeDistKey(date, scope, "*"))
	if err != nil {
		return nil, err
	}

	counts := make(map[string]uint64, len(keys))
	for _, key := range keys {
		qtype := key[strings.LastIndex(key, c_NATS_DELIM)+1:]
		if qtype == "total" {
			continue
		}
		val, err := a.natsHandle.GetPrivate(ctx, key)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("corrupt counter '%s': %w", key, err)
		}
		counts[qtype] = n
	}
	return counts, nil
}

func (a *appHandle) handleMsg(ctx context.Context, msg common.NatsMsg) {
	a.log.Debug("Handling %d byte message on subject %s", len(msg.Data), msg.Subject)
	if len(msg.Data) <= 0 {
		a.log.Warning("Msg had no data, probably garbage. Won't handle...")
		return
	}

	msgDomain, err := libtapir.ExtractDomain(msg.Data)
	if err != nil {
		a.log.Error("Error reading domain from message: %s", err)
		return
	}

	msgQtype, err := libtapir.ExtractQtype(msg.Data)
	if err != nil {
		a.log.Error("Error reading QTYPE from message: %s", err)
		return
	}

	for _, s := range a.ignoreSuffixes {
		if msgDomain == s || strings.HasSuffix(msgDomain, s) {
			a.log.Debug("%s matches suffix %s, ignoring...", msgDomain, s)
			return
		}
	}

	if !a.includeInvalidETLDs && !libtapir.HasValidETLD(msgDomain) {
		a.log.Debug("%s has invalid eTLD, ignoring", msgDomain)
		return
	}

	domain, err := libtapir.GetETLDPlusOne(msgDomain)
	if err != nil {
		a.log.Error("Error reading eTLD+1 from msgDomain: %s", err)
		return
	}
	qtype := strconv.FormatUint(uint64(msgQtype), 10) // from 1 to "1"
	date := time.Now().UTC().Format("2006-01-02")

	// "<date>.<flipped domain>.<qtype> = counter"
	// "<date>.<flipped domain>.total = counter"
	// "<date>.global.<qtype> = counter"
	// "<date>.global.total = counter"
	var domainTotal, globalTotal uint64
	for _, scope := range []string{domain, "global"} {
		for _, counter := range []string{qtype, "total"} {
			key := qtypeDistKey(date, scope, counter)
			n, err := a.natsHandle.IncrCounter(ctx, key)
			if err != nil {
				a.log.Error("Couldn't increment counter '%s': %s", key, err)
				continue
			}
			if counter == "total" {
				if scope == "global" {
					globalTotal = n
				} else {
					domainTotal = n
				}
			}
		}
	}

	// A failed total increment above leaves the total at 0, resulting in a skip here
	if domainTotal < a.domainMinTotal || globalTotal < a.globalMinTotal {
		return
	}

	if domainTotal%a.analyzeEvery != 0 {
		return
	}

	// Analyze distribution
	domainCounts, err := a.readQtypeCounts(ctx, date, domain)
	if err != nil {
		a.log.Error("Couldn't read distribution for %s: %s", domain, err)
		return
	}
	globalCounts, err := a.readQtypeCounts(ctx, date, "global")
	if err != nil {
		a.log.Error("Couldn't read global distribution: %s", err)
		return
	}

	_, _, p, ok := chiSquaredTest(domainCounts, globalCounts)
	if !ok {
		a.log.Debug("Distribution for %s not testable", domain)
		return
	}
	tvd := totalVariation(normalize(domainCounts), normalize(globalCounts))

	if p < a.alpha && tvd > a.minTvd {
		//a.log.Info("%s deviates from the global qtype distribution (p=%.3g, tvd=%.3f)", domain, p, tvd)

		// Assign tag
		freeText := fmt.Sprintf("{p=%.3g, alpha=%.3g, tvd=%.3f, min_tvd=%.3f}", p, a.alpha, tvd, a.minTvd)
		err := a.natsHandle.SetTagStr(ctx, domain, a.tag, freeText)
		if err != nil {
			a.log.Error("Error setting '%s' tag for '%s': %s", a.tag, domain, err)
			return
		}
	}

	return
}

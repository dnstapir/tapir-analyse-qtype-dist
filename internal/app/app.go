package app

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dnstapir/tapir-analyse-lib/common"
	"github.com/dnstapir/tapir-analyse-lib/libtapir"
)

const c_N_HANDLERS = 3
const c_NATS_DELIM = common.NATS_DELIM

// TODO: add private bucket suffix to conf/apphandle?
type Conf struct {
	Debug      			bool 		`toml:"debug"`
	Interval   			int  		`toml:"interval"`
	IgnoreSuffixes      []string	`toml:"ignore_suffixes"`
	IncludeInvalidETLDs	bool        `toml:"include_invalid_etlds"`
	AnalystID  			string
	Log        			common.Logger
	NatsHandle 			nats
}

type appHandle struct {
	id          		string
	includeInvalidETLDs bool
	ignoreSuffixes      []string
	observation 		string
	log         		common.Logger
	natsHandle  		nats
	exitCh      		chan<- common.Exit
	pm
}

type pm struct {
}

type job struct {
	isTick   bool
	msg      common.NatsMsg
}

type nats interface {
	ActivateSubscription(context.Context) (<-chan common.NatsMsg, error)
	SetObservation(context.Context, string, string) error
	IncrCounter(context.Context, string) error
	Shutdown() error
}

func qtypeDistKey(date, domain, counter string) string {
	parts := []string{date}
	if domain == "global" { // TODO: might collide with the ".global" TLD
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

	// TODO: how to handle queries for "se", "global", etc.
	domain, err := libtapir.GetETLDPlusOne(msgDomain)
	if err != nil {
		a.log.Error("Error reading eTLD+1 from msgDomain: %s", err)
		return
	}
	qtype := strconv.FormatUint(uint64(msgQtype), 10)
	date := time.Now().UTC().Format("2006-01-02")

	// "<date>.<flipped domain>.<qtype> = counter"
	// "<date>.<flipped domain>.total = counter"
	// "<date>.global.<qtype> = counter"
	// "<date>.global.total = counter"
	// "2006-01-02.com.example.1 = 10
	// "2006-01-02.global.1 = 100
	for _, scope := range []string{domain, "global"} {
		for _, counter := range []string{qtype, "total"} {
			key := qtypeDistKey(date, scope, counter)
			if err := a.natsHandle.IncrCounter(ctx, key); err != nil {
				a.log.Error("Couldn't increment counter: %s", err)
			}
		}
	}

	// TODO: analyze distribution
	// TODO: assign observation/tag

	return
}

package crossbouncer

import "sort"

// TimelineSchemaVersion is the wire contract the replay UI + flight-recorder
// command load. Matches iam-jit's TIMELINE_SCHEMA_VERSION exactly so the Go
// and Python emitters are interchangeable.
const TimelineSchemaVersion = "flight-recorder/1"

// Step is one stitched event in the cross-bouncer timeline. Nullable fields
// use pointers so they serialize as JSON null (not omitted) — matching the
// Python emitter the replay UI already consumes.
type Step struct {
	Index        int      `json:"index"`
	ArrivalIndex int      `json:"arrival_index"`
	Bouncer      string   `json:"bouncer"`
	Protocol     string   `json:"protocol"`
	TimeMS       *int64   `json:"time_ms"`
	Time         *string  `json:"time"`
	Action       string   `json:"action"`
	Decision     string   `json:"decision"`
	Reason       *string  `json:"reason"`
	Resources    []string `json:"resources"`
	Principal    *string  `json:"principal"`
	IAMContext   *string  `json:"iam_context"`
	Status       *string  `json:"status"`
	HasTimestamp bool     `json:"has_timestamp"`
}

// UnreachableBouncer names a probed-but-unanswered bouncer + why.
type UnreachableBouncer struct {
	Bouncer string `json:"bouncer"`
	Reason  string `json:"reason"`
}

// Coverage reports honest cross-bouncer coverage for the session.
type Coverage struct {
	BouncersProbed            []string             `json:"bouncers_probed"`
	BouncersReachable         []string             `json:"bouncers_reachable"`
	BouncersUnreachable       []UnreachableBouncer `json:"bouncers_unreachable"`
	BouncersContributing      []string             `json:"bouncers_contributing"`
	BouncersReachableNoEvents []string             `json:"bouncers_reachable_no_events"`
	Partial                   bool                 `json:"partial"`
	Gaps                      []string             `json:"gaps"`
}

// Meta is the timeline summary block.
type Meta struct {
	Since                *string        `json:"since"`
	Until                *string        `json:"until"`
	EventsAnalyzed       int            `json:"events_analyzed"`
	ProtocolsRepresented []string       `json:"protocols_represented"`
	StepsPerProtocol     map[string]int `json:"steps_per_protocol"`
	FirstStepTime        *string        `json:"first_step_time"`
	LastStepTime         *string        `json:"last_step_time"`
}

// Timeline is the full flight-recorder/1 document.
type Timeline struct {
	Schema    string   `json:"schema"`
	SessionID string   `json:"session_id"`
	StepCount int      `json:"step_count"`
	Steps     []Step   `json:"steps"`
	Coverage  Coverage `json:"coverage"`
	Meta      Meta     `json:"meta"`
}

// AssembleTimeline stitches session events (already fan-out merged) into the
// flight-recorder/1 timeline. notes maps every probed bouncer to "" (reachable)
// or an error reason. since/until are echoed into meta ("" -> null).
func AssembleTimeline(sessionID string, events []Event, notes map[string]string, since, until string) Timeline {
	steps := make([]Step, 0, len(events))
	for arrival, ev := range events {
		steps = append(steps, stepFromEvent(ev, arrival))
	}
	sortSteps(steps)
	for i := range steps {
		steps[i].Index = i
	}

	contributing := map[string]bool{}
	stepsPerProto := map[string]int{}
	var firstTime, lastTime *string
	for _, s := range steps {
		contributing[s.Bouncer] = true
		stepsPerProto[s.Protocol]++
		if s.HasTimestamp && s.Time != nil {
			if firstTime == nil {
				firstTime = s.Time
			}
			lastTime = s.Time
		}
	}

	cov := buildCoverage(notes, contributing)
	meta := Meta{
		Since:                strPtrOrNil(since),
		Until:                strPtrOrNil(until),
		EventsAnalyzed:       len(events),
		ProtocolsRepresented: sortedKeys(stepsPerProto),
		StepsPerProtocol:     stepsPerProto,
		FirstStepTime:        firstTime,
		LastStepTime:         lastTime,
	}
	return Timeline{
		Schema:    TimelineSchemaVersion,
		SessionID: sessionID,
		StepCount: len(steps),
		Steps:     steps,
		Coverage:  cov,
		Meta:      meta,
	}
}

// stepFromEvent projects one event onto the closed Step allow-list. The raw
// event body is never attached.
func stepFromEvent(ev Event, arrival int) Step {
	s := Step{
		ArrivalIndex: arrival,
		Bouncer:      ev.Bouncer(),
		Protocol:     ProtocolFor(ev.Bouncer()),
		Action:       ev.Action(),
		Decision:     ev.Verdict(),
		Resources:    ev.Resources(),
	}
	if s.Resources == nil {
		s.Resources = []string{}
	}
	if ms, ok := ev.TimeMS(); ok {
		s.TimeMS = &ms
		iso := ev.TimeISO()
		s.Time = &iso
		s.HasTimestamp = true
	}
	if r := ev.Reason(); r != "" {
		s.Reason = &r
	}
	if p := ev.Principal(); p != "" {
		s.Principal = &p
	}
	if ic := ev.IAMContext(); ic != "" {
		s.IAMContext = &ic
	}
	if st := ev.Status(); st != "" {
		s.Status = &st
	}
	return s
}

// sortSteps orders by (has_timestamp desc, time_ms asc, bouncer, arrival).
func sortSteps(steps []Step) {
	sort.SliceStable(steps, func(i, j int) bool {
		a, b := steps[i], steps[j]
		if a.HasTimestamp != b.HasTimestamp {
			return a.HasTimestamp // timestamped first
		}
		if a.HasTimestamp {
			ai, bi := int64(0), int64(0)
			if a.TimeMS != nil {
				ai = *a.TimeMS
			}
			if b.TimeMS != nil {
				bi = *b.TimeMS
			}
			if ai != bi {
				return ai < bi
			}
		}
		if a.Bouncer != b.Bouncer {
			return a.Bouncer < b.Bouncer
		}
		return a.ArrivalIndex < b.ArrivalIndex
	})
}

// buildCoverage derives the honest coverage block from the probe notes.
func buildCoverage(notes map[string]string, contributing map[string]bool) Coverage {
	var probed, reachable, contrib, reachableNoEvents []string
	var unreachable []UnreachableBouncer
	var gaps []string
	for name := range notes {
		probed = append(probed, name)
	}
	sort.Strings(probed)
	for _, name := range probed {
		note := notes[name]
		if note == "" {
			reachable = append(reachable, name)
			if !contributing[name] {
				reachableNoEvents = append(reachableNoEvents, name)
			}
		} else {
			unreachable = append(unreachable, UnreachableBouncer{Bouncer: name, Reason: note})
			gaps = append(gaps, name+" did not answer: "+note)
		}
		if contributing[name] {
			contrib = append(contrib, name)
		}
	}
	return Coverage{
		BouncersProbed:            probed,
		BouncersReachable:         reachable,
		BouncersUnreachable:       unreachable,
		BouncersContributing:      contrib,
		BouncersReachableNoEvents: reachableNoEvents,
		Partial:                   len(unreachable) > 0,
		Gaps:                      gaps,
	}
}

// helpers -------------------------------------------------------------------

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Package store defines SoroBeacon's persistence interfaces and models.
// The Postgres implementation lives in postgres.go; tests and alternative
// backends can implement the narrow per-domain interfaces below.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Monitor watches one or more Soroban contracts.
type Monitor struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	ContractIDs []string  `json:"contract_ids"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	// LastMatchedAt is the ledger close time of the most recent event that
	// created an alert for this monitor. Nil means it has never matched —
	// do not backfill a fake timestamp.
	LastMatchedAt *time.Time `json:"last_matched_at"`
	// ChannelIDs are the notification channels this monitor alerts to.
	ChannelIDs []int64 `json:"channel_ids"`
}

// Rule is one condition evaluated against every event of its monitor's
// contracts. Type selects a rules.RuleEvaluator; Params are its arguments.
type Rule struct {
	ID        int64           `json:"id"`
	MonitorID int64           `json:"monitor_id"`
	Type      string          `json:"type"`
	Params    json.RawMessage `json:"params"`
	Enabled   bool            `json:"enabled"`
}

// Channel is a configured notification destination. Config holds
// channel-specific settings including secrets (webhook URLs, bot tokens,
// SMTP credentials) — never log it and never return it from the API.
// When a ConfigCipher is configured, Config is encrypted at rest and the
// store returns it decrypted (see crypto.go).
type Channel struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"-"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`

	// The fields below are delivery health, derived from outcomes rather than
	// configured (see RecordChannelHealth and migration 0007). They answer
	// "is this channel still working?", which delivery_attempts could only
	// answer one alert at a time.
	//
	// ConsecutiveFailures counts failed deliveries since the last success.
	ConsecutiveFailures int64 `json:"consecutive_failures"`
	// ConsecutivePermanentFailures counts permanent failures (401/403/404)
	// since the last success, and is what auto-disable triggers on. A
	// transient failure neither increments nor clears it, so a revoked
	// credential is not hidden by an unrelated 5xx in the middle.
	ConsecutivePermanentFailures int64 `json:"consecutive_permanent_failures"`
	// LastError is the most recent failure message. It never holds channel
	// config: the notifiers redact URLs and tokens before building it.
	LastError string `json:"last_error,omitempty"`
	// LastErrorAt is when LastError was recorded, nil if there has been no
	// failure since the last success.
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	// LastSuccessAt is the last successful delivery, nil until the first one.
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	// DisabledAt is set when health tracking turned the channel off, and only
	// then. It is what makes the dashboard say "auto-disabled" rather than
	// "disabled", and it is cleared by an explicit re-enable.
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
}

// AutoDisabled reports whether health tracking, rather than an operator,
// turned this channel off. Such a channel is kept out of dispatch by
// enabled=false and comes back only through an explicit re-enable.
func (c Channel) AutoDisabled() bool { return c.DisabledAt != nil }

// HealthStatus is the coarse state the dashboard shows: "auto_disabled" when
// health tracking turned the channel off, "disabled" when an operator did,
// "failing" while deliveries are failing but the channel is still on, and
// "ok" otherwise.
func (c Channel) HealthStatus() string {
	switch {
	case c.DisabledAt != nil:
		return "auto_disabled"
	case !c.Enabled:
		return "disabled"
	case c.ConsecutiveFailures > 0:
		return "failing"
	default:
		return "ok"
	}
}

// ChannelHealthUpdate is one delivery outcome folded into a channel's health
// counters. The store applies it as a single UPDATE that both increments and
// (when the threshold is reached) disables, so several poller instances
// dispatching at once can neither lose a count nor disable twice.
type ChannelHealthUpdate struct {
	// Success clears the counters and the last error. It never re-enables a
	// channel: putting one back in rotation is an operator's decision, taken
	// through the channel update path.
	Success bool
	// Permanent marks a failure the channel will not recover from on its own
	// (401/403/404). Only permanent failures move a channel toward
	// auto-disable; a 5xx or a timeout is the provider having a bad day.
	Permanent bool
	// Error is the failure message recorded as last_error. It must already be
	// free of credentials — notifiers build their errors that way.
	Error string
	// DisableAfter is the number of consecutive permanent failures at which
	// the channel is auto-disabled. Zero (the default) never auto-disables.
	DisableAfter int
	// At is when the outcome happened. Zero means now.
	At time.Time
}

// Alert records one rule match on one event. EventID is the source event's
// TOID-based id; (RuleID, EventID) is unique so the same match can never
// fire twice.
type Alert struct {
	ID        int64           `json:"id"`
	MonitorID int64           `json:"monitor_id"`
	RuleID    int64           `json:"rule_id"`
	EventID   string          `json:"event_id"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
	// LedgerClosedAt is the matching event's ledger close time. CreateAlert
	// uses it to stamp monitors.last_matched_at; it is not stored on the
	// alert row. Zero skips the stamp so callers that only persist an
	// alert (tests, retries) do not invent a wall-clock match time.
	LedgerClosedAt time.Time `json:"-"`
	// Cooldown, when > 0, makes CreateAlert suppress this alert if the rule
	// already fired within the window. It is rule config, not alert data, so
	// it is never persisted on the alert row.
	Cooldown time.Duration `json:"-"`
	// SuppressedSinceLast is set by CreateAlert when a row is created: the
	// number of matches this rule dropped under its cooldown since the
	// previous alert. CreateAlert also folds it into Payload so the stored
	// alert and the dispatched notification both report it.
	SuppressedSinceLast int64 `json:"-"`
}

// AlertOutcome reports what CreateAlert did with a match.
type AlertOutcome string

const (
	// AlertCreated means a new alert row was written.
	AlertCreated AlertOutcome = "created"
	// AlertDuplicate means an alert for the same (rule_id, event_id) already
	// existed — the dedup guard — so nothing was written.
	AlertDuplicate AlertOutcome = "duplicate"
	// AlertSuppressed means the rule was inside its cooldown window, so the
	// match was counted and no alert was written.
	AlertSuppressed AlertOutcome = "suppressed"
)

// Status values persisted on delivery_attempts.status. Anything else is
// rejected by the API; the store filters on these exact strings.
const (
	DeliveryStatusSuccess = "success"
	DeliveryStatusFailed  = "failed"
)

// ValidDeliveryStatus reports whether s is a value the store actually
// writes. The empty string is not valid here — callers that mean "no
// filter" should check for empty themselves.
func ValidDeliveryStatus(s string) bool {
	return s == DeliveryStatusSuccess || s == DeliveryStatusFailed
}

// DeliveryAttempt records one try at sending an alert through a channel.
type DeliveryAttempt struct {
	ID              int64     `json:"id"`
	AlertID         int64     `json:"alert_id"`
	ChannelID       int64     `json:"channel_id"`
	Status          string    `json:"status"` // DeliveryStatusSuccess or DeliveryStatusFailed
	ResponseSnippet string    `json:"response_snippet"`
	AttemptedAt     time.Time `json:"attempted_at"`
}

// IngestState is the poller's checkpoint: the last fully processed ledger
// and, mid-page, the last getEvents cursor.
type IngestState struct {
	LastLedger uint32    `json:"last_ledger"`
	LastCursor string    `json:"last_cursor"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AlertFilter narrows ListAlerts. Zero values mean "no constraint".
type AlertFilter struct {
	MonitorID int64
	RuleID    int64
	// ContractID matches payload->>'contract_id'. Empty means no contract filter.
	ContractID string
	From       time.Time
	To         time.Time
	Limit      int
	// AfterID is the keyset cursor (the last id of the previous page). The
	// comparison flips with Sort: created_at_desc uses (created_at, id) <
	// the cursor row; created_at_asc uses >. Comparing only on id would
	// repeat or skip rows once sort is not newest-id.
	AfterID int64
	// Type filters channels by their notifier type ("slack", "discord",
	// ...). Empty means no type filter. Only meaningful for channels.
	Type string
	// Sort is an allowlisted order key: "created_at_desc" (default) or
	// "created_at_asc". Unknown values are treated as the default in the
	// store; the API rejects them with 400. Never interpolate this into SQL.
	Sort string
}

// ListFilter pages monitors or channels. Zero values mean "no constraint"
// besides the store's default page size. AfterID uses the same newest-first
// keyset as AlertFilter (id < AfterID) so the API does not grow a second
// cursor dialect.
//
// Query, Sort and Enabled apply to ListMonitorsPage. Channels ignore them
// (EnabledOnly stays the channels listing's on/off switch so enabled=false
// there still means "all", matching the pre-tri-state API).
type ListFilter struct {
	EnabledOnly bool
	// Type filters channels by notifier type ("slack", "discord", ...).
	// Empty means no type filter; only meaningful for channels.
	Type string
	// Enabled is the monitors tri-state filter: nil = all (default), true =
	// enabled only, false = disabled only. When nil, EnabledOnly is used.
	Enabled *bool
	// Query is a case-insensitive name substring. Empty means no name filter.
	Query string
	// Sort is an allowlisted order key: "name" (default), "id", "created_at".
	// Unknown values are treated as "name"; never interpolate this into SQL.
	Sort    string
	Limit   int
	AfterID int64
}

// Stats is the aggregate snapshot served by GET /stats.
type Stats struct {
	Monitors     int64     `json:"monitors"`
	Rules        int64     `json:"rules"`
	Channels     int64     `json:"channels"`
	Alerts       int64     `json:"alerts"`
	AlertsLast24 int64     `json:"alerts_last_24h"`
	LastLedger   uint32    `json:"last_ledger"`
	LastPollAt   time.Time `json:"last_poll_at"`
}

// AlertSeriesDays is the overview chart window: today (UTC) and the 29
// preceding UTC days. A spike only shows up against that quiet baseline.
const AlertSeriesDays = 30

// AlertDayCount is one UTC calendar-day bucket of alert totals.
type AlertDayCount struct {
	// Day is YYYY-MM-DD in UTC.
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

// ClampAlertSeriesDays maps a caller-supplied window onto a bounded range.
// Non-positive values become AlertSeriesDays so a missing query param cannot
// collapse the series; 90 is a hard cap so a typo cannot scan unbounded history.
func ClampAlertSeriesDays(days int) int {
	if days <= 0 {
		return AlertSeriesDays
	}
	if days > 90 {
		return 90
	}
	return days
}

// Monitors persists monitors and their channel attachments.
type Monitors interface {
	CreateMonitor(ctx context.Context, m *Monitor) error
	GetMonitor(ctx context.Context, id int64) (*Monitor, error)
	ListMonitors(ctx context.Context, enabledOnly bool) ([]Monitor, error)
	// ListMonitorsPage is the keyset-paginated listing used by the API and
	// dashboard. ListMonitors stays unpaginated for the poller, which must
	// see every enabled monitor in one shot.
	ListMonitorsPage(ctx context.Context, f ListFilter) ([]Monitor, error)
	UpdateMonitor(ctx context.Context, m *Monitor) error
	DeleteMonitor(ctx context.Context, id int64) error
	SetMonitorChannels(ctx context.Context, monitorID int64, channelIDs []int64) error
	// SetMonitorsEnabled sets enabled on every existing id in one statement.
	// Unknown IDs are returned rather than treated as an error so a mixed
	// list still applies to the known monitors. Duplicate ids are collapsed.
	SetMonitorsEnabled(ctx context.Context, ids []int64, enabled bool) (updated int, unknown []int64, err error)
	// DuplicateMonitor copies a monitor with its rules and channel
	// attachments in one transaction. The copy is always created
	// disabled so it cannot start alerting before it has been reviewed.
	// Alerts are not copied.
	DuplicateMonitor(ctx context.Context, id int64) (*Monitor, error)
}

// CopyMonitorName returns a unique name for a duplicated monitor.
// The first copy is "name (copy)"; collisions become "name (copy 2)",
// then (copy 3), and so on. existing is the set of names already in use.
func CopyMonitorName(src string, existing []string) string {
	taken := make(map[string]struct{}, len(existing))
	for _, n := range existing {
		taken[n] = struct{}{}
	}
	candidate := src + " (copy)"
	if _, ok := taken[candidate]; !ok {
		return candidate
	}
	for i := 2; ; i++ {
		candidate = fmt.Sprintf("%s (copy %d)", src, i)
		if _, ok := taken[candidate]; !ok {
			return candidate
		}
	}
}

// Rules persists rules.
type Rules interface {
	CreateRule(ctx context.Context, r *Rule) error
	// CreateRules inserts the batch in one transaction and fills each
	// rule's ID in request order. An empty slice is a no-op.
	CreateRules(ctx context.Context, rules []*Rule) error
	GetRule(ctx context.Context, id int64) (*Rule, error)
	ListRules(ctx context.Context, monitorID int64, enabledOnly bool) ([]Rule, error)
	UpdateRule(ctx context.Context, r *Rule) error
	DeleteRule(ctx context.Context, id int64) error
}

// Channels persists notification channels.
type Channels interface {
	CreateChannel(ctx context.Context, c *Channel) error
	GetChannel(ctx context.Context, id int64) (*Channel, error)
	ListChannels(ctx context.Context, enabledOnly bool) ([]Channel, error)
	ListChannelsPage(ctx context.Context, f ListFilter) ([]Channel, error)
	UpdateChannel(ctx context.Context, c *Channel) error
	DeleteChannel(ctx context.Context, id int64) error
	// ListChannelsForMonitor returns the enabled channels a monitor alerts to.
	ListChannelsForMonitor(ctx context.Context, monitorID int64) ([]Channel, error)
	// RecordChannelHealth folds one delivery outcome into a channel's health
	// counters, auto-disabling it once DisableAfter consecutive permanent
	// failures have accumulated. Unknown channel ids are ignored rather than
	// an error: a channel deleted mid-dispatch is a race, not a bug.
	RecordChannelHealth(ctx context.Context, channelID int64, u ChannelHealthUpdate) error
}

// Alerts persists alerts and delivery attempts.
type Alerts interface {
	// CreateAlert inserts a new alert unless the rule is inside its cooldown
	// window (Alert.Cooldown), in which case the match is counted and
	// AlertSuppressed is returned. AlertDuplicate means the (rule_id,
	// event_id) dedup guard rejected it. Enforcing both here, under the same
	// transaction, keeps the decision race-safe across poller instances and
	// restarts. On a new row, a non-zero LedgerClosedAt is written to
	// monitors.last_matched_at when it is newer than the stored value, and
	// Alert.SuppressedSinceLast is filled in.
	CreateAlert(ctx context.Context, a *Alert) (AlertOutcome, error)
	GetAlert(ctx context.Context, id int64) (*Alert, error)
	ListAlerts(ctx context.Context, f AlertFilter) ([]Alert, error)
	RecordDeliveryAttempt(ctx context.Context, d *DeliveryAttempt) error
	// ListDeliveryAttempts returns attempts for one alert, oldest first.
	// status empty means no filter; otherwise it is applied in SQL.
	ListDeliveryAttempts(ctx context.Context, alertID int64, status string) ([]DeliveryAttempt, error)
	// DeleteExpiredAlerts removes up to limit alerts with created_at
	// before cutoff. delivery_attempts follow via ON DELETE CASCADE.
	DeleteExpiredAlerts(ctx context.Context, cutoff time.Time, limit int) (deleted int64, err error)
}

// Ingest persists the poller checkpoint.
type Ingest interface {
	GetIngestState(ctx context.Context) (IngestState, error)
	SetIngestState(ctx context.Context, s IngestState) error
}

// Store is everything the application needs from persistence.
type Store interface {
	Monitors
	Rules
	Channels
	Alerts
	Ingest
	GetStats(ctx context.Context) (Stats, error)
	// AlertCountsByDay returns UTC calendar-day alert totals for `days`
	// consecutive days ending today (UTC). Days with no alerts are present
	// with count 0 so a chart has no gaps. Bucketing is done in SQL.
	AlertCountsByDay(ctx context.Context, days int) ([]AlertDayCount, error)
	Ping(ctx context.Context) error
	Close()
}

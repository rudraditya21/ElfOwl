// ANCHOR: CIS control rule matching engine - Dec 26, 2025
// Matches enriched events against CIS Kubernetes v1.8 control rules
// IMPLEMENTATION IN PROGRESS - Week 2 task

package rules

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// Engine matches enriched events against CIS control rules
type Engine struct {
	Rules  []*Rule
	Logger *zap.Logger
}

// Rule defines a CIS control detection rule
type Rule struct {
	ControlID  string
	Title      string
	Severity   string
	EventTypes []string
	Conditions []Condition
}

// Condition is a single matching criterion
type Condition struct {
	Field    string
	Operator string
	Value    interface{}
}

// Violation represents a detected CIS violation
type Violation struct {
	ControlID      string
	Title          string
	Severity       string
	Timestamp      time.Time
	Pod            *enrichment.K8sContext
	Container      *enrichment.ContainerContext
	Description    string
	RemediationRef string
}

// NewEngine creates a new rule engine
// ANCHOR: Rule engine initialization without config dependency - Dec 26, 2025
// Removed config parameter to break circular import dependency
func NewEngine() (*Engine, error) {
	logger, _ := zap.NewProduction()

	engine := &Engine{
		Rules:  loadCISRules(),
		Logger: logger,
	}

	return engine, nil
}

// Match evaluates an enriched event against all rules
func (e *Engine) Match(event *enrichment.EnrichedEvent) []*Violation {
	var violations []*Violation

	for _, rule := range e.Rules {
		// Check if rule applies to this event type
		if !contains(rule.EventTypes, event.EventType) {
			continue
		}

		// Evaluate all conditions
		allMatch := true
		for _, cond := range rule.Conditions {
			if !e.evaluateCondition(event, cond) {
				allMatch = false
				break
			}
		}

		if allMatch {
			violations = append(violations, &Violation{
				ControlID:      rule.ControlID,
				Title:          rule.Title,
				Severity:       rule.Severity,
				Timestamp:      time.Now(),
				Pod:            event.Kubernetes,
				Container:      event.Container,
				Description:    fmt.Sprintf("%s: %s", rule.ControlID, rule.Title),
				RemediationRef: fmt.Sprintf("docs/remediation#%s", rule.ControlID),
			})
		}
	}

	return violations
}

// evaluateCondition evaluates a single condition against an event
func (e *Engine) evaluateCondition(event *enrichment.EnrichedEvent, cond Condition) bool {
	// ANCHOR: Condition evaluation for CIS rule matching - Dec 26, 2025
	// Implements field extraction and operator-based matching
	// Supports: equals, not_equals, contains, in, regex patterns

	// Extract field value from event
	fieldValue := e.extractField(event, cond.Field)
	if fieldValue == nil {
		return false
	}

	// Evaluate based on operator
	switch cond.Operator {
	case "equals":
		return fieldValue == cond.Value

	case "not_equals":
		return fieldValue != cond.Value

	case "contains":
		// String contains check
		if str, ok := fieldValue.(string); ok {
			if val, ok := cond.Value.(string); ok {
				return strings.Contains(str, val)
			}
		}
		return false

	case "in":
		// Check if fieldValue is in list
		if values, ok := cond.Value.([]interface{}); ok {
			for _, v := range values {
				if fieldValue == v {
					return true
				}
			}
		}
		return false

	case "greater_than":
		// Numeric comparison
		if fv, ok := fieldValue.(int); ok {
			if cv, ok := cond.Value.(int); ok {
				return fv > cv
			}
		}
		return false

	case "less_than":
		// Numeric comparison
		if fv, ok := fieldValue.(int); ok {
			if cv, ok := cond.Value.(int); ok {
				return fv < cv
			}
		}
		return false

	default:
		e.Logger.Warn("unknown operator", zap.String("operator", cond.Operator))
		return false
	}
}

// extractField extracts a field value from an enriched event
// Supports nested fields like "kubernetes.pod_name", "container.id"
// ANCHOR: Field extraction for rule matching - Dec 26, 2025
// Only includes fields that exist in enrichment.EnrichedEvent structure
// Extended fields (process, network) will be added in Week 2 implementation
func (e *Engine) extractField(event *enrichment.EnrichedEvent, fieldPath string) interface{} {
	if event == nil {
		return nil
	}

	switch fieldPath {
	// Event fields
	case "event_type":
		return event.EventType
	case "timestamp":
		return event.Timestamp
	case "severity":
		return event.Severity
	case "cis_control":
		return event.CISControl

	// Kubernetes context fields
	case "kubernetes.namespace":
		if event.Kubernetes != nil {
			return event.Kubernetes.Namespace
		}
	case "kubernetes.pod_name":
		if event.Kubernetes != nil {
			return event.Kubernetes.PodName
		}
	case "kubernetes.pod_uid":
		if event.Kubernetes != nil {
			return event.Kubernetes.PodUID
		}
	case "kubernetes.cluster_id":
		if event.Kubernetes != nil {
			return event.Kubernetes.ClusterID
		}
	case "kubernetes.node_name":
		if event.Kubernetes != nil {
			return event.Kubernetes.NodeName
		}
	case "kubernetes.service_account":
		if event.Kubernetes != nil {
			return event.Kubernetes.ServiceAccount
		}

	// Container context fields
	case "container.id":
		if event.Container != nil {
			return event.Container.ContainerID
		}
	case "container.name":
		if event.Container != nil {
			return event.Container.ContainerName
		}
	case "container.runtime":
		if event.Container != nil {
			return event.Container.Runtime
		}

	default:
		return nil
	}

	return nil
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// loadCISRules loads all CIS Kubernetes v1.8 control rules
func loadCISRules() []*Rule {
	// TODO: Week 2 implementation - Load from loadCISRules() in cis_mappings.go
	return []*Rule{}
}

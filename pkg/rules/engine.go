// ANCHOR: CIS control rule matching engine - Dec 26, 2025
// Matches enriched events against CIS Kubernetes v1.8 control rules

package rules

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// Engine matches enriched events against CIS control rules
type Engine struct {
	Rules  []*Rule
	Logger *zap.Logger
}

// EngineConfig defines configuration for rule engine initialization
// ANCHOR: Engine configuration with flexible rule sourcing - Phase 3.2 Week 3
// Supports loading rules from file, ConfigMap, or hardcoded defaults
// Implements fallback chain: file → ConfigMap → hardcoded CISControls
type EngineConfig struct {
	RuleFilePath       string                // Path to YAML rules file
	ConfigMapName      string                // Kubernetes ConfigMap name
	ConfigMapNamespace string                // Kubernetes ConfigMap namespace
	ConfigMapDataKey   string                // ConfigMap data key for rule YAML (default: "rules.yaml")
	K8sClientset       *kubernetes.Clientset // K8s client for ConfigMap API access
	Ctx                context.Context       // Context for K8s API calls
	StrictSource       bool                  // When true, do not fall back to alternate sources on load errors
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
	Field         string
	Operator      string
	Value         interface{}
	compiledRegex *regexp.Regexp
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

// NewEngine creates a new rule engine with fallback rule loading
// ANCHOR: Flexible rule engine initialization with fallback chain - Phase 3.3 Week 3
// Attempts to load rules from optional file path, falls back to hardcoded rules
// Fallback chain: file (if provided) → hardcoded CISControls
// Backward compatible with old signature: NewEngine(filePath...string)
// New signature: NewEngine() uses default config, or NewEngineWithConfig() for advanced options
func NewEngine(ruleFilePath ...string) (*Engine, error) {
	logger, _ := zap.NewProduction()

	var rules []*Rule

	// Attempt to load rules from file if provided
	if len(ruleFilePath) > 0 && ruleFilePath[0] != "" {
		loadedRules, err := LoadRulesFromFile(ruleFilePath[0])
		if err != nil {
			logger.Warn("failed to load rules from file, using hardcoded rules",
				zap.String("file", ruleFilePath[0]),
				zap.Error(err))
			// Fall back to hardcoded rules
			rules = loadCISRules()
		} else {
			logger.Info("successfully loaded rules from file",
				zap.String("file", ruleFilePath[0]),
				zap.Int("rule_count", len(loadedRules)))
			rules = loadedRules
		}
	} else {
		// No file provided, use hardcoded rules
		rules = loadCISRules()
	}

	engine := &Engine{
		Rules:  rules,
		Logger: logger,
	}
	prepareRuleCaches(engine.Rules, logger)

	return engine, nil
}

// NewEngineWithConfig creates a new rule engine with comprehensive configuration
// ANCHOR: Advanced engine initialization with file and ConfigMap support - Phase 3.2 Week 3
// Implements full fallback chain: file → ConfigMap → hardcoded CISControls
// Allows fine-grained control over rule source selection
func NewEngineWithConfig(config *EngineConfig) (*Engine, error) {
	// Validate config is not nil
	if config == nil {
		return nil, fmt.Errorf("EngineConfig cannot be nil")
	}

	logger, _ := zap.NewProduction()

	// Set default ConfigMap data key if not specified
	dataKey := config.ConfigMapDataKey
	if dataKey == "" {
		dataKey = "rules.yaml"
	}

	var rules []*Rule
	var ruleSource string

	// Fallback chain: file → ConfigMap → hardcoded rules
	if config.RuleFilePath != "" {
		loadedRules, err := LoadRulesFromFile(config.RuleFilePath)
		if err != nil {
			if config.StrictSource {
				return nil, fmt.Errorf("failed to load rules from file %s: %w", config.RuleFilePath, err)
			}
			logger.Warn("failed to load rules from file, trying ConfigMap",
				zap.String("file", config.RuleFilePath),
				zap.Error(err))

			// Try ConfigMap as fallback
			if config.ConfigMapName != "" && config.ConfigMapNamespace != "" && config.K8sClientset != nil {
				if config.Ctx == nil {
					config.Ctx = context.Background()
				}
				loadedRules, err := LoadRulesFromConfigMap(config.Ctx, config.K8sClientset, config.ConfigMapName, config.ConfigMapNamespace, dataKey)
				if err != nil {
					logger.Warn("failed to load rules from ConfigMap, using hardcoded rules",
						zap.String("configmap", config.ConfigMapName),
						zap.String("namespace", config.ConfigMapNamespace),
						zap.Error(err))
					rules = loadCISRules()
					ruleSource = "hardcoded"
				} else {
					logger.Info("successfully loaded rules from ConfigMap",
						zap.String("configmap", config.ConfigMapName),
						zap.String("namespace", config.ConfigMapNamespace),
						zap.Int("rule_count", len(loadedRules)))
					rules = loadedRules
					ruleSource = "configmap"
				}
			} else {
				rules = loadCISRules()
				ruleSource = "hardcoded"
			}
		} else {
			logger.Info("successfully loaded rules from file",
				zap.String("file", config.RuleFilePath),
				zap.Int("rule_count", len(loadedRules)))
			rules = loadedRules
			ruleSource = "file"
		}
	} else if config.ConfigMapName != "" && config.ConfigMapNamespace != "" && config.K8sClientset != nil {
		// Try ConfigMap if no file configured
		if config.Ctx == nil {
			config.Ctx = context.Background()
		}
		loadedRules, err := LoadRulesFromConfigMap(config.Ctx, config.K8sClientset, config.ConfigMapName, config.ConfigMapNamespace, dataKey)
		if err != nil {
			if config.StrictSource {
				return nil, fmt.Errorf("failed to load rules from ConfigMap %s/%s: %w", config.ConfigMapNamespace, config.ConfigMapName, err)
			}
			logger.Warn("failed to load rules from ConfigMap, using hardcoded rules",
				zap.String("configmap", config.ConfigMapName),
				zap.String("namespace", config.ConfigMapNamespace),
				zap.Error(err))
			rules = loadCISRules()
			ruleSource = "hardcoded"
		} else {
			logger.Info("successfully loaded rules from ConfigMap",
				zap.String("configmap", config.ConfigMapName),
				zap.String("namespace", config.ConfigMapNamespace),
				zap.Int("rule_count", len(loadedRules)))
			rules = loadedRules
			ruleSource = "configmap"
		}
	} else {
		// No file or ConfigMap configured, use hardcoded rules
		rules = loadCISRules()
		ruleSource = "hardcoded"
	}

	engine := &Engine{
		Rules:  rules,
		Logger: logger,
	}
	prepareRuleCaches(engine.Rules, logger)

	logger.Info("rule engine initialized", zap.String("rule_source", ruleSource))
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
		for i := range rule.Conditions {
			if !e.evaluateCondition(event, &rule.Conditions[i]) {
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
func (e *Engine) evaluateCondition(event *enrichment.EnrichedEvent, cond *Condition) bool {
	if cond == nil {
		return false
	}

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
	case "equals", "==":
		return normalizedEqual(fieldValue, cond.Value)

	case "not_equals", "!=":
		return !normalizedEqual(fieldValue, cond.Value)

	case "contains":
		// String contains check
		if str, ok := fieldValue.(string); ok {
			if val, ok := cond.Value.(string); ok {
				return strings.Contains(str, val)
			}
		}
		return false

	case "in":
		matched, valid := valueInSlice(cond.Value, fieldValue)
		return valid && matched

	case "not_in":
		matched, valid := valueInSlice(cond.Value, fieldValue)
		return valid && !matched

	case "greater_than":
		fv, fOk := toFloat(fieldValue)
		cv, cOk := toFloat(cond.Value)
		return fOk && cOk && fv > cv

	case "less_than":
		fv, fOk := toFloat(fieldValue)
		cv, cOk := toFloat(cond.Value)
		return fOk && cOk && fv < cv

	case "regex":
		pattern, ok := cond.Value.(string)
		if !ok {
			return false
		}
		str, ok := fieldValue.(string)
		if !ok {
			return false
		}
		if cond.compiledRegex != nil {
			return cond.compiledRegex.MatchString(str)
		}
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(str)

	default:
		e.Logger.Warn("unknown operator", zap.String("operator", cond.Operator))
		return false
	}
}

func prepareRuleCaches(rules []*Rule, logger *zap.Logger) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		for i := range rule.Conditions {
			cond := &rule.Conditions[i]
			if cond.Operator != "regex" {
				continue
			}
			pattern, ok := cond.Value.(string)
			if !ok {
				continue
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				if logger != nil {
					logger.Warn("invalid regex pattern", zap.String("pattern", pattern), zap.Error(err))
				}
				continue
			}
			cond.compiledRegex = re
		}
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
	case "kubernetes.has_default_deny_policy":
		if event.Kubernetes != nil {
			return event.Kubernetes.HasDefaultDenyNetworkPolicy
		}
	// ANCHOR: Extended Kubernetes fields for Phase 1 - Dec 26, 2025
	// New fields for RBAC and image registry controls
	case "kubernetes.image_registry":
		if event.Kubernetes != nil {
			return event.Kubernetes.ImageRegistry
		}
	case "kubernetes.image_tag":
		if event.Kubernetes != nil {
			return event.Kubernetes.ImageTag
		}
	case "kubernetes.rbac_enforced":
		if event.Kubernetes != nil {
			return event.Kubernetes.RBACEnforced
		}
	case "kubernetes.rbac_level":
		if event.Kubernetes != nil {
			return event.Kubernetes.RBACLevel
		}
	case "kubernetes.service_account_token_age":
		if event.Kubernetes != nil {
			return event.Kubernetes.ServiceAccountTokenAge
		}
	case "kubernetes.service_account_permissions":
		if event.Kubernetes != nil {
			return event.Kubernetes.ServiceAccountPermissions
		}
	case "kubernetes.rbac_policy_defined":
		if event.Kubernetes != nil {
			return event.Kubernetes.RBACPolicyDefined
		}
	case "kubernetes.role_permission_count":
		if event.Kubernetes != nil {
			return event.Kubernetes.RolePermissionCount
		}
	case "kubernetes.audit_logging_enabled":
		if event.Kubernetes != nil {
			return event.Kubernetes.AuditLoggingEnabled
		}
	// ANCHOR: extractField case for automount_service_account_token - Bug: CIS_5.2.1 never fires - Apr 20, 2026
	// cis_mappings.go:526 uses operator "equals", value true — fires when auto-mount is on.
	// Without this case, extractField returns nil and the condition never satisfies.
	case "kubernetes.automount_service_account_token":
		if event.Kubernetes != nil {
			return event.Kubernetes.AutomountServiceAccountToken
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
	case "container.security_context.privileged":
		if event.Container != nil {
			return event.Container.Privileged
		}
	case "container.run_as_root":
		if event.Container != nil {
			return event.Container.RunAsRoot
		}
	// ANCHOR: Extended container security context fields - Dec 26, 2025
	// New fields for Phase 1 CIS control expansion
	case "container.allow_privilege_escalation":
		if event.Container != nil {
			if !event.Container.AllowPrivilegeEscalationKnown {
				return nil
			}
			return event.Container.AllowPrivilegeEscalation
		}
	case "container.host_network":
		if event.Container != nil {
			return event.Container.HostNetwork
		}
	case "container.host_ipc":
		if event.Container != nil {
			return event.Container.HostIPC
		}
	case "container.host_pid":
		if event.Container != nil {
			return event.Container.HostPID
		}
	case "container.seccomp_profile":
		if event.Container != nil {
			return event.Container.SeccompProfile
		}
	case "container.apparmor_profile":
		if event.Container != nil {
			return event.Container.ApparmorProfile
		}
	case "container.image_pull_policy":
		if event.Container != nil {
			return event.Container.ImagePullPolicy
		}
	case "container.image_scan_status":
		if event.Container != nil {
			return event.Container.ImageScanStatus
		}
	case "container.image_registry_auth":
		if event.Container != nil {
			return event.Container.ImageRegistryAuth
		}
	case "container.image_signed":
		if event.Container != nil {
			return event.Container.ImageSigned
		}
	case "container.memory_limit":
		if event.Container != nil {
			return event.Container.MemoryLimit
		}
	case "container.cpu_limit":
		if event.Container != nil {
			return event.Container.CPULimit
		}
	case "container.memory_request":
		if event.Container != nil {
			return event.Container.MemoryRequest
		}
	case "container.cpu_request":
		if event.Container != nil {
			return event.Container.CPURequest
		}
	case "container.storage_request":
		if event.Container != nil {
			return event.Container.StorageRequest
		}
	case "container.read_only_filesystem":
		if event.Container != nil {
			return event.Container.ReadOnlyFilesystem
		}
	case "container.volume_type":
		if event.Container != nil {
			return event.Container.VolumeType
		}
	case "container.selinux_level":
		if event.Container != nil {
			return event.Container.SELinuxLevel
		}
	case "container.isolation_level":
		if event.Container != nil {
			return event.Container.IsolationLevel
		}
	case "container.kernel_hardening":
		if event.Container != nil {
			return event.Container.KernelHardening
		}

	// Process fields
	case "process.uid":
		if event.Process != nil {
			return int(event.Process.UID)
		}
	case "process.pid":
		if event.Process != nil {
			return int(event.Process.PID)
		}
	case "process.command":
		if event.Process != nil {
			return event.Process.Command
		}

	// File fields
	case "file.path":
		if event.File != nil {
			return event.File.Path
		}
	case "file.operation":
		if event.File != nil {
			return event.File.Operation
		}

	// Capability fields
	case "capability.name":
		if event.Capability != nil {
			return event.Capability.Name
		}
	case "capability.allowed":
		if event.Capability != nil {
			return event.Capability.Allowed
		}

	// ANCHOR: Network context fields for Phase 1 - Dec 26, 2025
	// Support for network policy and DNS rules
	case "network.ingress_restricted":
		if event.Network != nil {
			return event.Network.IngressRestricted
		}
	case "network.egress_restricted":
		if event.Network != nil {
			return event.Network.EgressRestricted
		}
	case "network.namespace_isolation":
		if event.Network != nil {
			return event.Network.NamespaceIsolation
		}

	case "dns.query_allowed":
		if event.DNS != nil {
			return event.DNS.QueryAllowed
		}

	default:
		return nil
	}

	return nil
}

// valueInSlice checks if fieldValue is contained within slice-like condValue
func valueInSlice(condValue interface{}, fieldValue interface{}) (bool, bool) {
	if condValue == nil {
		return false, false
	}

	val := reflect.ValueOf(condValue)
	if val.Kind() != reflect.Slice && val.Kind() != reflect.Array {
		return false, false
	}

	for i := 0; i < val.Len(); i++ {
		if normalizedEqual(val.Index(i).Interface(), fieldValue) {
			return true, true
		}
	}

	return false, true
}

func normalizedEqual(lhs, rhs interface{}) bool {
	if lf, ok := toFloat(lhs); ok {
		if rf, ok := toFloat(rhs); ok {
			return lf == rf
		}
	}

	if lb, ok := toBool(lhs); ok {
		if rb, ok := toBool(rhs); ok {
			return lb == rb
		}
	}

	ls, lOK := lhs.(string)
	rs, rOK := rhs.(string)
	if lOK && rOK {
		return ls == rs
	}

	return reflect.DeepEqual(lhs, rhs)
}

// toFloat converts ints uints etc. to float64 for comparisons
func toFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

func toBool(value interface{}) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return false, false
		}
		return parsed, true
	default:
		return false, false
	}
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
// ANCHOR: Load CIS rules from in-repo mappings - Dec 26, 2025
func loadCISRules() []*Rule {
	return CISControls
}

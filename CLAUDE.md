# elf-owl Development Guide for Claude

**Version:** 1.0.0
**Date:** December 27, 2025
**Project:** elf-owl - Kubernetes Compliance Agent with eBPF Event Enrichment
**Status:** Week 3 - Active Development

---

## Table of Contents

1. [Code Changes Workflow](#code-changes-workflow)
2. [Anchor Comments Requirement](#anchor-comments-requirement)
3. [Git Commit Message Types](#git-commit-message-types)
4. [Code Review Standards](#code-review-standards)
5. [Project Structure & Key Files](#project-structure--key-files)
6. [Development Workflow](#development-workflow)
7. [Important Constraints](#important-constraints)
8. [Common Development Tasks](#common-development-tasks)

---

## Code Changes Workflow

### Plan-First Approach (MANDATORY)

Claude **MUST** follow this workflow for ALL code changes:

1. **Understand the Request** - Read and comprehend the user's request
2. **Explore Codebase** - Use Glob, Grep, and Read tools to understand affected code
3. **Create a Plan** - Document the proposed changes with:
   - Files to modify
   - Specific line numbers and sections
   - Rationale for each change
   - Potential side effects or impacts
4. **Present Plan to User** - Show the plan and wait for explicit approval
5. **Implement After Approval** - Only make code changes after user explicitly approves
6. **Test and Verify** - Run tests and verify changes work correctly

**DO NOT make code changes without an approved plan.**

### Plan Presentation Template

When presenting a plan, use this structure:

```
## Plan: [Feature/Fix Name]

### Overview
[One sentence description of what will be done]

### Files to Modify

1. File: `path/to/file.go`
   - Lines: XX-YY
   - Change: [What will be modified]
   - Reason: [Why this change is necessary]
   - Anchor Comment: [Proposed ANCHOR comment]

2. File: `path/to/file2.go`
   - Lines: AA-BB
   - Change: [What will be modified]
   - Reason: [Why this change is necessary]
   - Anchor Comment: [Proposed ANCHOR comment]

### Git Commits

1. `type: message` - Commit 1 description
2. `type: message` - Commit 2 description

### Testing

- [How changes will be tested]
- [What could go wrong]
- [How to verify success]

### Approval

Please review and approve before implementation begins.
```

---

## Anchor Comments Requirement

### Why Anchor Comments?

Anchor comments serve as documentation and traceability markers in the codebase. They help future developers understand:
- What a code section does
- Why it was implemented that way
- What bug or issue it addresses
- When it was added

### Anchor Comment Format

All new code and modified code sections **MUST** include anchor comments:

```go
// ANCHOR: [PURPOSE] - [BUG/ISSUE/FEATURE] - [DATE]
// [Detailed explanation of the approach and rationale]
```

### Anchor Comment Examples

**Example 1: Bug Fix**
```go
// ANCHOR: NetworkPolicy label selector matching - Bug #2: MatchExpressions ignored - Dec 20, 2025
// Implemented full label selector evaluation including MatchExpressions operators (In, NotIn, Exists, DoesNotExist).
// Previous code only checked MatchLabels, causing false positives in CIS 4.6.5 network isolation checks.
func (c *Client) selectorMatches(selector *metav1.LabelSelector, labels map[string]string) bool {
	// Implementation...
}
```

**Example 2: New Feature**
```go
// ANCHOR: Rule loading from YAML file - Feature: Configurable CIS controls - Jan 8, 2026
// Allows operators to load CIS rules from external YAML files instead of hardcoded mappings.
// Supports dynamic rule updates without code changes or recompilation.
func LoadRulesFromFile(filePath string) ([]*Rule, error) {
	// Implementation...
}
```

**Example 3: Complex Logic Section**
```go
// ANCHOR: RBAC privilege level calculation - Enhancement: Multi-level privilege detection - Dec 21, 2025
// Calculates privilege levels across RoleBindings and ClusterRoleBindings using permission counting.
// Levels: 0=restricted (0 permissions), 1=standard (1-10), 2=elevated (11-100), 3=admin (100+).
func (c *Client) GetRBACLevel(ctx context.Context, serviceAccount, namespace string) (int, error) {
	// Implementation...
}
```

### Where to Add Anchor Comments

**DO add anchors for:**
- New functions and methods
- Critical bug fixes
- Complex logic sections
- Integration points with other systems
- Configuration/flag handling
- Error handling paths
- Security-sensitive code
- Performance optimizations

**DO NOT add anchors for:**
- Simple variable assignments
- Loop bodies in straightforward iteration
- Standard library usage without customization
- Self-explanatory code (e.g., `count := count + 1`)
- Comments that already exist and are clear

---

## Git Commit Message Types

### Message Format

Use conventional commit message format:

```
type: description

[Optional detailed explanation]
```

### Commit Types

| Type | Usage | Example |
|------|-------|---------|
| **feat** | Adding a New Feature | `feat: implement rule loading from YAML file` |
| **fix** | Bug Fixes | `fix: correct NetworkPolicy selector matching for MatchExpressions` |
| **chore** | Maintenance & Non-Code Updates | `chore: update Go dependencies` |
| **style** | Code Formatting (No Logic Changes) | `style: format enricher.go to match linter` |
| **refactor** | Code Improvement Without Changing Functionality | `refactor: extract label matching to helper function` |
| **docs** | Documentation Updates | `docs: add remediation examples for CIS_4.5.1` |
| **perf** | Performance Improvements | `perf: optimize pod lookup with concurrent metadata cache` |
| **test** | Adding or Updating Tests | `test: add integration tests for enrichment pipeline` |
| **ci** | Changes to CI/CD Configuration | `ci: add golangci-lint configuration` |

### Commit Message Guidelines

- **First line:** Short, imperative mood, present tense (50 chars max)
- **Blank line:** Separate subject from body
- **Body:** Explain **why** not **what** (lines 72 chars max)
- **References:** Include issue/bug numbers when applicable
- **Co-author:** Include Claude as co-author

### Example Good Commit

```
fix: correct pod lookup optimization causing cache misses

The container ID extraction was using partial cgroup paths that didn't
consistently match pod UIDs in the cache. This caused 30% cache miss
rate for subsequent enrichment lookups.

Changed to extract full pod UID from cgroup hierarchy:
  /kubepods.slice/kubepods-pod{UID}.slice → {UID}

This fixes Bug #5 where network policies weren't being attached to
enriched events due to missing pod metadata.

Fixes: #74

🤖 Generated with Claude Code

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Code Review Standards

### Before Making Changes

- [ ] Plan created and approved by user
- [ ] Anchor comments identified in plan
- [ ] Commit messages planned
- [ ] Potential impacts understood
- [ ] Existing tests reviewed

### During Implementation

- [ ] Anchor comments added to code
- [ ] Changes minimal and targeted
- [ ] No over-engineering
- [ ] Error handling complete
- [ ] Logging included (if relevant)
- [ ] Code follows project style

### After Implementation

- [ ] All modified files reviewed
- [ ] Anchor comments verified present
- [ ] Commit message matches type guidelines
- [ ] Tests pass (if applicable)
- [ ] No security vulnerabilities introduced
- [ ] No performance regressions

---

## Project Structure & Key Files

### Core Directories

```
elf-owl/
├── cmd/elf-owl/                 # Agent entry point
│   └── main.go                  # Bootstrap code
│
├── pkg/
│   ├── agent/                   # Core agent orchestration
│   │   ├── agent.go             # Main agent loop
│   │   └── config.go            # Configuration types
│   │
│   ├── enrichment/              # Event enrichment pipeline
│   │   ├── types.go             # Data structures (700+ LOC)
│   │   └── enricher.go          # Enrichment logic (300+ LOC)
│   │
│   ├── rules/                   # Rule engine & CIS mappings
│   │   ├── engine.go            # Rule matching engine (300+ LOC)
│   │   ├── cis_mappings.go      # 48 CIS control definitions (600+ LOC)
│   │   ├── loader.go            # Rule loading from files/ConfigMaps
│   │   ├── engine_test.go       # Rule engine tests
│   │   ├── loader_test.go       # Loader tests
│   │   └── integration_test.go  # Integration tests
│   │
│   ├── kubernetes/              # K8s metadata client
│   │   ├── client.go            # K8s API client (600+ LOC)
│   │   └── cache.go             # Metadata cache (200+ LOC)
│   │
│   ├── evidence/                # Evidence processing
│   │   ├── signer.go            # HMAC-SHA256 signing
│   │   ├── cipher.go            # AES-256-GCM encryption
│   │   └── buffer.go            # Event buffering
│   │
│   ├── api/                     # Owl SaaS API client
│   │   └── client.go            # API communication
│   │
│   ├── config/                  # Configuration
│   │   └── types.go             # Config structures
│   │
│   ├── metrics/                 # Prometheus metrics
│   │   └── prometheus.go        # Metrics definitions
│   │
│   └── logger/                  # Structured logging
│       └── logger.go            # Zap logger setup
│
├── docs/
│   ├── remediation.md           # CIS control remediation guide
│   └── architecture.md          # Architecture overview
│
├── config/
│   ├── elf-owl.yaml             # Default configuration
│   └── rules/                   # Rule definitions
│       └── cis-controls.yaml    # CIS control rules (YAML)
│
├── deploy/
│   ├── helm/                    # Helm chart
│   └── kustomize/               # Kustomize overlays
│
└── test/
    ├── fixtures/                # Test data
    └── integration/             # Integration tests
```

### Key File Descriptions

#### `pkg/enrichment/types.go` (700+ LOC)
- **Purpose:** Data structures for enriched events
- **Key Types:**
  - `EnrichedEvent` - Main event structure with all context
  - `K8sContext` - Kubernetes pod and cluster metadata (40+ fields)
  - `ContainerContext` - Container security context
  - `ProcessContext` - Process execution details
  - `FileContext` - File operation context
  - `NetworkContext` - Network event details
  - `DNSContext` - DNS query details
  - `CapabilityContext` - Linux capability info

#### `pkg/enrichment/enricher.go` (300+ LOC)
- **Purpose:** Enrich events with Kubernetes metadata
- **Key Functions:**
  - `EnrichProcessEvent()` - Add K8s context to process events
  - `EnrichNetworkEvent()` - Add K8s context to network events
  - `EnrichFileEvent()` - Add K8s context to file events
- **Integration:** Uses K8s client and cache for metadata lookup

#### `pkg/rules/engine.go` (300+ LOC)
- **Purpose:** Match events against CIS control rules
- **Key Functions:**
  - `NewEngine()` - Create engine with fallback rule loading
  - `Match()` - Match event against all rules
  - `evaluateCondition()` - Evaluate single condition
  - `extractField()` - Extract field from event (40+ fields)
- **Operators:** equals, not_equals, contains, in, greater_than, less_than

#### `pkg/rules/cis_mappings.go` (600+ LOC)
- **Purpose:** Define all 48 automated CIS Kubernetes v1.8 controls
- **Structure:** Array of `Rule` objects with conditions
- **Rule Categories:**
  - Pod Security Context (8 rules: CIS 4.2.x)
  - Container Image & Registry (6 rules: CIS 4.3.x)
  - Resource Management (5 rules: CIS 4.4.x)
  - Network Policy (5 rules: CIS 4.6.x)
  - RBAC & Access Controls (10 rules: CIS 5.x.x)
  - Advanced Security Context (9 rules: CIS 4.7-4.9)

#### `pkg/kubernetes/client.go` (600+ LOC)
- **Purpose:** K8s API client for metadata extraction
- **Key Functions:**
  - `GetPodMetadata()` - Retrieve pod spec and status
  - `GetNetworkPolicyStatus()` - Evaluate network policies
  - `GetServiceAccountMetadata()` - RBAC information
  - `GetRBACLevel()` - Calculate privilege escalation level
  - `selectorMatches()` - Label selector matching with MatchExpressions

#### `pkg/rules/loader.go`
- **Purpose:** Load rules from files and ConfigMaps
- **Key Functions:**
  - `LoadRulesFromFile()` - Load from YAML file
  - `LoadRulesFromConfigMap()` - Load from K8s ConfigMap
  - `ConvertYAMLToRule()` - Parse YAML into Rule objects

### Critical Implementation Details

#### Event Enrichment Pipeline

1. **Container ID Extraction:** Extract from cgroup hierarchy
2. **Pod Lookup:** Query K8s API using container ID
3. **Metadata Injection:** Extract security context, RBAC, network policies
4. **Caching:** 5-minute TTL cache for performance
5. **Default Population:** Use safe defaults for missing fields

#### Rule Matching Logic

1. **Event Type Filter:** Check if event type matches rule
2. **Condition Evaluation:** Evaluate all conditions (AND logic)
3. **Field Extraction:** Extract field values from enriched event
4. **Operator Application:** Apply comparison operators
5. **Violation Generation:** Create violation if all conditions match

#### RBAC Privilege Calculation

- **Level 0:** Restricted (0 permissions)
- **Level 1:** Standard (1-10 permissions)
- **Level 2:** Elevated (11-100 permissions)
- **Level 3:** Admin (100+ permissions)

#### Label Selector Matching

- **MatchLabels:** Direct key=value matches
- **MatchExpressions:** Operator-based matching (In, NotIn, Exists, DoesNotExist)
- **Empty Selector:** Matches all pods

---

## Development Workflow

### Standard Development Steps

1. **Read existing code** - Understand current implementation
2. **Create plan** - Document proposed changes
3. **Get approval** - Wait for user sign-off
4. **Implement** - Make changes with anchor comments
5. **Add tests** - Test new functionality
6. **Commit** - Use proper commit message types
7. **Verify** - Run full test suite

### Running Tests

```bash
# Run all unit tests
go test ./pkg/...

# Run specific package tests
go test ./pkg/rules/... -v

# Run integration tests
go test ./test/integration/...

# Run with coverage
go test -cover ./pkg/...

# Run specific test
go test -run TestEnginMatch ./pkg/rules/
```

### Building the Project

```bash
# Build agent binary
go build -o elf-owl cmd/elf-owl/main.go

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o elf-owl-linux cmd/elf-owl/main.go
```

### Code Style

- Follow Go idioms and conventions
- Use `gofmt` for formatting
- Keep functions focused and testable
- Write clear variable names
- Add comments for non-obvious logic
- Use structured logging with zap

---

## Important Constraints

### DO

- ✅ Always create a plan first
- ✅ Wait for explicit user approval
- ✅ Include anchor comments in all modified code
- ✅ Use correct commit message types
- ✅ Write clear commit messages
- ✅ Read files before editing
- ✅ Test changes after implementation
- ✅ Document complex logic
- ✅ Handle errors gracefully
- ✅ Consider backward compatibility

### DO NOT

- ❌ Make code changes without an approved plan
- ❌ Skip anchor comments in modified sections
- ❌ Use incorrect commit message types
- ❌ Over-engineer solutions
- ❌ Add unnecessary features beyond the request
- ❌ Make commits without proper messages
- ❌ Modify code without reading it first
- ❌ Assume code behavior without verification
- ❌ Break existing tests
- ❌ Ignore error handling

---

## Common Development Tasks

### Task 1: Add a New CIS Control Rule

**Plan Structure:**
1. Add rule to `pkg/rules/cis_mappings.go` array
2. Define conditions based on eBPF event fields
3. Add unit test to `pkg/rules/engine_test.go`
4. Add remediation guidance to `docs/remediation.md`

**Anchor Comment Example:**
```go
// ANCHOR: [Control ID]: [Control Title] - Feature: CIS Kubernetes v1.8 - [DATE]
// Detects [what it detects]. Requires [event type] event type and [field] condition match.
```

### Task 2: Fix a Rule Matching Bug

**Plan Structure:**
1. Read the affected rule and related tests
2. Identify the root cause (event type, field extraction, condition logic)
3. Trace through rule engine code
4. Propose fix with before/after examples
5. Create test case that reproduces bug

**Anchor Comment Example:**
```go
// ANCHOR: [Rule ID] condition matching - Bug #N: [Issue description] - [DATE]
// Previous code failed to [what was wrong]. Changed to [solution].
```

### Task 3: Enhance Event Enrichment

**Plan Structure:**
1. Add new fields to `EnrichedEvent` struct
2. Add extraction logic to enricher
3. Update K8s client if new API calls needed
4. Update rule conditions to use new fields
5. Test enrichment pipeline

**Anchor Comment Example:**
```go
// ANCHOR: Enrichment field: [field name] - Feature: [Enhancement description] - [DATE]
// Extracts [description]. Used by [CIS controls].
```

### Task 4: Update Rule Loader

**Plan Structure:**
1. Modify `LoadRulesFromFile()` or `LoadRulesFromConfigMap()`
2. Update error handling and validation
3. Add unit tests for new loading scenarios
4. Verify fallback chain still works

**Anchor Comment Example:**
```go
// ANCHOR: Rule loading from [source] - Feature: [Enhancement] - [DATE]
// Implements [functionality]. Supports [features].
```

---

## File Modification Checklist

When modifying existing files:

1. **Read First** - Always read the file completely before editing
2. **Identify Impact** - Note all functions/sections affected
3. **Preserve Style** - Match existing code style and patterns
4. **Add Anchors** - Include anchor comments in modified sections
5. **Test Scope** - Consider what tests are affected
6. **Document Changes** - Update relevant documentation
7. **Commit Atomically** - One logical change per commit

---

## Special Cases

### Security-Sensitive Code

- Extra-detailed plan required
- All edge cases must be covered
- Must verify no vulnerabilities introduced
- Consider authorization and authentication implications

### Performance-Critical Code

- Plan must include performance impact analysis
- Consider benchmarking existing vs. new code
- Anchor comments must explain optimization
- Document any trade-offs

### Configuration/Flag Changes

- Must document default values
- Must explain impact on existing deployments
- Include migration guidance if breaking

### Data Structure Changes

- Plan must include migration strategy
- Must document backward compatibility
- Explain data transformation logic
- Update all code that uses the structure

---

## Questions & Support

If any guideline is unclear:
- Ask user for clarification before proceeding
- Do not guess or assume behavior
- Document the clarification in comments
- Update this CLAUDE.md if guideline is ambiguous

For questions about:
- Architecture: Refer to README.md and SPRINT.md
- Code structure: Check project structure section above
- CIS controls: See docs/remediation.md
- Implementation details: Check commit messages and anchor comments

---

## Quick Reference

### When to Anchor Comment
```
New functions/methods → YES
Bug fixes → YES
Complex logic → YES
Security-sensitive code → YES
Simple assignments → NO
Standard library usage → NO
Already-commented code → NO
```

### When to Plan
```
Any code changes → YES
Adding functions → YES
Modifying existing code → YES
Fixing bugs → YES
Refactoring → YES
Documentation only → MAYBE
Tests only → MAYBE
```

### Commit Type Selection
```
New feature → feat
Bug fix → fix
Test additions → test
Documentation → docs
Code cleanup → refactor
Formatting → style
Performance → perf
Maintenance → chore
CI/CD changes → ci
```

---

**Last Updated:** December 27, 2025
**Status:** Active - Binding Guidelines
**Version:** 1.0.0
**Authority:** elf-owl Project Standards

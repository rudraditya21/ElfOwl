# CIS Kubernetes v1.8 Remediation Guide

## Overview

This document provides remediation guidance for all 48 automated CIS Kubernetes v1.8 controls implemented in elf-owl. Each control includes:
- Control ID and description
- Severity level
- What the control detects
- Remediation steps with YAML examples
- Best practices

---

## Pod Security Context Controls (CIS 4.1.x, 4.2.x, 4.5.x)

### CIS 4.5.1: Minimize the admission of privileged containers
**Severity:** CRITICAL

**What it detects:** Containers running with `securityContext.privileged: true`

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: false  # Explicitly disable privilege
      allowPrivilegeEscalation: false
```

**Best Practices:**
- Never run containers as privileged unless absolutely necessary
- If privileged access is required, use specific capabilities instead
- Use Pod Security Standards to enforce this at admission level
- Audit logs to identify privileged containers

---

### CIS 4.5.2: Ensure containers do not run as root
**Severity:** HIGH

**What it detects:** Processes with UID 0 (root) inside containers in pods

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000  # Use dedicated non-root user
    runAsGroup: 3000
    fsGroup: 2000
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
```

**Best Practices:**
- Create dedicated users in Dockerfile (USER directive)
- Set runAsNonRoot: true in securityContext
- Use fixed UID/GID for reproducibility
- Avoid running as root even in development

**Dockerfile Example:**
```dockerfile
FROM ubuntu:20.04
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
COPY --chown=appuser:appuser app /app
```

---

### CIS 4.5.3: Minimize Linux Kernel Capability usage
**Severity:** HIGH

**What it detects:** Use of dangerous Linux capabilities (NET_ADMIN, SYS_ADMIN, SYS_MODULE, SYS_PTRACE, SYS_BOOT, MAC_ADMIN)

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      drop:
        - ALL  # Drop all capabilities
      add:
        - NET_BIND_SERVICE  # Add only required capabilities
```

**Best Practices:**
- Drop ALL capabilities by default
- Add only minimum required capabilities
- Document why each capability is needed
- Use CAP_NET_BIND_SERVICE instead of running as root

---

### CIS 4.5.5: Ensure the filesystem is read-only where possible
**Severity:** MEDIUM

**What it detects:** Writes to system directories (/, /bin, /sbin, /usr/bin, /usr/sbin, /etc, /lib, /usr/lib)

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

**Best Practices:**
- Set readOnlyRootFilesystem: true when possible
- Mount /tmp and cache directories as emptyDir
- Build container images with minimal attack surface
- Log any denied writes to audit logs

---

### CIS 4.1.1: Ensure ServiceAccount admission controller is enabled
**Severity:** HIGH

**What it detects:** Use of default ServiceAccount

**Remediation:**
```yaml
# Create dedicated ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: default

---
# Reference in Pod
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  serviceAccountName: myapp-sa
  serviceAccount: myapp-sa
  automountServiceAccountToken: false  # Disable if not needed
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Create dedicated ServiceAccount for each application
- Never use default ServiceAccount
- Set automountServiceAccountToken: false if not needed
- Use RBAC to restrict ServiceAccount permissions

---

### CIS 4.6.1: Ensure default deny NetworkPolicy is in place
**Severity:** HIGH

**What it detects:** Absence of default-deny NetworkPolicy

**Remediation:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-traffic
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443  # HTTPS only
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

**Best Practices:**
- Deploy default-deny NetworkPolicy in all namespaces
- Use selector-based policies for pod communication
- Implement egress rules to restrict outbound traffic
- Test policies before enforcement

---

### CIS 4.2.1: Ensure runAsNonRoot enforcement
**Severity:** HIGH

**What it detects:** Containers running with runAsRoot: true

**Remediation:** (See CIS 4.5.2 above)

---

### CIS 4.2.2: Minimize allowPrivilegeEscalation
**Severity:** HIGH

**What it detects:** Containers with allowPrivilegeEscalation: true

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
```

**Best Practices:**
- Set allowPrivilegeEscalation: false
- Combine with runAsNonRoot: true
- Drop unsafe capabilities

---

### CIS 4.2.3: Ensure hostNetwork is disabled
**Severity:** HIGH

**What it detects:** Pods with hostNetwork: true

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  hostNetwork: false  # Explicitly disable (default)
  containers:
  - name: app
    image: myapp:latest
    ports:
    - containerPort: 8080
```

**Best Practices:**
- Never use hostNetwork unless necessary
- Use service port mapping instead
- Restrict by namespace with Pod Security Standards

---

### CIS 4.2.4: Ensure hostIPC is disabled
**Severity:** HIGH

**What it detects:** Pods with hostIPC: true

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  hostIPC: false  # Explicitly disable (default)
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Disable hostIPC for all containers
- Use inter-process communication within pod only
- Use volumes for shared data between pods

---

### CIS 4.2.5: Ensure hostPID is disabled
**Severity:** HIGH

**What it detects:** Pods with hostPID: true

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  hostPID: false  # Explicitly disable (default)
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Disable hostPID for all containers
- Isolate process namespaces
- Use debugging sidecars for troubleshooting

---

### CIS 4.2.6: Ensure restrictive capabilities
**Severity:** HIGH

**What it detects:** Containers with dangerous capabilities (NET_ADMIN, NET_RAW, SYS_ADMIN, SYS_MODULE, etc.)

**Remediation:** (See CIS 4.5.3 above)

---

### CIS 4.2.7: Ensure seccomp enforcement
**Severity:** MEDIUM

**What it detects:** Containers with seccomp profile "unconfined"

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: localhost/my-profile.json
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: my-profile.json
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: my-profile.json
```

**Best Practices:**
- Use RuntimeDefault seccomp profile
- Deploy custom profiles for specific applications
- Test profiles in audit mode first
- Update profiles based on application needs

---

### CIS 4.2.8: Ensure AppArmor enforcement
**Severity:** MEDIUM

**What it detects:** Containers with AppArmor "unconfined"

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/my-profile
spec:
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Load AppArmor profiles on all nodes
- Use container.apparmor.security.beta.kubernetes.io annotations
- Start with audit mode before enforcement
- Monitor AppArmor violations

---

## Container Image & Registry Controls (CIS 4.3.x)

### CIS 4.3.1: Ensure images from known registry
**Severity:** MEDIUM

**What it detects:** Container images from unknown registries (not docker.io)

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myregistry.azurecr.io/myapp:v1.2.3  # Use private registry
  imagePullSecrets:
  - name: myregistry-credentials
```

**Best Practices:**
- Use only vetted, internal registries
- Configure registry mirrors in container runtime
- Use image pull secrets for authentication
- Audit all image sources

---

### CIS 4.3.2: Ensure images without 'latest' tag
**Severity:** MEDIUM

**What it detects:** Containers using 'latest' tag

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:v1.2.3  # Use specific version tag
```

**Best Practices:**
- Always use specific version tags
- Use semantic versioning (v1.2.3)
- Implement admission controller to enforce
- Automate tag management in CI/CD

---

### CIS 4.3.3: Ensure image pull policy is Always
**Severity:** MEDIUM

**What it detects:** imagePullPolicy not set to Always

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:v1.2.3
    imagePullPolicy: Always  # Always pull to get latest security patches
```

**Best Practices:**
- Set imagePullPolicy: Always
- Ensures latest image is always pulled
- Critical for security patches
- Combine with image scanning

---

### CIS 4.3.4: Minimize admission of images with unknown vulnerabilities
**Severity:** MEDIUM

**What it detects:** Images not scanned for vulnerabilities

**Remediation:**
```yaml
# Use vulnerability scanning in CI/CD
# Example: Trivy, Snyk, or Aqua Security
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  annotations:
    image-scan-status: "scanned"
    vulnerability-count: "0"
spec:
  containers:
  - name: app
    image: myapp:v1.2.3  # Only use scanned images
```

**Best Practices:**
- Implement image scanning in registry
- Fail build on critical vulnerabilities
- Use Trivy, Snyk, or Aqua Security
- Regular rescans of deployed images

---

### CIS 4.3.5: Ensure image registry access control
**Severity:** HIGH

**What it detects:** Images from registries without authentication

**Remediation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockercfg
data:
  .dockercfg: <base64-encoded-credentials>

---
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  imagePullSecrets:
  - name: registry-credentials
  containers:
  - name: app
    image: private-registry.com/myapp:v1.2.3
```

**Best Practices:**
- Require authentication for all registries
- Use imagePullSecrets in all deployments
- Rotate registry credentials regularly
- Use short-lived tokens when possible

---

### CIS 4.3.6: Ensure image signature verification
**Severity:** HIGH

**What it detects:** Unsigned container images

**Remediation:**
```yaml
# Use Notary or other signing tools
# Configure admission controller to verify signatures

apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-signature-verification
webhooks:
- name: verify.image.signature
  clientConfig:
    service:
      name: image-verifier
      namespace: security
      path: "/verify"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
```

**Best Practices:**
- Sign all images with organization key
- Use Notary or cosign for signing
- Verify signatures at admission time
- Rotate signing keys regularly

---

## Resource Management Controls (CIS 4.4.x)

### CIS 4.4.1: Ensure container memory limit is set
**Severity:** MEDIUM

**What it detects:** Containers without memory limits

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    resources:
      limits:
        memory: "512Mi"
      requests:
        memory: "256Mi"
```

**Best Practices:**
- Set memory limits for all containers
- Use requests for scheduling
- Use limits to prevent OOM kills
- Monitor actual usage to right-size

---

### CIS 4.4.2: Ensure CPU limit is set
**Severity:** MEDIUM

**What it detects:** Containers without CPU limits

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    resources:
      limits:
        cpu: "500m"
      requests:
        cpu: "250m"
```

**Best Practices:**
- Set CPU limits for predictable performance
- Use CPU requests for scheduler placement
- Monitor throttling events
- Use VPA for auto-sizing

---

### CIS 4.4.3-4.5: Ensure memory and storage requests
**Severity:** MEDIUM

**What it detects:** Missing resource requests

**Remediation:** (See above - use requests in addition to limits)

---

## Network Policy Controls (CIS 4.6.x)

### CIS 4.6.1-4.6.5: Network Policy Controls
**Severity:** HIGH

**What it detects:** Missing network policies or unrestricted traffic

**Remediation:** (See CIS 4.6.1 above for comprehensive examples)

---

## RBAC & Access Controls (CIS 5.x.x)

### CIS 5.1.1: Ensure cluster admin RBAC is enforced
**Severity:** CRITICAL

**What it detects:** Missing RBAC policies for cluster-admin

**Remediation:**
```yaml
# Define minimal required ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: app-reader
subjects:
- kind: ServiceAccount
  name: myapp-sa
  namespace: default
```

**Best Practices:**
- Never grant cluster-admin to applications
- Use least privilege principle
- Create custom roles for specific needs
- Regular RBAC audits

---

### CIS 5.1.2: Ensure minimal RBAC access
**Severity:** HIGH

**What it detects:** ServiceAccounts with excessive permissions (rbac_level > 2)

**Remediation:** (See CIS 5.1.1 - use custom roles instead of cluster-admin)

---

### CIS 5.2.1: Ensure ServiceAccount token is not auto-mounted
**Severity:** HIGH

**What it detects:** automountServiceAccountToken: true

**Remediation:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: default
automountServiceAccountToken: false

---
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  serviceAccountName: myapp-sa
  automountServiceAccountToken: false  # Explicitly disable
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Disable auto-mounting by default
- Mount only when explicitly needed
- Use projected volumes for tokens
- Rotate tokens regularly

---

### CIS 5.2.2: Service account token validity
**Severity:** MEDIUM

**What it detects:** ServiceAccount tokens older than 30 days

**Remediation:**
```yaml
# Implement token rotation in application
# Use audience restriction for tokens
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  serviceAccountName: myapp-sa
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          audience: api
          expirationSeconds: 3600
          path: token
```

**Best Practices:**
- Rotate tokens regularly
- Use short-lived tokens when possible
- Implement token refresh in applications
- Monitor token age

---

### CIS 5.3.1: Ensure default ServiceAccount is not used
**Severity:** HIGH

**What it detects:** Use of default ServiceAccount

**Remediation:** (See CIS 4.1.1)

---

### CIS 5.3.2: Service account permissions
**Severity:** HIGH

**What it detects:** ServiceAccounts with >5 permissions

**Remediation:** (See CIS 5.1.1 - limit permissions)

---

### CIS 5.4.1-5.4.2: Role-based access control
**Severity:** HIGH

**What it detects:** Missing or overly permissive roles

**Remediation:**
```yaml
# Example: Role for reading pods in specific namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
```

**Best Practices:**
- Use Role for namespace scope
- Use ClusterRole only when necessary
- Define granular permissions
- Regular RBAC audits

---

### CIS 5.5.1: Audit logging for RBAC
**Severity:** HIGH

**What it detects:** Audit logging disabled

**Remediation:**
```yaml
# Enable audit logging in kube-apiserver
# Add to kube-apiserver static pod spec:
# --audit-log-path=/var/log/kubernetes/audit.log
# --audit-log-maxage=30
# --audit-log-maxbackup=10
# --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

**Audit Policy Example:**
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  verbs: ["create", "delete", "patch", "update"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
- level: Metadata
  verbs: ["get", "list", "watch"]
  resources: ["*"]
- level: None
  verbs: ["get"]
  resources: ["*/status"]
```

**Best Practices:**
- Enable comprehensive audit logging
- Monitor RBAC changes
- Aggregate logs to central location
- Regular audit reviews

---

## Advanced Security Context Controls (CIS 4.7-4.9)

### CIS 4.7.1-4.7.3: Seccomp, AppArmor, SELinux
**Severity:** MEDIUM

**What it detects:** Missing security policies (seccomp, AppArmor, SELinux)

**Remediation:** (See CIS 4.2.7, 4.2.8 above)

---

### CIS 4.8.1: Enforce read-only root filesystem
**Severity:** HIGH

**What it detects:** Writable root filesystem

**Remediation:** (See CIS 4.5.5)

---

### CIS 4.8.2: Restrict volume mounts
**Severity:** HIGH

**What it detects:** Use of sensitive volume types (hostPath, emptyDir, local)

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: config
      mountPath: /etc/config
    - name: cache
      mountPath: /tmp
  volumes:
  - name: config
    configMap:
      name: app-config
  - name: cache
    emptyDir:
      sizeLimit: 1Gi
  # Avoid:
  # - hostPath volumes
  # - local volumes
```

**Best Practices:**
- Use ConfigMap/Secret instead of hostPath
- Use emptyDir only for temporary data
- Avoid local storage volumes
- Use persistent volumes for data

---

### CIS 4.9.1: Container runtime security
**Severity:** HIGH

**What it detects:** Non-standard container runtimes

**Remediation:**
```yaml
# Use officially supported runtimes:
# - docker
# - containerd
# - CRI-O

apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  runtimeClassName: runc  # Use standard runtime
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Use official container runtimes
- Keep runtime updated
- Monitor runtime version compliance
- Disable experimental runtimes

---

### CIS 4.9.2: Container isolation enforcement
**Severity:** HIGH

**What it detects:** Low isolation level

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
```

**Best Practices:**
- Combine multiple security controls
- Use pod security standards
- Regular isolation testing
- Monitor violation events

---

### CIS 4.9.3: Kernel hardening enforcement
**Severity:** MEDIUM

**What it detects:** Missing kernel hardening

**Remediation:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
spec:
  securityContext:
    sysctls:
    - name: kernel.dmesg_restrict
      value: "1"
    - name: kernel.kptr_restrict
      value: "1"
    - name: kernel.yama.ptrace_scope
      value: "2"
  containers:
  - name: app
    image: myapp:latest
```

**Best Practices:**
- Apply kernel hardening sysctls
- Use safe defaults
- Monitor kernel security events
- Keep kernel updated

---

## General Remediation Strategy

### 1. Assessment Phase
- Run elf-owl against cluster
- Review all detected violations
- Categorize by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Create remediation timeline

### 2. Implementation Phase
- Start with CRITICAL violations
- Group by control type
- Use Pod Security Standards for enforcement
- Update deployment manifests

### 3. Validation Phase
- Test in non-production first
- Run elf-owl to verify fixes
- Review audit logs for compliance
- Document exceptions with justification

### 4. Enforcement Phase
- Deploy updated manifests to production
- Configure admission controllers
- Implement continuous monitoring
- Regular compliance reviews

---

## Automation with Pod Security Standards

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - configMap
    - emptyDir
    - projected
    - secret
    - downwardAPI
    - persistentVolumeClaim
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: "MustRunAsNonRoot"
  runAsGroup:
    rule: "MustRunAs"
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: "MustRunAs"
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
  seLinux:
    rule: "MustRunAs"
    seLinuxOptions:
      level: "s0:c123,c456"
```

---

## Monitoring & Enforcement

Use these tools to enforce compliance:

1. **Admission Controllers:**
   - Pod Security Standards
   - Custom webhooks
   - OPA/Gatekeeper

2. **Network Policies:**
   - Default-deny ingress/egress
   - Selective allow rules
   - Label-based selection

3. **RBAC:**
   - Least privilege
   - Service account isolation
   - Regular audits

4. **Monitoring:**
   - elf-owl continuous scanning
   - Audit log monitoring
   - Alert on violations

---

## References

- [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)


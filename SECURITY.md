# Security policy

Please do not disclose suspected vulnerabilities in a public issue.

Report them through this repository's private vulnerability reporting flow:

https://github.com/warpmetal/warpmetal-agent-runtime/security/advisories/new

Include the affected release, host operating system, expected impact, and a
minimal reproduction when possible. Do not include live credentials, private
keys, node tokens, or customer data.

Only the latest release receives security fixes during the V1 preview.

The root supervisor never exposes the Podman API outside the host. Container
lifecycle operations are delegated to a service running as the locked
`warpmetal-runtime` account. Its Unix socket is reachable only by that account
and root, and the service receives only its own cgroup subtree. Sandbox access
continues to use forced SSH commands and never grants access to this socket.

// collector/enricher.go
// Metadata enrichment from /proc, cgroups, and Kubernetes.
// Currently stubbed — production implementation will parse cgroup paths,
// extract container IDs, and query the kubelet API for pod metadata.
package main

// Future: move enrich() and ProcMeta from main.go here, add k8s client

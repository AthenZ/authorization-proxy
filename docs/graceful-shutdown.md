# Graceful shutdown

The sidecar server supports graceful shutdown.
To enable it, set `shutdownTimeout` and `shutdownDelay` to value > 0 in the `config.yaml`.

<!-- TOC -->

- [Graceful shutdown](#graceful-shutdown)
  - [Rolling update in K8s with graceful shutdown](#rolling-update-in-k8s-with-graceful-shutdown)
  - [Illustration of a normal graceful shutdown](#illustration-of-a-normal-graceful-shutdown)

<!-- /TOC -->

## Rolling update in K8s with graceful shutdown

1. make sure the `strategy` is set in the deployment
    - sample
    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    spec:
    strategy:
        rollingUpdate:
            maxSurge: 25%
            maxUnavailable: 25%
        type: RollingUpdate
    ```
1. make sure the `readinessProbe` for sidecar is set
    - sample
    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    spec:
        containers:
        -   name: sidecar
            readinessProbe:
                httpGet:
                    path: /healthz
                    port: 8081
                initialDelaySeconds: 3
                timeoutSeconds: 2
                successThreshold: 1
                failureThreshold: 2
                periodSeconds: 3
    ```
1. make sure the `config.yaml` has the correct value
    - `shutdownDelay = failureThreshold * periodSeconds + timeoutSeconds` (add 1s for buffer)
    - `0 < shutdownTimeout < terminationGracePeriodSeconds - shutdownDelay`
    - sample
    ```yaml
    version: "v2.0.0"
    server:
        shutdownTimeout: 10s
        shutdownDelay: 9s
        healthCheck:
            port: 8081
            endpoint: "/healthz"
    ```
1. make sure your application can still handle new requests after shutdown for `shutdownDelay` seconds

## Illustration of a normal graceful shutdown

```mermaid
---
displayMode: compact
---
gantt
    title normal graceful shutdown Illustration
    dateFormat  mm:ss.SSS
    axisFormat t=%S
    tickInterval 3second

    section ContainerStatus.ready
    ❌ false: 00:00.000, 3500ms
    ✅ true: 00:03.500, 3s
    ✅ true: 00:06.500, 3s
    ❌ false: 00:09.500, 3s
    ❌ false: 00:12.500, 3s
    ❌ ...: 00:15.500, 3s
    
    section K8s Prober
    initialDelaySeconds: 00:00.000, 3s
    1st Probe periodSeconds: 00:03.000, 3s
    1st Probe timeoutSeconds: 00:03.000, 2s
    2nd Probe periodSeconds: 00:06.000, 3s
    2nd Probe timeoutSeconds: 00:06.000, 2s
    3rd Probe periodSeconds: 00:09.000, 3s
    3rd Probe timeoutSeconds: 00:09.000, 2s
    4th Probe periodSeconds: 00:12.000, 3s
    4th Probe timeoutSeconds: 00:12.000, 2s
    ... Probe periodSeconds: 00:15.000, 3s
    ... Probe timeoutSeconds: 00:15.000, 2s
    
    section Sidecar Pod
    pod start, sidecar process start: milestone, 00:00.000, 30ms
    pod termination start, got SIGTERM, sidecar shutdown: milestone, 00:04.500, 30ms
    terminationGracePeriodSeconds... (default 30s): 00:04.500, 20s

    section Sidecar Proxy/API
    sidecar proxy/API start: milestone, 00:00.500, 30ms
    shutdownDelay: 00:04.500, 9s
    shutdown gracefully: milestone, 00:13.500, 30ms
    server close if NO alive connections: milestone, 00:16.500, 30ms
    shutdown forcefully: milestone, 00:23.500, 30ms
    shutdownTimeout: 00:13.500, 10s

    section Sidecar Health Check
    sidecar health check start: milestone, 00:01.000, 30ms
    server close: milestone, 00:04.500, 30ms
    ✅ 200 OK: 00:03.000, 500ms
    ❌ 1st Connection Refused: 00:06.000, 500ms
    ❌ 2nd Connection Refused: 00:09.000, 500ms
    ❌ 3rd Connection Refused: 00:12.000, 500ms
    ❌ ... Connection Refused: 00:15.000, 500ms

%% asumption
%% it takes 500ms for sidecar to response each health check probe
```

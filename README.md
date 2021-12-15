## Kyverno prometheus exporter

## Installation

```
 kubectl apply -f https://gitlab.com/rajdas98/kv-exporter/-/raw/master/k8s-manifest.yaml
```

### Import grafana dashbaord
Link- https://gitlab.com/rajdas98/kv-exporter/-/raw/master/grafana-dashboard.json

## Metrics Support
- Total count of violations
- Number of violations on audit mode
- Number of violations of blocked resources (enforce mode)
- Total count of successful policy application
- Number of audit policies

## Screenshot
![IMAGE ALT TEXT](screenshot.png)

# Flag Templates

These folders are static compose/file payload examples rather than Flow generator manifests. When turning one into a generator pack, place the derived manifest in `flag_generators/<name>/manifest.yaml` or `flag_node_generators/<name>/manifest.yaml` and use structured hints only:

```yaml
hint_levels:
  low:
    - "Target: {{NEXT_NODE_IP}}"
  medium:
    - "Service or artifact: {{OUTPUT.File(path)}}"
  high:
    - "Answer: {{OUTPUT.Flag(flag_id)}}"
```

Each level must contain at least one non-empty hint.

Do not add older single-hint fields to new manifests.

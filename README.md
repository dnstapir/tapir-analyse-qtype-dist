# Configuration example
```toml
debug = true
ignore_suffixes = ["looptest.dnstapir.se", "org"]
include_invalid_etlds = true
tag = "anomalous_qtype_distribution"
domain_min_total = 50
global_min_total = 200
analyze_every = 10
min_tvd = 0.4
alpha = 1e-13

[nats]
debug = true
url = "nats://nats:4222"
event_subject = "core-integration-test.events.new_qname"
private_subject_prefix = "core-integration-test.service.tapir-analyse-qtype-dist"
tag_subject_prefix = "core-integration-test.tags"

[nats.tag_bucket]
name = "tag_bucket"

[nats.private_bucket]
name = "private_tapir-analyse-qtype-dist"
create = true
ttl = 100000

[api]
active = false
```

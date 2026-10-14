# Configuration example
```toml
debug = true
interval = 120

# NATS configuration
[nats]
debug = true
url = "nats://localhost:4222"
event_subject = "internal.events.new_qname" # subscribe to new qnames
private_subject_prefix = "internal.service.tapir-analyse-qtype-dist"

# TODO: Configure a tag bucket

# Private bucket for qtype-dist
[nats.private_bucket]
name = "private_tapir-analyse-qtype-dist"
create = true
```

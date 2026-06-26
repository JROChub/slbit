# slbit Visualization Packet v1

Status: normative for slbit v0.1.x and compatibility-preserved in slbit v0.2.0.

The schema identifier is:

```text
slbit/viz-packet/v1
```

A packet contains:

- semantic claim identifier and logical bit width;
- optional RGB color, icon, and layer name;
- a SHA-256 commitment to the transcript seed;
- ordered human-readable transcript rounds;
- a digest for every opaque round payload;
- a transcript digest over the exported round projection;
- a packet digest over all packet fields except `packet_digest`.

Packet JSON is compact UTF-8 with deterministic field ordering and JSON string
escaping. Control characters are rejected from semantic input fields.

slbit v0.2.0 emits corrected deterministic v1 JSON. The v0.1.0 implementation
emitted a duplicate `component` key in the internal round projection used for
packet digesting. v0.2.0 verification accepts that legacy digest form so
existing v1 packets can still be checked, while new v1 packets use the
corrected projection.

## Trust Boundary

The packet is observation data. It MUST NOT be included in a Power House
`phx_fingerprint`, Rootprint branch ID, replay fingerprint, or proof-validity
decision.

The packet and transcript digests provide deterministic transport integrity.
They do not establish the soundness of an external proof.

## Limits

- claim identifier: 256 UTF-8 bytes;
- icon and layer/component labels: 128 UTF-8 bytes;
- note: 4,096 UTF-8 bytes;
- rounds: 1,000,000;
- opaque payload: 16 MiB per round.

Round numbers MUST increase strictly.

For new integrations, prefer [`packet_v2.md`](packet_v2.md).

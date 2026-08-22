# AegisGuard

**An empirical framework for assessing post-quantum readiness in public-facing TLS infrastructure.**

> *"Measure what you can prove. Never infer what you cannot observe."*

AegisGuard is a non-intrusive TLS/PQC measurement tool built around one constraint: a scanner that cannot observe the negotiated key-exchange group must say so, rather than reporting the absence of evidence as evidence of weakness.

---

## Why this exists

TLS 1.3 always negotiates a key exchange over some named group, but that group is not exposed by every client API — Python's `ssl` module reports the protocol version and cipher suite but *not* the negotiated group. Tools that fill the gap by inference produce confident and wrong answers:

| Inference | Why it's wrong |
|---|---|
| `TLS_AES_256_GCM_SHA384` → classical KEX | The cipher suite constrains the AEAD, not the key agreement |
| RSA-2048 certificate → classical KEX | Certificate algorithm and key exchange are independent |
| TLS 1.3 negotiated → post-quantum | TLS 1.3 is evidence of neither PQC nor classical |
| Group not observed → "not quantum-safe" | Absence of evidence, reported as a vulnerability |

That last row is the failure mode that matters. It inflates vulnerability counts in exactly the direction that makes a tool look valuable, and the result is unfalsifiable because the missing evidence is never surfaced.

AegisGuard resolves the group from an **independent measurement channel** (the OpenSSL CLI) and classifies it against a fixed table. Anything unobserved, unparsed, or unrecognised becomes `NOT_VERIFIED` — a first-class outcome carrying **zero risk penalty**.

---

## Classification

| Observed group | Class | Confidence |
|---|---|---|
| `X25519`, `X448`, `secp256r1`, `secp384r1`, `secp521r1`, `RSA` | `CLASSICAL` | HIGH |
| `X25519MLKEM768`, `SecP256r1MLKEM768` | `HYBRID_PQC` | HIGH |
| `MLKEM768`, `MLKEM1024` | `PQC` | HIGH |
| *absent / unrecognised* | `NOT_VERIFIED` | UNKNOWN |

No *harvest-now-decrypt-later* finding is emitted unless a classical group was **positively observed**.

---

## Study results

Two disjoint measurement campaigns, 2026-08-22, from a single vantage in India (OpenSSL 3.5.7, CPython 3.14):

| | Dataset A (banking) | Dataset B (10 sectors) |
|---|---|---|
| Targets | 100 | 300 |
| Reachable | 98 | 295 |
| TLS 1.3 | 81.6% | 88.8% |
| **Hybrid PQC** | **52.0%** | **63.4%** |
| Hybrid PQC (TLS 1.3 only) | 63.8% | 71.4% |
| `NOT_VERIFIED` | 48.0% | 36.6% |
| HSTS present | 50.0% | 58.0% |
| Expired certificates | 0 | 0 |

**Headline finding — a sectoral gap.** Banking/Financial trails all nine other sectors:

| Sector | Hybrid PQC (reachable) |
|---|---|
| Payments/FinTech | 85.3% |
| Media/Streaming | 73.3% |
| Browser Ecosystem | 73.3% |
| E-commerce | 68.9% |
| Enterprise/SaaS | 63.2% |
| Social Media | 61.8% |
| Search/Web Platforms | 55.0% |
| Cloud/Technology | 52.0% |
| Retail/Consumer | 50.0% |
| **Banking/Financial** | **46.9%** |

The gap replicates across two disjoint banking samples (52.0% and 46.9%) and survives conditioning on TLS 1.3, so it is not merely protocol lag.

Every positively verified group was `X25519MLKEM768`. No `SecP256r1MLKEM768` and no pure ML-KEM group was observed anywhere.

---

## Known limitations — read before reusing the data

These are disclosed in the paper and are not resolved in the released datasets.

**1. No classical group was resolved anywhere (393 reachable observations).**
Every TLS 1.3 session negotiates *some* group, and 104 TLS 1.3 sessions returned `NOT_VERIFIED` — so this is an instrument property, not a property of the Internet. The likely mechanism: OpenSSL 3.5 offers `X25519MLKEM768` first by default, producing a 1216-byte key share and a ClientHello spanning multiple TCP segments; stacks that assume a single-segment ClientHello reset the probe connection, while the smaller Python `ssl` ClientHello on the first channel succeeds. If so, `NOT_VERIFIED` is a *systematically biased* stratum, not random residue.

**Consequence: hybrid adoption figures are a lower bound, and classical adoption is unmeasured.** Fixing this requires persisting the probe's exit status per endpoint, retrying with `-groups X25519`, and cross-checking against a client that reports the group without a second connection.

**2. Certificate algorithm fields are placeholder constants.**
`pyOpenSSL`/`cryptography` are in `requirements.txt` but were absent from the environment during both runs, so `tls_probe.py` fell back to a hard-coded `RSA` / `2048` / `sha256WithRSAEncryption (estimated)`. Those columns are uniform across all 393 reachable records and carry no information. They are excluded from all

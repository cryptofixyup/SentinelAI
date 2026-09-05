# SentinelAI

Security-first medical AI infrastructure built around evidence-bounded deployment controls.

## Core Features

- **MedSigLIP V0 integration:** Medical image/text embedding architecture suitable for data-efficient classification, zero-shot classification, and semantic image retrieval; text generation is outside the intended model role.
- **Maximum Efficiency & Security Protocol (Sep 2026):** Ultra-PEFT design using rank-4 Q/V-only LoRA or 8-token prompt tuning, with frozen encoders and strict pre-embedding de-identification. Differential-privacy controls, attested-enclave inference, and encrypted vector storage are deployment-dependent or optional controls.
- **SecureFreshDiskANN:** Proposed optional persistent vector-storage layer for confidential embeddings, designed for encrypted storage and retrieval within an attested or air-gapped boundary.
- **Offline / air-gapped deployment:** Architecture supports deployments where external network access is unavailable or prohibited, subject to local availability of all required dependencies.
- **Validation-gated operation:** Performance, privacy-budget behavior, clinical utility, and deployment controls are treated as measurable validation requirements rather than assumptions.

## Security Protocol Status

The September 2026 protocol is an **engineering baseline**, not a claim of universal or independently certified security superiority.

The supplied assessment identifies several measurements that must remain validation-gated, including absolute VRAM usage, wall-clock training time, throughput, and clinical utility under rank-4 PEFT with the stated privacy budget.

Accordingly, this repository distinguishes:

- **Architecture:** controls and components defined by the design.
- **Benchmark:** measured performance under a named environment and configuration.
- **Audit:** independent assessment supported by an identifiable report and scope.
- **Clinical validation:** institution-specific evidence on the intended task and population.
- **Regulatory readiness:** documentation and controls mapped to the applicable pathway.
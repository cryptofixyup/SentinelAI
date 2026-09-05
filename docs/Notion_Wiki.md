# SentinelAI Product Wiki

## Maximum Efficiency & Maximum Security Protocol — September 2026 [Engineering Baseline v1.1]

This protocol defines a validation-gated engineering architecture for MedSigLIP-class medical vision-language encoders under stringent clinical, privacy, and security requirements.

### Model Boundary

MedSigLIP is treated here as an image/text embedding model for medical applications such as data-efficient classification, zero-shot classification, and semantic image retrieval. Text generation is outside the model role described by the underlying V0 documentation.

### 1. Parameter-Efficient Core

- Freeze the vision and text encoders.
- Inject LoRA adapters exclusively on query and value projections, with rank `r = 4` and `alpha = 8`, or use 8-token prompt tuning.
- Optional 4-bit base-model quantization with BF16 compute where the implementation and hardware support it.
- The design minimizes the trainable parameter surface; the exact trainable fraction must be calculated from the concrete model/adaptor configuration.

**Evidence boundary:** A small trainable fraction does not by itself prove negligible memorization or inversion risk. Those properties require empirical privacy/security evaluation.

### 2. Privacy & Federated Controls

- Mandatory pre-embedding de-identification covering the applicable HIPAA identifiers, GDPR requirements, and automated burned-in text/PHI detection.
- Client-level differential privacy may be applied to LoRA updates using a declared budget such as `epsilon <= 2.0`, `delta = 1e-5`, provided the complete accounting parameters are documented.
- Federated learning is restricted to PEFT deltas; raw patient data remains at the institution.
- Secure aggregation may combine cryptographic and confidential-compute controls, but each mechanism must be specified as part of a concrete protocol rather than treated as a guarantee by name alone.

### 3. Runtime & Deployment Envelope

- Inference and adaptation can be confined to an attested confidential-compute boundary with HSM-wrapped keys and encrypted vector storage.
- Offline and air-gapped deployment is supported at the architecture level where all required model, runtime, key-management, and update dependencies are available locally.
- Output minimization, rate limiting, timing controls, and other hardening measures should be evaluated against the specific threat model.

### 4. Secure Vector Storage — SecureFreshDiskANN

For deployments requiring persistent embeddings, SecureFreshDiskANN is the proposed encrypted persistent-memory vector-index layer.

The supplied assessment describes:

- encrypted persistent vector storage;
- storage-layer operation within an attested or air-gapped boundary;
- sealed keys, rate limiting, hard buffer rejection, and encrypted background snapshots;
- compatibility with confidential-compute runtimes;
- benchmark targets of `2,500+` sustained inserts/s and sub-millisecond range queries once indexed.

These performance figures are benchmark claims and require reproducible test evidence before being presented as production guarantees.

SecureFreshDiskANN is optional for purely ephemeral in-memory caches or environments that already provide an equivalent attested, hardware-encrypted vector store.

### 5. Validation & Change-Control Gates

Before clinical deployment, each institution must validate utility on its own local data distribution and intended clinical task.

The supplied assessment explicitly identifies absolute VRAM, wall-clock time, throughput, and clinical utility under rank-4 PEFT plus the stated privacy budget as requiring independent measurement or site-specific validation.

Any material change to PEFT rank, privacy budget, model quantization, enclave configuration, cryptographic protocol, retrieval policy, or output surface should trigger documented change-control and re-validation according to the institution's governance process.

### 6. Claims Policy

The repository uses the following evidence hierarchy:

**Implemented** → **Benchmarked** → **Independently Audited** → **Clinically Validated** → **Regulatory Readiness Evidence**

A claim must not be promoted to a stronger category without the corresponding artifact.

Examples:

- "Architecture supports offline inference" is an architectural statement.
- "18 ms/image on T4" is a benchmark statement only when the benchmark configuration is documented.
- "Independently audited" requires an identifiable audit scope and report.
- "Clinically validated" requires institution-specific validation evidence.
- "FDA-ready" or equivalent regulatory language requires applicability and documentation under the actual regulatory pathway.

### 7. Deployment Position

The September 2026 configuration is best described as a **security-first engineering baseline with validation gates**. It should not be described as the objectively maximum achievable security configuration, universally lossless, independently audited, or clinically production-ready unless those claims are supported by corresponding evidence.

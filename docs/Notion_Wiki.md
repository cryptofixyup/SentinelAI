# SentinelAI Product Wiki

## Maximum Efficiency & Maximum Security Protocol — September 2026 [Engineering Baseline v1.1]

This protocol defines a validation-gated engineering architecture for MedSigLIP-class medical vision-language encoders under stringent clinical, privacy, and security requirements.

### Model Boundary

MedSigLIP is treated here as an image/text embedding model for medical applications such as data-efficient classification, zero-shot classification, and semantic image retrieval. Text generation is outside the model role described by the underlying V0 documentation.

### 1. Parameter-Efficient Core

- Freeze the vision and text encoders.
- Inject LoRA adapters exclusively on query and value projections, with rank `r = 4` and `alpha = 8`, or use 8-token prompt tuning.
- Optional 4-bit base-model quantization with BF16 compute where the implementation and hardware support it.
- The design minimizes the trainable parameter surface; the exact trainable fraction must be calculated from the concrete model/adapter configuration.

**Evidence boundary:** A small trainable fraction does not by itself prove negligible memorization or inversion risk. Those properties require empirical privacy/security evaluation.

### 2. Privacy & Federated Controls

- Mandatory pre-embedding de-identification covering the applicable HIPAA identifiers, GDPR requirements, and automated burned-in text/PHI detection.
- Client-level differential privacy may be applied with a declared budget such as `epsilon <= 2.0`, `delta = 1e-5`, provided complete accounting parameters are documented.
- Federated learning is restricted to PEFT deltas; secure aggregation must be concretely specified.

### 3. Runtime & Deployment Controls

- Attested confidential-compute boundary for deployments that enable confidential inference.
- HSM-wrapped keys and encrypted vector storage for deployments that enable these controls.
- Offline / air-gapped operation is supported at the architecture level when all required dependencies are locally available.
- Hardening must be evaluated against the declared threat model.

### 4. SecureFreshDiskANN

SecureFreshDiskANN is a proposed optional persistent-memory vector-index layer for confidential embeddings. The supplied assessment describes encrypted storage, an attested or air-gapped boundary, sealed keys, rate limiting, hard buffer rejection, encrypted snapshots, and confidential-compute compatibility.

Performance targets such as `2,500+ inserts/s` and sub-ms range queries are benchmark claims and require reproducible evidence before being treated as production guarantees.

### 5. Validation & Change Control

- Validate local clinical utility on the intended task and population before clinical use.
- Independently measure VRAM, wall-clock training time, throughput, privacy behavior, and clinical utility under the concrete deployment configuration.
- Material changes to the model, PEFT configuration, privacy parameters, runtime boundary, or storage layer trigger revalidation.

### 6. Claims Policy

Use the following evidence hierarchy:

1. **Implemented** — present in the repository and executable.
2. **Benchmarked** — measured under a named environment and configuration.
3. **Independently Audited** — supported by an identifiable independent report and scope.
4. **Clinically Validated** — supported by institution-specific evidence on the intended task and population.
5. **Regulatory Readiness Evidence** — documentation and controls mapped to the applicable regulatory pathway.

### Deployment Position

SentinelAI is positioned here as a security-first engineering baseline with validation gates. It is not presented as objectively maximum achievable security, universally lossless, independently audited, or clinically production-ready without the corresponding evidence.

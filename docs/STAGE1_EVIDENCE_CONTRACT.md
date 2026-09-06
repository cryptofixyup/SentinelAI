# Stage 1 Evidence Construction Contract

Stage 1 is a deterministic evidence-construction boundary. It extracts and describes source evidence but does not determine whether that evidence constitutes a vulnerability.

## Boundary

Stage 0 manifest -> verify canonical payload and `manifest_sha256` -> verify commit/object bindings -> deterministic router -> AST extraction for `PRIMARY` and `DELETED` -> bounded evidence construction -> canonical Evidence Manifest -> `stage1_sha256`.

`SECONDARY`, `DEPENDENCY`, and `NON_CODE` records do not enter AST evidence construction.

## Authority

The exact Git object referenced by the verified Stage 0 record is authoritative. The working tree is an execution environment only. Evidence content is materialized from the immutable Git object after binding verification.

## Evidence identity

Evidence IDs are deterministic and assigned after canonical ordering by path, byte range, node type, and evidence type. Each evidence block binds to commit, Git object ID, SHA-256 content hash, and an exact byte range.

## Bounds

Evidence construction has explicit limits for block count, block size, referenced nodes, and total payload bytes. Exceeding a limit produces an explicit incomplete state; content is never silently truncated and treated as complete evidence.

## Security boundary

Structural labels such as `CALL`, `CONDITION`, `RETURN`, and `AUTHORIZATION_CHECK` describe extracted evidence. They are not vulnerability conclusions. Stage 2 is the first layer permitted to reason about claims supported by the evidence.

## Reproducibility

Identical Stage 0 input, Git objects, parser metadata, and Stage 1 ruleset must produce byte-identical evidence payloads and `stage1_sha256`. Parser or ruleset changes are expected to change the committed artifact.

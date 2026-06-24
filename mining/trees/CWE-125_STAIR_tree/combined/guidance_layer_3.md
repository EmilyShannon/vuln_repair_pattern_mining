# Layer 3 Guidance
*1 guidance items at depth 3*

## Item 1: Unvalidated length and structure fields in encoded inputs cause out-of-bounds access and resource exhaustion.

**Guidance:**
Apply layered validation of declared lengths, counts, and nesting before any parsing. Cross-verify sizes against actual data and configured ceilings, enforce container-element coherence, cap depth and aggregate size, and reject inconsistent, cyclic, or overlong structures to prevent out-of-bounds access and resource exhaustion.

*Covers 191 original steps*

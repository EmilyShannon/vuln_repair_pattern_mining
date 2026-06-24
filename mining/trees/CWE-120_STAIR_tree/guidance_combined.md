# Combined Guidance (All Layers)


---

# Layer 1 Guidance
*1 guidance items at depth 1*

## Item 1: Constrain untrusted data to validated, canonicalized, and strictly bounded operational ranges.

**Guidance:**
Canonicalize and strictly validate external input for length, type, and range; reject values exceeding limits or using malformed encodings. Limit copies, allocations, and iterations to validated bounds, explicitly terminate and clear buffers, and contextually encode outputs to their sinks to prevent injection from alternate encodings.

*Covers 9 original steps*

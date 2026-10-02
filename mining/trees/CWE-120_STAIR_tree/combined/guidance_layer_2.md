# Layer 2 Guidance
*1 guidance items at depth 2*

## Item 1: Insufficient bounds and capacity validation

**Summary:**
Insufficient validation of externally influenced sizes and indices lets string and buffer operations exceed allocated bounds, causing overflows, out-of-bounds access, and unterminated data. Miscalculated capacities during formatting or fallback behaviors exacerbate the risk.

**Guidance:**
Validate and constrain data-dependent sizes and indices before processing, compute required capacity from trusted limits, and ensure termination so all accesses remain within allocated memory.

*Covers 9 original patches*

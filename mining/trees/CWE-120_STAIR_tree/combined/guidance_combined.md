# Combined Guidance (All Layers)


---

# Layer 1 Guidance
*3 guidance items at depth 1*

## Item 1: Insufficient length and capacity validation

**Summary:**
String and buffer operations rely on unchecked sizes, including accessing a last character on empty strings and copying data without verifying capacity, while user-influenced precision values can inflate required space, resulting in out-of-bounds reads or writes.

**Guidance:**
Enforce size and bounds validation before any string or buffer access; constrain precision-driven sizes to safe limits; and ensure buffers have sufficient capacity before modification to keep all operations within verified boundaries.

*Covers 3 original patches*

## Item 2: Insufficient bounds checks on sizes and indices

**Summary:**
Insufficient validation of externally influenced lengths and indices allows operations to exceed buffer or array bounds. Out-of-range codes trigger unsafe memory resizing, and format-dependent parsing miscomputes required capacities, causing overflows or out-of-bounds access during string handling and data decoding.

**Guidance:**
Validate all input-driven sizes and indices before use, deriving acceptable capacities from the data format. Constrain string and buffer operations to verified limits, reject or truncate excess data, and fail safely when indices fall outside mapping ranges.

*Covers 3 original patches*

## Item 3: Buffer overflow via unchecked sizes and misallocation

**Summary:**
Missing bounds checks, size validation, and termination allow data operations to exceed buffer capacity, causing overflow and memory corruption. Underestimated allocations, including not accounting for fallback strings, further enable out-of-bounds writes and unterminated data.

**Guidance:**
Validate input lengths against buffer capacity, allocate for worst-case content including fallbacks, and restrict writes to verified limits. Always terminate resulting data and fail early when space is insufficient to avoid overflows and unterminated results.

*Covers 3 original patches*


---

# Layer 2 Guidance
*1 guidance items at depth 2*

## Item 1: Insufficient bounds and capacity validation

**Summary:**
Insufficient validation of externally influenced sizes and indices lets string and buffer operations exceed allocated bounds, causing overflows, out-of-bounds access, and unterminated data. Miscalculated capacities during formatting or fallback behaviors exacerbate the risk.

**Guidance:**
Validate and constrain data-dependent sizes and indices before processing, compute required capacity from trusted limits, and ensure termination so all accesses remain within allocated memory.

*Covers 9 original patches*

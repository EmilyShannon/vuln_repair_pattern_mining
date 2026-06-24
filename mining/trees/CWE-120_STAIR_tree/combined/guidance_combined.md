# Combined Guidance (All Layers)


---

# Layer 1 Guidance
*2 guidance items at depth 1*

## Item 1: Unvalidated length fields and undersized buffers allow overflow and memory corruption.

**Guidance:**
Validate declared sizes against buffer capacity, compute effective copy length as the minimum of available space and input size, and reject or truncate when limits are exceeded. Allocate buffers for worst-case input plus delimiters, detect size arithmetic overflow, and explicitly terminate written data to prevent overflow and unterminated states.

*Covers 4 original steps*

## Item 2: Missing length and range checks enable buffer overflows and out-of-bounds access.

**Guidance:**
Validate incoming length fields and code values against strict maximums before any access or copy, rejecting or truncating at safe limits, and ensure copied data is explicitly terminated. Allocate buffers for the largest accepted payload plus terminators, apply bounds-checked transfers to configuration data, and guard against integer overflow in size calculations.

*Covers 5 original steps*


---

# Layer 2 Guidance
*1 guidance items at depth 2*

## Item 1: Unvalidated size metadata from untrusted inputs enables out-of-bounds writes and memory corruption.

**Guidance:**
Perform strict length verification, cross-validate reported sizes with actual content and available storage, and cap operations to verified limits. Derive resource allocation from validated maxima, adopt fail-closed behavior, and reject malformed or inconsistent records to prevent unsafe access.

*Covers 9 original steps*

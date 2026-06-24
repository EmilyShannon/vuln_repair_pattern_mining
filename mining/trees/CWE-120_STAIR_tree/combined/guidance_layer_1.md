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

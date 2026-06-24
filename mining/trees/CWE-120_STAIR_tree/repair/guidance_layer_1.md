# Layer 1 Guidance
*3 guidance items at depth 1*

## Item 1: Validate lengths, restrict copies to capacity, and allocate for worst case with terminator.

**Guidance:**
Before any buffer operation, obtain destination capacity and validate input size, compute the permitted amount as the smaller of these after reserving space for a terminator, and restrict the transfer to that amount while explicitly terminating. Size allocations using the maximum possible input expansion and include headroom for delimiters and worst-case growth.

*Covers 3 original steps*

## Item 2: Harden input handling with capacity verification and guarded transfers to avert memory overruns.

**Guidance:**
Before indexing or copying, compare untrusted length fields with actual buffer capacity and clamp to safe limits; refuse malformed input and log errors. Perform copies and text access only within these verified bounds, guarantee explicit termination after truncation, and treat absent terminators or size mismatches as validation failures.

*Covers 4 original steps*

## Item 3: Enforce code bounds and resize buffers to accommodate maximal mapping size.

**Guidance:**
Pre-validate each code against an explicit upper bound before lookup or translation, rejecting out-of-range values. Expand storage to cover the longest accepted representation and halt processing when the calculated footprint would exceed that capacity.

*Covers 2 original steps*

# Combined Guidance (All Layers)


---

# Layer 1 Guidance
*2 guidance items at depth 1*

## Item 1: Unvalidated external input sizes against buffer capacity enable overflow and memory corruption.

**Guidance:**
Before any buffer operation, compare the provided length to the actual capacity and bound the operation to the smaller value. Allocate space for the worst-case expansion plus terminators, reject or safely truncate oversized input, and validate string length before indexing or concatenation to prevent out-of-bounds access.

*Covers 5 original steps*

## Item 2: Configuration field copying of externally supplied data lacks size enforcement, allowing overwrite of adjacent memory.

**Guidance:**
Measure incoming configuration lengths before transfer, compare against fixed capacity, and restrict copying to the validated limit with explicit termination; reject out-of-range codes and overlong records, or provision larger bounded storage to the documented maximum so accepted inputs cannot exceed capacity.

*Covers 4 original steps*


---

# Layer 2 Guidance
*1 guidance items at depth 2*

## Item 1: Missing size validation on external data copied into configuration fields causes overflow and memory corruption.

**Guidance:**
Apply strict boundary validation and enforce size limits on all externally sourced configuration data, rejecting or safely constraining excess. Centralize validation and propagate verified sizes through data handling to maintain consistent protections during processing, storage, and transmission.

*Covers 9 original steps*

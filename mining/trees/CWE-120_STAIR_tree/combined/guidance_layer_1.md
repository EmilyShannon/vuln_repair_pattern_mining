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

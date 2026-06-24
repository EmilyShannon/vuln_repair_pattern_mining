# Layer 2 Guidance
*3 guidance items at depth 2*

## Item 1: Unvalidated ASN.1/TLV length and string fields enable out-of-bounds access and memory corruption.

**Guidance:**
Validate every TLV/ASN.1 length against remaining input and strict size limits before allocating, copying, or advancing; prevent integer wrap when computing offsets, require constructed lengths to equal the sum of contained elements, bound recursion depth and cumulative size, and handle strings only within verified declared lengths and expected encodings, rejecting indefinite or inconsistent length forms.

*Covers 78 original steps*

## Item 2: Untrusted data drives miscomputed sizes and loops in decoders and deserializers, enabling overreads and overwrites.

**Guidance:**
Pre-calculate worst-case expansion and validate required output sizes against trusted bounds before allocating or copying, reject inputs whose decoded or declared lengths exceed remaining capacity, and fail on malformed padding or truncated segments. Constrain loop iterations to validated byte counts, detect arithmetic overflow, and stop when advancing offsets or counters would reach or pass buffer ends.

*Covers 76 original steps*

## Item 3: Failure to enforce container and element size coherence in untrusted inputs permits boundary violations.

**Guidance:**
Treat all embedded lengths as untrusted: maintain a remaining byte budget per container, validate each field’s size against that budget and maxima, and reject arithmetic overflow, inconsistencies, or nonmonotonic consumption. Cross-check nested structures for sum of parts no greater than container size, enforce recursion and iteration limits, and stop processing immediately on boundary violations rather than attempting recovery.

*Covers 37 original steps*

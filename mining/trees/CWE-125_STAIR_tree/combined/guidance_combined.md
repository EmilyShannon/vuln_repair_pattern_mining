# Combined Guidance (All Layers)


---

# Layer 1 Guidance
*5 guidance items at depth 1*

## Item 1: Unchecked ASN.1 length and string assumptions cause buffer over-reads and memory leaks.

**Guidance:**
Cross-check declared ASN.1 lengths with actual buffer availability, reject invalid encodings and unexpected types, and never assume strings are implicitly terminated by limiting interpretation to verified byte spans. Limit all parsing and printing to validated boundaries, and ensure allocations are paired with deallocation on every outcome, including error cases.

*Covers 38 original steps*

## Item 2: Insufficient TLV length validation during protocol parsing permits out of bounds reads and crashes.

**Guidance:**
Before handling any TLV or sub-object, ensure required header bytes are present, compare its declared length to the remaining input, detect integer wraparound when computing offsets, and abort parsing on mismatch. Advance the parsing position only by validated sizes, cap total and nested lengths to protocol maxima, and discard messages when limits are exceeded rather than reading past boundaries.

*Covers 40 original steps*

## Item 3: Insufficient bounds checks in base64 decoding and deserialization permit out-of-bounds reads.

**Guidance:**
Derive operation sizes from available buffer capacity, validate every claimed length and index against remaining bytes before advancing, and reject on any mismatch, padding irregularity, or trailing data. Clamp all accesses to verified bounds so decoders and parsers never read past produced output or expected delimiters.

*Covers 40 original steps*

## Item 4: Miscomputed lengths and invalid iteration limits trigger reads beyond valid data regions.

**Guidance:**
Treat all externally provided sizes and counts as untrusted and validate them against fixed upper limits and available storage. Detect overflow in size calculations, reject zero or nonsensical dimensions, and bound all iteration and copy operations to validated ranges to prevent index wraparound and out-of-bounds access.

*Covers 36 original steps*

## Item 5: Trust in attacker-controlled lengths and encodings enables out-of-bounds memory accesses on malformed inputs.

**Guidance:**
Derive permissible bounds from the actual buffer size, then verify every length, offset, index, and iteration count against those bounds before access; abort on mismatch or arithmetic overflow. Clamp reads to the validated region, recheck at each nested element, and strictly validate string encodings to reject invalid or truncated sequences, preventing cursor advancement beyond verified data.

*Covers 37 original steps*


---

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


---

# Layer 3 Guidance
*1 guidance items at depth 3*

## Item 1: Unvalidated length and structure fields in encoded inputs cause out-of-bounds access and resource exhaustion.

**Guidance:**
Apply layered validation of declared lengths, counts, and nesting before any parsing. Cross-verify sizes against actual data and configured ceilings, enforce container-element coherence, cap depth and aggregate size, and reject inconsistent, cyclic, or overlong structures to prevent out-of-bounds access and resource exhaustion.

*Covers 191 original steps*

# Layer 2 Guidance
*1 guidance items at depth 2*

## Item 1: Unvalidated size metadata from untrusted inputs enables out-of-bounds writes and memory corruption.

**Guidance:**
Perform strict length verification, cross-validate reported sizes with actual content and available storage, and cap operations to verified limits. Derive resource allocation from validated maxima, adopt fail-closed behavior, and reject malformed or inconsistent records to prevent unsafe access.

*Covers 9 original steps*

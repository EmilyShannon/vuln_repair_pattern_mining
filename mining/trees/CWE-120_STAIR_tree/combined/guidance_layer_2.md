# Layer 2 Guidance
*1 guidance items at depth 2*

## Item 1: Missing size validation on external data copied into configuration fields causes overflow and memory corruption.

**Guidance:**
Apply strict boundary validation and enforce size limits on all externally sourced configuration data, rejecting or safely constraining excess. Centralize validation and propagate verified sizes through data handling to maintain consistent protections during processing, storage, and transmission.

*Covers 9 original steps*

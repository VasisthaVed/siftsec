# Prioritization Rubric (P0–P4)

`siftsec` assigns every normalized finding a deterministic priority based on its shortest witness path in the reachability graph (`max_hops = 8` by default).

| Priority | Condition |
| :--- | :--- |
| **P0** | Finding's resource lies on a witness path reaching a sensitive `data_store` via **write** permission (`via_write_permission = true`). |
| **P1** | Finding's resource lies on a witness path reaching a sensitive `data_store` via **read-only** permission (`via_write_permission = false`). |
| **P2** | Finding's resource lies on a witness path, but does not reach a sensitive `data_store` within `max_hops`. |
| **P3** | Finding's resource is exposed at a boundary, with no witness path reaching any sensitive `data_store`. |
| **P4** | Finding's resource is absent from the graph (**reachability unknown**). Never inflated to P0. |

## Mitigations & Downgrades

Explicit mitigations (guardrails, IAM permissions boundaries, non-internet-exposed notebooks) downgrade `priority` by one level relative to `base_priority`. Every downgrade is recorded in `evidence.downgrades`; silent downgrades are prohibited.

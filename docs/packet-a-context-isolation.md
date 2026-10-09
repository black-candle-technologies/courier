# Packet A: context isolation

Implementation in progress; this document does not claim acceptance or release approval.

## Owner decision

D3 was approved by Riley through the authenticated parent conversation on 2026-10-09: v1 requires one relay security binding per principal. Distinct identities may use multiple hosts. The explicit question described separate identities for each relay and the user answered “Yes” (message `Sentinel_8cfbcc9261e081918aec9191ae9a3a64`). This approves implementation, not real credential creation, user-data migration, deployment, or merging.

D1 freshness, D2 visibility, D4 owner recovery, D5 history/leave policy, and D6 limits/CLI remain unresolved proposals. No team protocol or send behavior is enabled by this packet.

## Initial compatibility slice

`Context` captures a state root once. `LegacyContext` preserves the existing default directory without moving data or creating files. A zero or failed context is an error. Later slices bind each store and command to the selected context; this first slice alone does not establish isolation.

Base initially verified at `1e71d18f96e049b127ca48c55a012af7eeb06aa2`, tree `05c7301ac58a294f660a1252872fa2fb4dbf94dd`. Integrator fixes are pending; final verification must use the refreshed stack tip supplied by the parent.

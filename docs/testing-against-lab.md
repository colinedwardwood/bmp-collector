# Testing against a real BMP session

Every test in this repo decodes synthetic BMP messages constructed by the test itself —
never a real router. There's now a real target prepared (not yet live-validated) in
`colinedwardwood/network-o11y-demo`'s AWS-colocated k3s lab.

## What was added

SR Linux's BMP support couldn't be confirmed (only Nokia SR OS documentation was found —
a different product line from SR Linux, which is what this lab actually runs). Rather than
gamble on undocumented capability, a real FRR router (`bmp-monitor`) was added to the lab
topology instead — FRR's `bgpd` has genuine, long-standing BMP support, and needs no
vendor licensing.

- `bmp-monitor` (FRR) is eBGP-peered with `spine1` (AS104 ↔ AS201) over a new
  `ethernet-1/4` link — a real BGP session with a real RIB, not a synthetic one.
- `bmp-monitor` streams that session's RIB via BMP (`bmp targets` / `bmp connect`) to
  `bmp-collector.network-lab.svc.cluster.local:1790`.
- A `bmp-collector` Deployment+Service was added to the lab's k8s manifests
  (`k8s/telemetry/bmp-collector.yaml`), listening on that same port.

## What's NOT done yet — real gaps, not just caveats

- **No cluster access was available to actually validate any of this.** The vtysh BMP
  command syntax is written from documentation, not confirmed against a live FRR
  instance of the specific image version in use.
- **`bmp-collector` has no published container image.** `ci.yml` builds and tests but
  does not push to a registry — the k8s manifest's image reference is a placeholder
  that needs a real build-and-push step (or a locally-built image) before it can deploy.
- Whoever has cluster access should deploy this, confirm the BGP session actually
  establishes (`show bgp summary` on `bmp-monitor`), and confirm `bmp-collector`'s
  `/metrics` shows non-zero message counts before trusting this as a real test path.

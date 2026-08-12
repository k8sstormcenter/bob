# PUBLISHED DEMO KEYS — COMPROMISED BY DESIGN. DO NOT TRUST.

Every private key in this directory is committed to a public git repository.
Anyone on the internet has them. They exist so the demo and the component tests
are reproducible from a clean checkout, and for no other reason.

**Treat any signature made by these keys as unsigned.** They authenticate
nothing. A fragment or trust policy signed with them proves only that someone
read this directory.

| Key | Role in the demo |
|---|---|
| `root.pem` | Signs the trust policy. Its public half is compiled into the demo `node-agent` image as the root of trust. |
| `vendor.pem` | Profiles: signs the `base`-class learned profile. Rules: signs `overlay`-class bundle rules. |
| `operator.pem` | Profiles: signs `admission`- and `overlay`-class fragments. Rules: signs the `base`-class user baseline. |

## Never do this in a real cluster

- Do **not** run a real workload against a `node-agent` image that embeds
  `root.pem`'s public key. Any attacker can then sign a trust policy that names
  their own signing key, and the whole chain — policy, fragments, enforced
  profile — becomes attacker-controlled.
- Do **not** copy these keys into a production trust policy, values file, or
  Secret.
- Do **not** treat a green demo run as evidence that a real deployment is
  signed. It is evidence that the plumbing works.

## What a real deployment does instead

Generate your own keys, keep the private halves offline, and rebuild
`node-agent` with your own root public key — see "Bring your own root key" in
[`../demo.md`](../demo.md). The signing keys never touch the cluster: only
public-key fingerprints (in the trust policy) and the root public key (compiled
into the image) are deployed.

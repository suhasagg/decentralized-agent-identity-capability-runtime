# Production Architecture

Deploy a stateless verification PDP behind an authenticated gateway. Resolve identities from enterprise workload identity and/or DID infrastructure. Keep signing keys in KMS/HSM. Persist revocations and capability metadata in strongly controlled storage; distribute invalidations over an event stream. Enforce decisions in the gateway before tools are invoked.

For high-impact actions, bind an approval and capability to an exact canonical action hash and consume it atomically. Treat ambiguous execution outcomes as UNKNOWN and reconcile before retry.

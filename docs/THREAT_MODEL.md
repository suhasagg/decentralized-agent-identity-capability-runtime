# Threat Model

Trust no agent merely because it is authenticated. The verifier assumes compromised intermediaries, prompt injection, replay, confused-deputy behavior, stale identity state and scope-escalation attempts.

The authorization boundary is the cryptographically verified delegation chain plus local policy. Model text, retrieved memory and tool output are context, never authority.

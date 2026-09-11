# Changelog

## 0.2.1 — 2026-09-10

- HTTP event requests now have separate 100/minute allowances per recognized event type and effective Fastify IP. Invalid types share a single bounded bucket. Reads keep their existing general allowance.
- Query and JSON events use the same validation and bucket selection, including query precedence. Redis accounting remains 20 events/hour/type.
- Added six real Fastify HTTP integration tests with the rate-limit plugin enabled. Full suite: 55/55; typecheck and build passed.
- This does not change proxy trust or recover real visitor IPs. HTTP allowances are per process; existing proxy/IP and Redis availability limitations remain.

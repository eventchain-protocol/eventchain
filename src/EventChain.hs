-- | EventChain: zero-trust provenance protocol.
--
-- Umbrella module for the EventChain implementation. The protocol is an
-- append-only JSON-Lines file of hash-chained, identity-signed events
-- that verifies offline; see @docs/protocol.md@ for the protocol summary
-- and <https://eventchain.heliosapp.run/> for the full specification.
--
-- Implementation is pending design; this module intentionally exports
-- nothing yet.
module EventChain () where

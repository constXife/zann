-- One canonical device policy, including for existing roots. Missing/corrupt
-- policy is refused by the service rather than interpreted as a default.
INSERT INTO metadata (key, value) VALUES ('export_step_up_policy', 'any_configured_factor');

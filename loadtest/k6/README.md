# k6 loadtest scenarios

## Scenarios

- `scenarios/smoke.js`: basic health/system/vaults/items probe.
- `scenarios/sanity_lowload.js`: low load + optional VM metrics guardrails.
- `scenarios/morning_sync.js`: ramping load + optional VM monitor loop.
- `scenarios/baseline_normal.js`: mixed traffic (read/write/heavy).
- `scenarios/soak_leak.js`: constant VU soak for leak checks.
- `scenarios/signup_burst.js`: registration spike, optional first-session followup.
- `scenarios/signup_onboarding.js`: registration + first item creation.

## Profiles

Profiles are stage definitions loaded via `K6_PROFILE` or `K6_PROFILE_PATH`.

- `profiles/normal.json`
- `profiles/peak.json`
- `profiles/soak.json`
- `profiles/signup_peak.json`
- `profiles/low.json`
- `profiles/mid.json`
- `profiles/max.json`

## Common env vars

- `ZANN_BASE_URL` (default `http://desktop:8080`)
- `ZANN_ACCESS_TOKEN` (optional; enables write/heavy paths)
- `ZANN_SERVICE_ACCOUNT_TOKEN` (optional; read-only)
- `K6_PROFILE` (e.g. `low`, `mid`, `max`, `normal`, `peak`, `soak`, `signup_peak`)
- `K6_STAGES` (JSON stages override)
- `K6_PROFILE_PATH` (custom profile path)
- `ZANN_TEST_RUN_ID` (trace baggage)
- `K6_TRAFFIC_PROFILE` (e.g. `read_80_write_20`, `read_100`, `write_100`, `read_50_write_50`)

`K6_TRAFFIC_PROFILE` defaults to `read_80_write_20` and is not inferred from token presence.

## Scenario-specific env vars

- `K6_REGISTER_ENABLED=1` to enable registration in `baseline_normal.js`.
- `K6_EMAIL_DOMAIN` (default `loadtest.local`)
- `K6_SIGNUP_FOLLOWUP=0` to disable followup in `signup_burst.js`.
- `K6_FILE_SIZE_BYTES` (default `2048`)
- `K6_LEAK_VUS` (default `20`)
- `K6_LEAK_DURATION` (default `2h`)
- `VM_URL`, `CPU_QUERY`, `MEM_QUERY`, `ZANN_MONITOR_INTERVAL` (enable SUT monitoring across scenarios)
- `ZANN_MEM_LIMIT_BYTES`, `ZANN_CPU_LIMIT`

## Examples

```
K6_PROFILE=low k6 run loadtest/k6/scenarios/baseline_normal.js
K6_REGISTER_ENABLED=1 K6_PROFILE=low k6 run loadtest/k6/scenarios/baseline_normal.js
K6_TRAFFIC_PROFILE=read_100 K6_PROFILE=low k6 run loadtest/k6/scenarios/baseline_normal.js
K6_TRAFFIC_PROFILE=write_100 K6_PROFILE=mid k6 run loadtest/k6/scenarios/baseline_normal.js
K6_PROFILE=signup_peak k6 run loadtest/k6/scenarios/signup_burst.js
K6_PROFILE=signup_peak k6 run loadtest/k6/scenarios/signup_onboarding.js
K6_PROFILE=soak k6 run loadtest/k6/scenarios/soak_leak.js
```

## Runner

Use `runner.js` to select a scenario via `K6_SCENARIO`:

```
K6_SCENARIO=baseline_normal K6_PROFILE=low k6 run loadtest/k6/runner.js
K6_SCENARIO=signup_burst K6_PROFILE=signup_peak k6 run loadtest/k6/runner.js
K6_SCENARIO=signup_onboarding K6_PROFILE=signup_peak k6 run loadtest/k6/runner.js
K6_SCENARIO=soak_leak K6_PROFILE=soak k6 run loadtest/k6/runner.js
```

## Env loading helper

Use `loadtest/run_k6.sh` to auto-load `loadtest/.env.k6`:

```
K6_SCENARIO=baseline_normal K6_PROFILE=low ./loadtest/run_k6.sh run loadtest/k6/runner.js
```

`run_k6.sh` defaults `K6_PROFILE=low` if it is not provided.

## Scenario helper (reset + server)

Use `loadtest/run_scenario.sh` to reset the DB, ensure the loadtest server is up,
and inject the service-account token before running k6:

```
K6_SCENARIO=baseline_normal K6_PROFILE=low ./loadtest/run_scenario.sh run loadtest/k6/runner.js
K6_SCENARIO=signup_burst K6_PROFILE=signup_peak ./loadtest/run_scenario.sh run loadtest/k6/runner.js
```

`run_scenario.sh` will also auto-login with the admin user and set
`ZANN_ACCESS_TOKEN` if it is not provided (defaults to
`ZANN_ADMIN_EMAIL=loadtest.admin@local.test` and
`ZANN_ADMIN_PASSWORD=Loadtest123!`).

## Universal helper

Use `loadtest/run_loadtest.sh` to run a scenario without specifying k6 args:

```
K6_SCENARIO=baseline_normal K6_PROFILE=low ./loadtest/run_loadtest.sh
K6_SCENARIO=signup_burst K6_PROFILE=signup_peak ./loadtest/run_loadtest.sh
```

`run_loadtest.sh` defaults `K6_PROFILE=low` if it is not provided.

import baselineScenario, {
  options as baselineOptions,
  monitor as baselineMonitor,
  runBaseline as baselineRunBaseline,
  setup as baselineSetup,
} from "./scenarios/baseline_normal.js";
import signupBurstScenario, {
  monitor as signupBurstMonitor,
  options as signupBurstOptions,
} from "./scenarios/signup_burst.js";
import signupOnboardingScenario, {
  monitor as signupOnboardingMonitor,
  options as signupOnboardingOptions,
} from "./scenarios/signup_onboarding.js";
import smokeScenario, {
  monitor as smokeMonitor,
  options as smokeOptions,
  setup as smokeSetup,
} from "./scenarios/smoke.js";
import sanityScenario, { options as sanityOptions, setup as sanitySetup } from "./scenarios/sanity_lowload.js";
import morningScenario, {
  options as morningOptions,
  setup as morningSetup,
  monitor as morningMonitor,
  load as morningLoad,
} from "./scenarios/morning_sync.js";
import leakScenario, {
  monitor as leakMonitor,
  options as leakOptions,
  setup as leakSetup,
  leak as leakExec,
} from "./scenarios/soak_leak.js";

const SCENARIO = __ENV.K6_SCENARIO || "baseline_normal";

const registry = {
  baseline_normal: {
    options: baselineOptions,
    default: baselineScenario,
    monitor: baselineMonitor,
    runBaseline: baselineRunBaseline,
  },
  signup_burst: {
    options: signupBurstOptions,
    default: signupBurstScenario,
    monitor: signupBurstMonitor,
  },
  signup_onboarding: {
    options: signupOnboardingOptions,
    default: signupOnboardingScenario,
    monitor: signupOnboardingMonitor,
  },
  smoke: {
    options: smokeOptions,
    default: smokeScenario,
    setup: smokeSetup,
    monitor: smokeMonitor,
  },
  sanity_lowload: {
    options: sanityOptions,
    default: sanityScenario,
    setup: sanitySetup,
  },
  morning_sync: {
    options: morningOptions,
    default: morningScenario,
    setup: morningSetup,
    monitor: morningMonitor,
    load: morningLoad,
  },
  soak_leak: {
    options: leakOptions,
    default: leakScenario,
    setup: leakSetup,
    leak: leakExec,
    monitor: leakMonitor,
  },
};

const selected = registry[SCENARIO];
if (!selected) {
  console.warn(`Unknown K6_SCENARIO: ${SCENARIO}`);
}

export const options = selected?.options || baselineOptions;
export function setup() {
  if (selected?.setup) {
    return selected.setup();
  }
  if (baselineSetup) {
    return baselineSetup();
  }
  return {};
}
export const monitor = selected?.monitor;
export const load = selected?.load;
export const leak = selected?.leak;
export const runBaseline = selected?.runBaseline || baselineRunBaseline;

export default function (data) {
  if (!selected) {
    return baselineScenario(data);
  }
  if (selected.default) {
    return selected.default(data);
  }
  return baselineScenario(data);
}

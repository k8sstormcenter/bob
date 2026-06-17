// Canonical noise-model profiles for the demo loadgens (k6).
//
// Lets you pick the SHAPE of the benign background traffic WITHOUT touching the
// app-specific request logic in each chain's loadgen. Selected per-deployment
// via the PROFILE env var (k6 exposes it as __ENV.PROFILE); default 'realistic'.
//
// This file is the reference implementation. A compact copy of scenarios()/
// think() is INLINED into each k6 loadgen's script.js (keeps each loadgen a
// single self-contained ConfigMap key). Edit this first, then update the
// inlined copies (see example/noise-profiles/README.md).
//
// Profiles:
//   realistic - organic peaks/valleys + exponential think-time (lifelike; default).
//   flat      - constant VUs + constant think-time: a deterministic, low-variance
//               baseline. Any anomaly stands out trivially -> control / worst case
//               for "how much does baseline noise help the attacker hide?".
//   bursty    - low base punctuated by sharp short spikes + heavy-tailed think-time
//               (clusters of activity then quiet): high-variance baseline.
//   diurnal   - slow day/night cycle (long quiet -> busy -> quiet) + exponential
//               think: tests detectors/tuners against a slowly drifting baseline.
import { sleep } from 'k6';

const R = (x) => Math.max(1, Math.round(x));

// Build the k6 `scenarios` object for a profile. `peak` is the chain's busy-hour
// VU target (react~14, dapr~18, log4j~14); other levels derive from it.
export function scenarios(profile, peak) {
  peak = peak || 12;
  const base = Math.max(2, R(peak * 0.3));
  let s;
  switch (profile) {
    case 'flat':
      s = { executor: 'constant-vus', vus: R(peak * 0.5), duration: '30m' };
      break;
    case 'bursty':
      s = { executor: 'ramping-vus', startVUs: base, gracefulRampDown: '5s', stages: [
        { duration: '2m',  target: base },
        { duration: '15s', target: R(peak * 1.8) },
        { duration: '20s', target: base },
        { duration: '3m',  target: base },
        { duration: '15s', target: R(peak * 2) },
        { duration: '25s', target: 1 },
        { duration: '2m',  target: base },
        { duration: '15s', target: R(peak * 1.8) },
        { duration: '40s', target: base },
        { duration: '4m',  target: base },
        { duration: '15s', target: R(peak * 2) },
        { duration: '20s', target: base },
      ] };
      break;
    case 'diurnal':
      s = { executor: 'ramping-vus', startVUs: 1, gracefulRampDown: '20s', stages: [
        { duration: '7m', target: peak },   // morning ramp
        { duration: '5m', target: peak },   // midday plateau
        { duration: '7m', target: 1 },      // evening wind-down
        { duration: '3m', target: 1 },      // night quiet
        { duration: '6m', target: peak },   // next day
        { duration: '4m', target: 1 },
      ] };
      break;
    case 'realistic':
    default:
      s = { executor: 'ramping-vus', startVUs: base, gracefulRampDown: '15s', stages: [
        { duration: '3m', target: R(peak * 0.6) },
        { duration: '5m', target: peak },
        { duration: '4m', target: R(peak * 0.3) },
        { duration: '5m', target: R(peak * 0.85) },
        { duration: '3m', target: 1 },
        { duration: '6m', target: R(peak * 0.7) },
      ] };
  }
  return { noise: s };
}

// Returns a think(meanSeconds) function whose distribution matches the profile.
export function thinker(profile) {
  switch (profile) {
    case 'flat':
      return (m) => sleep(m);                                              // deterministic
    case 'bursty':
      return (m) => { const r = Math.random();
        sleep(r < 0.15 ? Math.min(60, m * 6 * Math.random())              // occasional long idle
                       : Math.max(0.05, m * 0.25 * Math.random())); };    // mostly rapid -> clusters
    case 'diurnal':
    case 'realistic':
    default:
      return (m) => sleep(Math.min(30, -Math.log(1 - Math.random()) * m)); // exponential, heavy-tailed
  }
}

# IKT-Linz demo recording runbook

The split-screen demo video: RanUI (the disease path) on the left 960px, Pixie/dx
(the detection) on the right 960px, hstacked to 1920x1080 by `compose-split.sh`.

Two operators, one clock:

- **metal-bob** drives the browser and records. Owns everything in *Recording side*.
- **edge4** owns the cluster and fires the chain. Owns everything in *Fire side*.

This is run repeatedly. Follow it literally; the traps at the end are all things
that already cost us a take.

---

## The protocol

Panels are **pre-opened and rolling before the fire**, never opened afterwards. A
cold panel costs ~57s to render, ~45s of which is spinners — open it after the
fire and the first minute of the chain is lost.

Capture is **step-locked per detection**, not per chain step. Of the 20 steps only
7 bear detections; the rest are plumbing and are fired straight through.

Per detection:

| # | who | action |
|---|-----|--------|
| 1 | metal-bob | panel pre-opened, rendered, screencast rolling |
| 2 | edge4 | T-2min heads-up over the bridge |
| 3 | metal-bob | **ack**: panels confirmed rendered and rolling |
| 4 | edge4 | announce **T-0 in UTC**, fire exactly one step (`demo_chain --only N`) |
| 5 | metal-bob | capture the event landing live, **ack** with what was seen |
| 6 | edge4 | pull verified ids from ClickHouse, send them |
| 7 | metal-bob | open the post-fire per-trace deeplink, capture, **ack** |
| 8 | edge4 | advance to the next detection |

The cluster is **held between detections**. Silence from metal-bob means *not
seen* — edge4 holds. Never infer consent from silence in either direction.

### The 7 pause points

| step | detection | panels |
|------|-----------|--------|
| 3  | worker-callback | shadow_trace(worker) + fullchain — socat :1337, no dx_order |
| 5  | sa-token-read | evidence_graph(order) + shadow_trace(worker) |
| 10 | nmap-sweep | evidence_graph(order) + fullchain — conn_stats blank, note it on camera |
| 13 | redis-rce | evidence_graph(order) + shadow_trace(redis) |
| 17 | cve-2026-47701-extract | evidence_graph(orchestrator order) + breakout |
| 19 | privileged-pod | evidence_graph + shadow_trace(ran-privileged, R1017) |
| 20 | host-escape + k3s-cred | evidence_graph + fullchain — host-escape C blank (entlein/dx#171); k3s-cred rows are host-attributed, pod='' |

Plumbing (1, 2, 4, 6-9, 11, 12, 15, 16, 18) is fired through without pausing.

### Panel classes

- **Pre-open, keep rolling all run**: `dx/fullchain`, `dx/breakout` (both accumulate
  the chain — capture incremental growth at each detection), `dx/shadow_trace`
  (SHADOWS list), `px/cluster` (topology bed, nice-to-have).
- **Post-fire only**, because they need an id the chain has not produced yet: the
  per-trace shadow deeplink (`shadow_id`) and `dx/evidence_graph`
  (`order_id` + `case_id`).

---

## Recording side (metal-bob)

### Prerequisites

There is exactly **one** puppeteer install on the machine. Do not `npm install`
anywhere else.

```
NODE_PATH=/mnt/dev-data/tmp/iktlinz/node_modules      # puppeteer-core 24.43.1
CHROME_BIN=/home/tanzee/.cache/puppeteer/chrome/linux-148.0.7778.97/chrome-linux64/chrome
ffmpeg=/home/tanzee/.local/bin/ffmpeg
```

### Login

Self-hosted Pixie at `work.soc.k8sstormcenter.com`, identity via Auth0
(`stormcenter.eu.auth0.com`). Scripted email+password; **no persisted profile** —
the session cookie does not survive the browser exiting, so every run logs in.

The Auth0 form re-renders after the email is entered, so `page.type('#password')`
can fire at a stale node and the keystrokes land in the still-focused username
field — typing the password in cleartext and submitting it as the username. Each
field is therefore waited for, clicked, typed, and **verified** before submit.
Credentials come from the environment, never from a file in the repo.

### Finding a panel

Views are reached by URL, never by clicking. Valid scripts on this tenant:
`dx/shadow_trace`, `dx/fullchain`, `dx/breakout`, `dx/evidence_graph`,
`px/cluster`. (`dx/kubescape_mitre`, `dx_kubescape_mitre` and `dx/alerts` do NOT
exist — they return "Script name invalid".)

```
https://work.soc.k8sstormcenter.com/live/clusters/<cluster>?script=dx%2Fshadow_trace
```

A per-trace deeplink is an ordinary anchor whose href carries the parameters:

```
/live/clusters/<cluster>?script=dx%2Fshadow_trace&shadow_id=<hex>&container=<name>&start_time=-6h&clickhouse_dsn=…
```

So traces are reached by **navigation**. Harvest them with
`a[href*=shadow_id]` and match on the `container` param — never on the `jss*`
class names, which are regenerated per build.

With `--keep-ch` the pre-teardown shadows remain in ClickHouse, so disambiguate
fresh from stale by `OPENED` / `LAST_SEEN` against the fire window, not by
container alone.

### Render-complete

An empty panel with a spinner is **perfectly stable text**, so "wait until the DOM
stops changing" returns immediately and everything downstream acts on nothing.
Require all three: zero progress indicators, content past the header baseline, and
6s of quiet. Budget 10 minutes.

Measured on a full ClickHouse: 69 spinners and 343 chars of DOM for ~45s, then
everything at once — 57-61s consistently.

### Screencast

Headless, `defaultViewport` 960x1080. **Headful renders 878x911** (the window
manager takes its cut), which breaks `compose-split.sh`'s no-rescale hstack.

Chrome must be started with throttling disabled or a backgrounded headless page
records one frozen frame:

```
--disable-background-timer-throttling --disable-backgrounding-occluded-windows
--disable-renderer-backgrounding --disable-features=CalculateNativeWinOcclusion
--force-device-scale-factor=1 --window-size=960,1080
```

`page.screencast({ fps: 10 })`, continuous.

**Launch the recorder detached** (`setsid`/`nohup`, writing to a log), never as a
child of an interactive session. The screencast container is only finalised by a
clean `recorder.stop()`; if the parent dies the file is left **0 bytes** and the
whole take is lost with nothing to salvage. Stop it by sending SIGTERM to the
recorded PID, which the recorder traps to close each screencast in turn. Do **not** settle-wait on the right
panel during a fire: the detection feed accumulates and never settles, so a
settle-wait parks the recording on an early frame. Nudge the mouse periodically so
Chrome keeps emitting frames on an otherwise idle page.

### Scrolling

Pixie is a fixed-height flex app: `window.scrollBy()` does nothing, an inner div
owns the overflow. Pick the scroller **at runtime**:

1. candidates = elements with `scrollHeight - clientHeight >= 40`, `clientHeight >= 200`,
   **and** computed `overflow-y` in {auto, scroll, overlay};
2. rank by `clientHeight` — the most viewport-like is the outer pane;
3. step `0.85 × clientHeight` until `scrollTop` stops changing.

Verify by hashing each frame and counting distinct ones. On the trace view: 46
candidates, `jss5` (ch 1016 / sh 8122), bottom in 9 steps, 10 frames / 10 distinct,
footer visible.

### Accept-a-take gate

Reject and re-shoot unless all hold:

- distinct frame hashes > 1 (the pane actually moved / the feed actually changed);
- the expected detection is visible in the panel, not merely present in ClickHouse;
- output is exactly 960x1080;
- no login form, no spinner, no "Script name invalid" in any frame.

### Compose

`./compose-split.sh [left.webm] [right.webm] [out.mp4]` — pure hstack to 1920x1080,
shorter panel padded with `tpad` clone. The left recorder owns the clock; start the
right recorder a few seconds earlier and stop it a few seconds later.

---

## Fire side (edge4)

*Authored by edge4; committed here by metal-bob because the branch requires signed commits.*

### 0. Preconditions

- dx capture policy = `adaptive_base` (shipped). The video needs full dark tables
  for a rich shadow_trace. Confirm via the `DX_CAPTURE_POLICY` env on
  `kubectl -n honey get ds dx-daemon`. `static` is measurement-only, **never** for video.
- Clean slate: `bash /home/ubuntu/iktlinz-reset.sh --keep-ch`, run **standalone** —
  never chained, or the pattern match kills the invoking shell (exit 144).
  `--keep-ch` preserves the `dx_kpi_proof` scores and the profile mirror; a full
  truncate would wipe build-agent's scores and never re-emit `profile_compare`.
  Expect a final line `CLEAN, iktlinz-ns=0 rogueartifacts=0`.
- Known residue after `--keep-ch`: stale OPEN rogue shadows from prior runs remain
  in the shadow_trace list. Harmless, because capture navigates by `shadow_id`
  rather than by the list. Separate them by `t0` / `updated_at >= ` this run's start.

### 1. Deploy bound, no fire

```
bash run-iktlinz-e2e.sh --benign-only --pre 5 --post 0 --out results/vidcap
```

Born-bound orchestrator (label stamped into the pod template before apply),
oopservability (redis / spog / target-allocator), 6 SBoBs. Prints
`benign-only run: no disease fired`. The benign twin stops when the runner exits,
so there is no worker churn during capture.

Confirm healthy and bound: orchestrator `Running 2/2`, and **no** open rogue shadow
for any live pod (`dx_shadow_trace` with `closed_at=0` for the current pod hashes —
empty means all bound; a hit means binding failed, re-check the SBoBs).
`agent-worker` and `ran-privileged` are *meant* to be rogue; they get no SBoB.

> Use the `--benign-only` **flag**. The env-var form `BENIGN_ONLY=1 bash …` is
> silently overridden by line 21 and fires the disease. See Traps 8.

### 2. Step-lock fire

```
RAN_URL=http://localhost:8080 python3 demo_chain.py --only N
```

One step, **no `--reset`** (the deploy already reset the campaign). Steps are
stateful — `exec_sys` pins to the step-2 worker foothold — so fire them in order.
Plumbing fired through without pausing: 1, 2, 4, 6, 7, 8, 9, 11, 12, 15, 16, 18.
Pause and capture at: 3, 5, 10, 13, 17, 19, 20.

### 3. Signalling (per detection, UTC)

T-2min heads-up → metal-bob's panels-rolling ack → fire the step and announce T-0
(`date -u +%H:%M:%SZ`) → metal-bob's capture ack → window bounds + verified ids →
metal-bob's post-fire deeplink capture → advance ack. Cluster held between
detections; metal-bob's silence means *not seen*, so hold.

### 4. ClickHouse id extraction

Verified, never invented. `T0` = the fire instant.

```sql
-- shadow_id: pick the row with t0 >= T0 (separates the attack worker from benign/stale)
SELECT shadow_id, pod, container, t0, last_epoch, rogue_state
FROM forensic_db.dx_shadow_trace
WHERE pod LIKE 'agent-worker%' AND updated_at >= toDateTime('<T0>','UTC')
ORDER BY updated_at DESC;
-- t0 = OPENED, last_epoch = LAST_SEEN

-- order_id + case_id; culprit_key = ns/pod/pid = case_id; event_time is UInt64 NANOS
SELECT order_id, culprit_key
FROM forensic_db.dx_orders
WHERE event_time BETWEEN <T0_ns> AND <now_ns>;
```

### 5. Deeplink forms

Loadable scripts only.

```
shadow_trace:    /live/clusters/edge4_79f499d2?script=dx%2Fshadow_trace&container=<c>&shadow_id=<hex>&start_time=-30m
evidence_graph:  /live/clusters/edge4_79f499d2?script=dx%2Fevidence_graph&order_id=<hex>&case_id=<ns/pod/pid urlencoded>&start_time=-30m
```

Omit `clickhouse_dsn` on evidence_graph — the vis defaults it.
`process_forest`, `conn_stats` and `redis_events` are ClickHouse **tables**, not
confirmed loadable scripts; keep them out of deeplinks until they are shown to resolve.

### 6. End of run

dx stays `adaptive_base`. Leave the fired chain up until every post-fire deeplink
is confirmed captured, **then** reset with `--keep-ch`. Repeat per fix.

---

## Traps

Each of these produced a confident false success before it was understood.

1. **Settling on text alone.** An empty spinner panel is stable text. Everything
   downstream then operates on an empty page.
2. **Picking the scroller by hidden content.** Ranking by `scrollHeight - clientHeight`
   selects an inner widget (`clientHeight` ~385) and scrolls it off-screen: the
   numbers report `atBottom: true` while the rendered frame never moves.
3. **`overflow: hidden` containers.** They report `scrollHeight > clientHeight` and
   silently ignore `scrollTop`. Filter on computed overflow.
4. **Headful sizing.** 878x911, not 960x1080.
5. **Auth0 field collision.** See *Login*.
6. **Recording a static-policy run.** A chain fired under the static arm has no
   worker shadow at all (0 rows in `dx_shadow_trace`, `dc_snoop`, `stack_trace`,
   `conn_stats`). Confirm the policy arm before the fire, not after.
9. **A killed recorder leaves a 0-byte video.** The screencast is finalised on
   clean stop only. A recorder run as a session-scoped background job dies with the
   session and takes the entire take with it — the warm PNGs survive, the video does
   not. Run it detached and stop it deliberately.
8. **`BENIGN_ONLY=1` as an environment variable does nothing.** Line 21 of
   `run-iktlinz-e2e.sh` assigns `BENIGN_ONLY=0` unconditionally, so the env form is
   overridden and the disease fires during what was meant to be a benign deploy.
   Use the `--benign-only` flag.
7. **A panel can scroll perfectly and be empty.** The k3s-1 controller shadow
   renders FOREST as "Showing 1 records" over a blank grid. Check content, not
   just mechanics.

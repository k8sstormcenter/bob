// record.cjs — screencast RanUI while demo_chain.py drives the scripted demo.
//
// Two things make a naive screencast record one frozen frame:
//   1. headless Chrome throttles timers/rendering for backgrounded pages, so the
//      canvas graph never repaints -> identical frames.
//   2. reloading with 'domcontentloaded' snaps back before the canvas paints.
// So: disable throttling, and after each refresh wait for the canvas pixels to
// settle before letting the recorder sit on that state.
//
//   CHROME_BIN=... node record.cjs [out.webm]        (full 20-step run)
//   CHAIN_ARGS="--from 1 --to 2" node record.cjs x.webm   (short take)
const puppeteer = require('puppeteer-core');
const { spawn } = require('child_process');
const path = require('path');
const { setupLayout } = require('./layout.cjs');

const HERE = __dirname;
const OUT = process.argv[2] || path.join(HERE, 'iktlinz-demo.webm');
process.env.PATH = `${HERE}/bin:${process.env.PATH}`;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function canvasSig(page) {
  return page.evaluate(() => {
    const cs = Array.from(document.querySelectorAll('canvas'));
    if (!cs.length) return 'nocanvas';
    const c = cs.sort((a, b) => b.width * b.height - a.width * a.height)[0];
    try { const d = c.toDataURL('image/png'); return d.length + ':' + d.slice(-96); }
    catch (e) { return 'tainted'; }
  });
}

async function settle(page, maxMs = 15000) {
  const t0 = Date.now(); let last = null, stable = 0;
  while (Date.now() - t0 < maxMs) {
    const s = await canvasSig(page);
    if (s === last) { if (++stable >= 2) return; } else { stable = 0; last = s; }
    await sleep(600);
  }
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN, headless: 'new',
    args: [
      '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage',
      '--window-size=960,1080',
      // keep painting while headless/backgrounded — without these the screencast
      // records one frozen frame
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-features=CalculateNativeWinOcclusion',
      '--force-device-scale-factor=1',
    ],
    userDataDir: `${HERE}/chrome-rec`,
    defaultViewport: { width: 960, height: 1080 },
  });
  const page = await browser.newPage();
  await page.bringToFront();
  await page.goto('http://localhost:8080/', { waitUntil: 'networkidle2', timeout: 60000 });
  await settle(page);
  await setupLayout(page);   // collapse armory, enlarge timeline, zoom graph

  // Window is already sized to the LEFT HALF of the 1920x1080 laptop screen
  // (960x1080), so we capture the whole window natively: no crop (nothing of the
  // UI is lost) and no downscale (text stays crisp).
  const recorder = await page.screencast({ path: OUT, fps: 10 });
  console.log('recording ->', OUT);

  let alive = true;
  // Refresh loop: reload, wait for the canvas to actually paint, nudge the page
  // so Chrome keeps issuing frames.
  (async () => {
    while (alive) {
      await sleep(8000);
      if (!alive) break;
      try {
        await page.reload({ waitUntil: 'networkidle2', timeout: 30000 });
        await settle(page);
        await setupLayout(page);
        await page.mouse.move(600 + Math.random() * 40, 400 + Math.random() * 40);
      } catch (e) { /* keep recording regardless */ }
    }
  })();

  const args = process.env.CHAIN_ARGS ? process.env.CHAIN_ARGS.split(' ') : ['--from', '1', '--to', '20'];
  const child = spawn('python3', [path.join(HERE, 'demo_chain.py'), ...args],
                      { cwd: HERE, env: { ...process.env } });
  child.stdout.on('data', d => process.stdout.write(d));
  child.stderr.on('data', d => process.stderr.write(d));

  const code = await new Promise(res => child.on('close', res));
  console.log('chain exited with', code);

  alive = false;
  try { await page.reload({ waitUntil: 'networkidle2', timeout: 30000 }); await settle(page); await setupLayout(page); } catch (e) {}
  await sleep(4000);
  await recorder.stop();
  await browser.close();
  console.log('video written ->', OUT);
})().catch(e => { console.error('RECORD ERROR:', e.message); process.exit(1); });

// capture.cjs — grab a single RanUI frame for demo-step verification.
//   CHROME_BIN=... node capture.cjs <label>
// Writes ./frames/<label>.png
//
// The attack graph is drawn on <canvas> (no DOM nodes to await), so a fixed
// sleep races the render and yields frames with no pods. We therefore poll the
// largest canvas's pixels until they stop changing.
const path = require('path');
const puppeteer = require('puppeteer-core');
const fs = require('fs');
const { setupLayout } = require('./layout.cjs');
const OUT = path.join(__dirname, 'frames');
const label = process.argv[2] || 'frame';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function canvasSignature(page) {
  return page.evaluate(() => {
    const cs = Array.from(document.querySelectorAll('canvas'));
    if (!cs.length) return 'nocanvas';
    const c = cs.sort((a, b) => b.width * b.height - a.width * a.height)[0];
    try {
      const d = c.toDataURL('image/png');
      return d.length + ':' + d.slice(-96);
    } catch (e) { return 'tainted'; }
  });
}

async function waitGraphSettled(page, maxMs = 30000, needStable = 3) {
  const t0 = Date.now();
  let last = null, stable = 0, drew = false;
  while (Date.now() - t0 < maxMs) {
    const sig = await canvasSignature(page);
    if (sig !== 'nocanvas' && sig !== 'tainted' && parseInt(sig) > 2000) drew = true;
    if (sig === last) {
      stable++;
      if (stable >= needStable && drew) return true;
    } else { stable = 0; last = sig; }
    await sleep(800);
  }
  return drew;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN, headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    userDataDir: OUT + '/../chrome-data', defaultViewport: { width: 960, height: 1080 },
  });
  const page = await browser.newPage();
  await page.goto('http://localhost:8080/', { waitUntil: 'networkidle2', timeout: 45000 });
  await setupLayout(page);          // same framing as the video
  const settled = await waitGraphSettled(page);
  await sleep(1200);                        // final paint
  const p = `${OUT}/${label}.png`;
  await page.screenshot({ path: p });
  const txt = await page.evaluate(() => (document.body.innerText || '').slice(0, 500));
  console.log(`frame -> ${p} (graph settled: ${settled})`);
  console.log('--- visible text ---\n' + txt);
  await browser.close();
})().catch(e => { console.error('CAPTURE ERROR:', e.message); process.exit(1); });

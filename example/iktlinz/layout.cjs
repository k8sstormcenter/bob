// layout.cjs — shared RanUI layout tuning for recording.
// Re-applied after every load/reload (a reload resets all of it).
//   - collapse the armory (left panel) so the graph gets the full width
//   - open + enlarge the operation timeline, un-truncate and enlarge its text
//   - zoom the cytoscape graph onto the action (fit alone leaves it tiny)
const sleep = ms => new Promise(r => setTimeout(r, ms));

// NB: RanUI puts these on `title`, not `aria-label` — matching only aria-label
// silently found nothing and the panel never collapsed.
const COLLAPSE = 'button[title="Collapse armory"], button[aria-label="Collapse armory"]';
const TIMELINE = 'button[title="Toggle operation timeline"], button[aria-label="Toggle operation timeline"]';

async function clickByLabel(page, re) {
  const box = await page.evaluate((src) => {
    const rx = new RegExp(src, 'i');
    const b = [...document.querySelectorAll('button')].find(x =>
      rx.test(x.getAttribute('title') || '') || rx.test(x.getAttribute('aria-label') || ''));
    if (!b) return null;
    const r = b.getBoundingClientRect();
    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
  }, re.source);
  if (!box) return false;
  await page.mouse.click(box.x, box.y);
  return true;
}

async function setupLayout(page, { fontPx = 15, pad = 40, minZoom = 0.85, timelineVh = 40 } = {}) {
  // 1. collapse the armory — use a real click; an in-page .click() did not register
  const collapsed = await clickByLabel(page, /collapse armory/);
  if (!collapsed) console.log('   (armory already collapsed or control absent)');
  await sleep(500);

  // 2. ensure the operation timeline is open
  const timelineOpen = await page.evaluate(
    () => /Operation Timeline/i.test(document.body.innerText || ''));
  if (!timelineOpen) {
    await clickByLabel(page, /toggle operation timeline/);
    await sleep(500);
  }

  // 3. readable, untruncated timeline with real estate
  await page.addStyleTag({ content: `
    .truncate { overflow: visible !important; text-overflow: clip !important; white-space: normal !important; }
    [class*="text-xs"], [class*="text-sm"] { font-size: ${fontPx}px !important; line-height: 1.35 !important; }
    [class*="max-h-"] { max-height: ${timelineVh}vh !important; }
  `});
  await sleep(250);

  // 4. zoom the graph onto the action. cy.fit() on a sparse graph leaves it
  //    tiny, so enforce a floor and re-centre on the newest (right-most) nodes.
  await page.evaluate(({ pad, minZoom }) => {
    const g = document.getElementById('graph');
    const cy = g && g._cyreg && g._cyreg.cy;
    if (!cy) return;
    cy.resize();
    const n = cy.nodes();
    if (!n.length) return;
    cy.fit(n, pad);
    if (cy.zoom() < minZoom) { cy.zoom(minZoom); cy.center(n); }
  }, { pad, minZoom });
  await sleep(300);

  // 5. timeline shows newest activity
  await page.evaluate(() => {
    const sc = [...document.querySelectorAll('div')]
      .filter(d => d.scrollHeight > d.clientHeight + 20 && d.clientHeight > 120);
    const tl = sc[sc.length - 1];
    if (tl) tl.scrollTop = tl.scrollHeight;
  });
  await sleep(200);
}

module.exports = { setupLayout, sleep };

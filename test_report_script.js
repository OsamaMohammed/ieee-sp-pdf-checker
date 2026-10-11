// Execute the generated report script against a small DOM contract. This checks
// filtering/export logic without a browser dependency; it is not layout QA.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const controls = new Map();
function control(id, value = '') {
  const c = {id, value, textContent: '', events: {}, addEventListener(event, fn) { this.events[event] = fn; }, focus() {}};
  controls.set(id, c); return c;
}
for (const id of ['status-filter', 'category-filter']) control(id, 'all');
for (const id of ['search', 'download', 'print', 'save-status', 'shown']) control(id);
const cards = Array.from(html.matchAll(/<article class="finding" data-status="([^"]+)" data-category="([^"]+)">([\s\S]*?)<\/article>/g), m => {
  const c = {dataset: {status:m[1], category:m[2]}, textContent:m[3], hidden:false};
  c.classList = {toggle(name, hidden) { c.hidden = hidden; }}; return c;
});
assert.ok(cards.length >= 100);
const selects = Array.from(html.matchAll(/class="answer-select" id="answer-([^"]+)" data-rule="[^"]+"/g), m => {
  const c = control('answer-'+m[1]); c.dataset = {rule:m[1]}; control('note-'+m[1]); return c;
});
const blobs = [];
const document = {
  getElementById(id) { assert.ok(controls.has(id), 'Missing control '+id); return controls.get(id); },
  querySelectorAll(selector) { if(selector === '.finding') return cards; if(selector === '.answer-select') return selects; if(selector === 'details') return []; throw Error('Unexpected selector '+selector); },
  createElement(tag) { assert.equal(tag,'a'); return {click() {}}; }
};
vm.runInNewContext(script, {document, window:{addEventListener(){}, print(){}}, Blob,
  URL:{createObjectURL(blob){blobs.push(blob);return 'blob:test';},revokeObjectURL(){}}, setTimeout(fn){fn();}});
assert.equal(controls.get('shown').textContent, `${cards.length} of ${cards.length} checks shown`);
controls.get('status-filter').value = 'warning';
controls.get('status-filter').events.input();
assert.ok(cards.filter(c => !c.hidden).every(c => c.dataset.status === 'warning'));
controls.get('status-filter').value = 'all';
controls.get('category-filter').value = 'later';
controls.get('category-filter').events.input();
assert.ok(cards.some(c => !c.hidden));
assert.ok(cards.filter(c => !c.hidden).every(c => c.dataset.category === 'later'));
const select = controls.get('answer-ethics.humans');
select.value = 'not_applicable';
controls.get('download').events.click();
assert.equal(blobs.length,0,'Missing justification must block export');
assert.match(controls.get('save-status').textContent,/justification/);
controls.get('note-ethics.humans').value = 'No human-derived data or participants.';
controls.get('download').events.click();
assert.equal(blobs.length,1);
blobs[0].text().then(text => {
  assert.deepEqual(JSON.parse(text), {'ethics.humans':{answer:'not_applicable',note:'No human-derived data or participants.'}});
  console.log('Generated report filtering and answer-export checks passed.');
}).catch(error => { console.error(error); process.exitCode=1; });

"""Self-contained, offline HTML rendering for the SP27 checker."""
from html import escape
from urllib.parse import urlsplit


def e(value):
    return escape(str(value), quote=True)


LABELS = dict(violation='Violation', warning='Warning', needs_review='Needs review',
              pass_='Pass', not_applicable='Not applicable / guidance')
LABELS['pass'] = LABELS.pop('pass_')


def render_html(report: dict) -> str:
    cards = []
    order = {'violation':0, 'warning':1, 'needs_review':2, 'pass':3, 'not_applicable':4}
    for f in sorted(report['findings'], key=lambda f: (order[f['status']], f['method'] == 'author_checklist', f['rule_id'])):
        id, status = f['rule_id'], f['status']
        category = 'later' if f['stage'] != 'submission' else 'checklist' if f.get('question') else 'automated'
        source = f['source']
        url = source['url']
        parts = urlsplit(url)
        link = '<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>'.format(e(url), e(source['section'])) if parts.scheme == 'https' and parts.hostname in ('sp2027.ieee-security.org', 'conferences.ieeeauthorcenter.ieee.org') else e(url)
        controls = ''
        if f.get('answerable'):
            answer = f.get('answer') or {}
            options = [('', 'Unanswered'), ('yes', 'Yes - confirmed by me'), ('no', 'No - needs action')]
            if f.get('conditional'):
                options.append(('not_applicable', 'Not applicable - explain below'))
            choices = ''.join('<option value="{}"{}>{}</option>'.format(e(v), ' selected' if answer.get('answer','') == v else '', e(t)) for v,t in options)
            controls = '<div class="answer"><label for="answer-{0}">Your answer</label><select class="answer-select" id="answer-{0}" data-rule="{0}">{1}</select><label for="note-{0}">Note / justification</label><textarea id="note-{0}" rows="2" placeholder="Required for not applicable and chair-approved exceptions">{2}</textarea></div>'.format(e(id), choices, e(answer.get('note','')))
        pages = 'Pages ' + ', '.join(map(str, f['pages'])) if f['pages'] else 'Document / policy'
        question = '<p class="question">{}</p>'.format(e(f['question'])) if f.get('question') else ''
        cards.append('''<article class="finding" data-status="{status}" data-category="{category}">
<div class="card-top"><span class="badge {status}">{label}</span><span class="meta">{pages} &middot; {method} &middot; {kind}</span></div>
<h3>{title}</h3><div class="rule">{id}</div>{question}
<details {opened}><summary>Evidence and next action</summary><p class="evidence">{evidence}</p><p><strong>Next action:</strong> {fix}</p><p class="meta">{explanation}</p></details>
{controls}<div class="source">Rule source: {link} &middot; {date}</div></article>'''.format(
            status=e(status), category=e(category), label=e(LABELS[status]), pages=e(pages),
            method=e(f['method'].replace('_',' ')), kind=e(f['kind']), title=e(f['title']), id=e(id),
            question=question, opened='open' if status in ('violation','warning') else '',
            evidence=e(f['evidence']), fix=e(f['remediation']), explanation=e(f.get('explanation','')),
            controls=controls, link=link, date=e(source['checked_on'])))
    counts = report['summary']['counts']
    stats = ''.join('<div class="stat"><span class="number {}">{}</span><span>{}</span></div>'.format(s, counts[s], e(LABELS[s])) for s in ('violation','warning','needs_review','pass'))
    rows = ''.join('<tr><td>{}</td><td>{:.2f} &times; {:.2f}</td><td>{}</td><td>{}</td></tr>'.format(p['number'],p['width'],p['height'],p['rotation'],e(section['kind'])) for p,section in zip(report['measurements']['pages'], report['measurements']['sections']))
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>SP27 preflight - ''' + e(report['input']['name']) + '''</title><style>
:root{--ink:#172b3a;--muted:#536575;--line:#dce3e8;--blue:#176075;--paper:#fff;--bg:#f1f5f7}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,Segoe UI,sans-serif}main{max-width:1120px;margin:auto;padding:36px 28px 70px}.eyebrow{letter-spacing:.15em;text-transform:uppercase;font-size:12px;font-weight:750;color:var(--blue)}header{display:flex;justify-content:space-between;gap:24px;align-items:start}h1{font-size:38px;letter-spacing:-.04em;margin:8px 0}h2{font-size:23px;margin:26px 0 10px}h3{font-size:18px;margin:12px 0 0}.subtitle,.meta{color:var(--muted)}.meta{font-size:13px}.tag{border:1px solid var(--line);padding:7px 12px;border-radius:30px;white-space:nowrap}.intro{max-width:820px}.summary{background:var(--ink);color:white;border-radius:16px;padding:24px;margin:26px 0}.summary h2{margin:0 0 8px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:22px}.stat{display:flex;flex-direction:column;border-left:1px solid #617583;padding-left:16px;font-size:13px}.number{font-size:36px;font-weight:700;line-height:1.3}.number.violation{color:#ffb5ac}.number.warning{color:#ffd597}.number.needs_review{color:#b5dce8}.number.pass{color:#a5e0c4}.toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:22px 0}.toolbar label{display:flex;flex-direction:column;gap:4px;font-size:13px;font-weight:600}input,select,textarea,button{font:inherit;border:1px solid #91a5b3;border-radius:7px;padding:9px 12px;background:white;color:var(--ink)}input[type=search]{min-width:250px}button{cursor:pointer;font-weight:650}button.primary{background:var(--blue);color:white;border-color:var(--blue)}:focus-visible{outline:3px solid #e5a72b;outline-offset:3px}.finding{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:14px 0}.card-top{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.badge{font-size:12px;font-weight:750;padding:4px 9px;border-radius:5px;background:#eef1f3}.badge.violation{color:#8c2418;background:#ffe3de}.badge.warning{color:#754508;background:#fff0d7}.badge.needs_review{color:#20576c;background:#e0f0f5}.badge.pass{color:#1f6444;background:#e0f2e8}.badge.not_applicable{color:#4f5b66;background:#eceff2}.rule{font:12px/1.7 ui-monospace,Consolas,monospace;color:var(--muted);margin-bottom:9px}.question{font-weight:550}details{margin-top:12px}summary{cursor:pointer;font-weight:600}.evidence{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.65 ui-monospace,Consolas,monospace;background:#f4f7f8;border-radius:6px;padding:14px;max-height:340px;overflow:auto}.source{border-top:1px solid var(--line);margin-top:18px;padding-top:10px;font-size:12px;color:var(--muted)}a{color:#176075;overflow-wrap:anywhere}.answer{display:grid;grid-template-columns:170px 1fr;gap:8px;align-items:center;margin-top:18px;padding-top:14px;border-top:1px dashed var(--line)}.answer label{font-size:13px}.answer textarea{width:100%;resize:vertical}.notice{background:#e7f0f4;border-left:4px solid var(--blue);padding:14px 18px;border-radius:4px;font-size:14px}.hidden{display:none!important}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;background:white;font-size:14px}td,th{border-bottom:1px solid var(--line);padding:9px 12px;text-align:left}footer{margin-top:30px;font-size:12px;color:var(--muted)}code{overflow-wrap:anywhere}#save-status{color:var(--blue);font-size:14px}
@media(max-width:650px){main{padding:20px 14px}header{display:block}header .tag{display:inline-block;margin-top:12px}h1{font-size:30px}.stats{grid-template-columns:repeat(2,1fr)}.finding{padding:17px}.answer{grid-template-columns:1fr}.toolbar label,input[type=search]{width:100%}}
@media print{body{background:white;font-size:11px}main{max-width:none;padding:0}.toolbar,.answer,#download,#save-status{display:none}.finding{break-inside:avoid}.finding.hidden{display:block!important}.summary{background:white;color:black;border:1px solid #999}.number{color:black!important}.evidence{max-height:none;overflow:visible}details>summary{display:none}details::details-content{content-visibility:visible}a{color:black}}
</style></head><body><main>
<header><div><div class="eyebrow">IEEE Security &amp; Privacy 2027</div><h1>Submission preflight</h1><div class="subtitle">''' + e(report['input']['name']) + ' &middot; ' + str(report['input']['pages']) + ' pages &middot; ' + e(report['options']['paper_type'].upper()) + ' &middot; Cycle ' + str(report['options']['cycle']) + '''</div></div><span class="tag">Local &middot; Offline</span></header>
<p class="intro">Check the evidence, fix detected problems, and complete the author checklist. Automated measurements and author confirmations are shown separately. This report does not certify acceptance.</p>
<section class="summary" aria-label="Check summary"><h2>''' + e(report['summary']['outcome']) + '</h2><div>' + str(report['summary']['covered_rules']) + ' / ' + str(report['summary']['total_rules']) + ' policy checks represented &middot; Snapshot ' + e(report['policy_version']) + '</div><div class="stats">' + stats + '''</div></section>
<div class="notice"><strong>Not everything is in the PDF.</strong> HotCRP declarations, research ethics, submission history and artifact contents need your review. “Needs review” means unresolved, not a confirmed violation. “Pass” applies only to the narrow check named.</div>
<h2>Findings &amp; author checklist</h2><p class="meta">Choose answers below, then download the answers file and rerun with <code>--answers answers.json</code>. Editing this page does not change the recorded check results. Unsaved answers are lost when you close or reload it.</p>
<div class="toolbar"><label>Show<select id="status-filter"><option value="all">All statuses</option><option value="action">Violations, warnings &amp; review</option>''' + ''.join('<option value="{}">{}</option>'.format(s,e(t)) for s,t in LABELS.items()) + '''</select></label>
<label>Category<select id="category-filter"><option value="all">All categories</option><option value="automated">PDF / source checks</option><option value="checklist">Author checklist</option><option value="later">Later-stage guidance</option></select></label><label>Search<input type="search" id="search" placeholder="Rule, page, evidence..."></label><button id="download" class="primary">Download answers</button><button id="print">Print report</button></div>
<p id="save-status" role="status" aria-live="polite"></p><p id="shown" class="meta" role="status"></p><section id="findings">''' + ''.join(cards) + '''</section>
<details><summary>Page measurements and section hints</summary><div class="table-wrap"><table><thead><tr><th>Page</th><th>MediaBox (PDF points)</th><th>Rotation</th><th>Section hint</th></tr></thead><tbody>''' + rows + '''</tbody></table></div></details>
<details><summary>Limits and interpretation</summary><ul>''' + ''.join('<li>'+e(s)+'</li>' for s in report['limitations']) + '''</ul><p>Formatting reference: <a href="https://ctan.org/pkg/ieeetran">IEEEtran 1.8b</a>. ''' + e(report['measurements']['baseline'].get('provenance','')) + '''</p></details>
<footer>Generated ''' + e(report['generated_at']) + '<br>PDF SHA-256: <code>' + e(report['input']['sha256']) + '''</code><br>Reports contain excerpts from your paper. No document or answer is uploaded by this tool.</footer></main>
<script>
const cards=Array.from(document.querySelectorAll('.finding'));
function filter(){const status=document.getElementById('status-filter').value;const category=document.getElementById('category-filter').value;const query=document.getElementById('search').value.toLowerCase();let shown=0;for(const card of cards){const ok=(status==='all'||status===card.dataset.status||(status==='action'&&['violation','warning','needs_review'].includes(card.dataset.status)))&&(category==='all'||category===card.dataset.category)&&card.textContent.toLowerCase().includes(query);card.classList.toggle('hidden',!ok);if(ok)shown++;}document.getElementById('shown').textContent=shown+' of '+cards.length+' checks shown';}
for(const id of ['status-filter','category-filter','search'])document.getElementById(id).addEventListener('input',filter);filter();
document.getElementById('download').addEventListener('click',()=>{const answers={};const message=document.getElementById('save-status');for(const select of document.querySelectorAll('.answer-select')){if(!select.value)continue;const id=select.dataset.rule;const note=document.getElementById('note-'+id).value.trim();if((select.value==='not_applicable'||(id==='length.exception'&&select.value==='yes'))&&!note){message.textContent='Add a justification for '+id+' before saving.';document.getElementById('note-'+id).focus();return;}answers[id]={answer:select.value,note};}const blob=new Blob([JSON.stringify(answers,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='answers.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);message.textContent='Downloaded '+Object.keys(answers).length+' answers. Rerun the checker with --answers answers.json to update results.';});
let wasOpen=[];window.addEventListener('beforeprint',()=>{wasOpen=Array.from(document.querySelectorAll('details')).map(d=>d.open);document.querySelectorAll('details').forEach(d=>d.open=true);});window.addEventListener('afterprint',()=>document.querySelectorAll('details').forEach((d,i)=>d.open=wasOpen[i]));document.getElementById('print').addEventListener('click',()=>window.print());
</script></body></html>'''

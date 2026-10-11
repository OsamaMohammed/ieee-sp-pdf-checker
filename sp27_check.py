"""Offline IEEE S&P 2027 submission preflight checker."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys
import tempfile
from typing import Optional
import webbrowser

import fitz

CFP = 'https://sp2027.ieee-security.org/cfpapers.html'
CHECKED_ON = '2026-10-10'
HERE = Path(__file__).resolve().parent
STATUSES = ('violation', 'warning', 'needs_review', 'pass', 'not_applicable')


def finding(rule_id, title, status, evidence, remediation, pages=None,
            method='measurement', section='Page Limit and Formatting', explanation=''):
    return dict(rule_id=rule_id, title=title, status=status, method=method,
                applicability='submission', pages=pages or [], evidence=evidence,
                explanation=explanation, remediation=remediation,
                source=dict(url=CFP, section=section, checked_on=CHECKED_ON),
                kind='mandatory', stage='submission')


def extract_pdf(path: Path) -> dict:
    path = Path(path)
    try:
        with fitz.open(str(path)) as doc:
            if not doc.is_pdf or doc.needs_pass or not doc.page_count:
                raise ValueError('Use a nonempty, unencrypted PDF.')
            pages = []
            for number, page in enumerate(doc, 1):
                item = dict(number=number, width=page.mediabox.width,
                            height=page.mediabox.height, rotation=page.rotation,
                            cropbox=list(page.cropbox), mediabox=list(page.mediabox),
                            text='', lines=[], links=[], annotations=[], fonts=[],
                            drawing_bounds=[], image_bounds=[], error='')
                try:
                    flags = fitz.TEXTFLAGS_DICT & ~fitz.TEXT_PRESERVE_IMAGES
                    raw = page.get_text('dict', flags=flags, clip=fitz.INFINITE_RECT())
                    for block in raw['blocks']:
                        for line in block.get('lines', []):
                            spans = [{k: s[k] for k in ('text', 'font', 'size', 'bbox', 'origin')}
                                     for s in line['spans']]
                            item['lines'].append(dict(text=''.join(s['text'] for s in spans),
                                                      bbox=list(line['bbox']), spans=spans))
                    item['text'] = '\n'.join(line['text'] for line in item['lines'])
                    item['links'] = [link.get('uri', '') for link in page.get_links() if link.get('uri')]
                    item['annotations'] = [a.info for a in (page.annots() or [])]
                    item['fonts'] = [dict(xref=f[0], extension=f[1], type=f[2], name=f[3])
                                     for f in page.get_fonts()]
                    item['drawing_bounds'] = [list(d['rect']) for d in page.get_drawings()]
                    item['image_bounds'] = [list(i['bbox']) for i in page.get_image_info()]
                except Exception as exc:
                    item['error'] = str(exc)
                pages.append(item)
            return dict(path=str(path.resolve()), page_count=len(pages),
                        metadata=doc.metadata or {}, pages=pages)
    except (RuntimeError, OSError, ValueError) as exc:
        raise ValueError('Cannot inspect PDF {}: {}'.format(path.name, exc)) from exc


def extraction_gap(page):
    if page['error']:
        return page['error']
    if not page['text'].strip():
        return 'No extractable text'
    area = page['width'] * page['height']
    image_area = sum(max(0, b[2]-b[0]) * max(0, b[3]-b[1]) for b in page['image_bounds'])
    if image_area > area * .45 and len(re.findall(r'\w+', page['text'])) < 50:
        return 'Image-dominated page with sparse searchable text; image contents were not OCRed'
    return ''


def check_geometry(document: dict) -> list:
    findings = []
    bad = [p for p in document['pages'] if abs(p['width'] - 612) > 1 or abs(p['height'] - 792) > 1]
    findings.append(finding('page.size', 'US Letter page size', 'violation' if bad else 'pass',
                            '; '.join('p{}: {:.2f} x {:.2f} pt'.format(p['number'], p['width'], p['height'])
                                      for p in bad) or 'All MediaBoxes are 612 x 792 PDF points (tolerance 1 pt).',
                            'Export with US Letter paper size.', [p['number'] for p in bad]))
    odd = [p for p in document['pages'] if p['rotation'] or p['cropbox'] != p['mediabox']]
    findings.append(finding('pdf.boxes', 'Rotation and crop boxes', 'warning' if odd else 'pass',
                            '; '.join('p{}: rotation {}; crop {}; media {}'.format(
                                p['number'], p['rotation'], p['cropbox'], p['mediabox']) for p in odd)
                            or 'No rotated or cropped pages detected.',
                            'Visually verify page orientation and that no content is hidden by cropping.',
                            [p['number'] for p in odd]))
    unreadable = [p for p in document['pages'] if extraction_gap(p)]
    findings.append(finding('pdf.readability', 'PDF text extraction', 'needs_review' if unreadable else 'pass',
                            '; '.join('p{}: {}'.format(p['number'], extraction_gap(p))
                                      for p in unreadable) or 'Text was extracted from every page; visual readability still needs review.',
                            'Inspect affected pages visually. Image-only PDFs cannot be fully checked without OCR.',
                            [p['number'] for p in unreadable], section='Conference Submission Server'))
    return findings


BASELINE = dict(body_size=10.0, leading=11.2, side_margin=54.0,
                vertical_margin=72.0, column_gap=18.0, column_width=243.0,
                size_tolerance=0.25, leading_tolerance=0.6, margin_tolerance=5.0,
                source='https://ctan.org/pkg/ieeetran')
REF_HEADING = re.compile(r'^(?:[IVX]+[.\s]+|\d+[.\s]+)?(?:references|bibliography)\s*$', re.I)
APP_HEADING = re.compile(r'^appendi(?:x|ces)(?:\s+[A-Z0-9]+)?(?:\s*[:.].*)?\s*$', re.I)


def section_estimates(document):
    """Conservative page hints; never certification of reference-only content."""
    estimates = []
    in_references = False
    for page in document['pages']:
        lines = [line['text'].strip() for line in page['lines'] if line['text'].strip()]
        lines = [s for s in lines if not re.fullmatch(r'\d+', s)]
        refs = [i for i, s in enumerate(lines) if REF_HEADING.fullmatch(s)]
        apps = [i for i, s in enumerate(lines) if APP_HEADING.fullmatch(s)]
        entries = sum(bool(re.match(r'^\[\d+\]', s)) for s in lines)
        reference_only = bool(lines and not apps and not page['image_bounds'] and
                              ((refs == [0] and entries) or (in_references and not refs and entries >= 3)))
        if apps:
            kind = 'appendix' if apps[0] == 0 else 'mixed'
            in_references = False
        elif reference_only:
            kind = 'references (estimated)'
            in_references = True
        elif refs:
            kind = 'mixed'
            in_references = True
        else:
            kind = 'body or uncertain'
            in_references = False
        estimates.append(dict(page=page['number'], kind=kind))
    return estimates


def visible_margin_overflow(document, page, bounds, baseline):
    """Confirm candidate box overflow in rendered ink, not font ascent boxes."""
    tolerance = baseline['margin_tolerance']
    left = baseline['side_margin'] - tolerance
    right = page['width'] - left
    top = baseline['vertical_margin'] - tolerance
    bottom = page['height'] - top
    regions = []
    if bounds[0] < left:
        regions.append((0, 0, left, page['height']))
    if bounds[2] > right:
        regions.append((right, 0, page['width'], page['height']))
    if bounds[1] < top:
        regions.append((0, 0, page['width'], top))
    if bounds[3] > bottom:
        regions.append((0, bottom, page['width'], page['height']))
    if not regions:
        return False
    # Cropped/rotated coordinates require contextual review; retain the warning.
    if page['rotation'] or page['cropbox'] != page['mediabox']:
        return True
    try:
        with fitz.open(document['path']) as pdf:
            rendered = pdf[page['number'] - 1]
            for region in regions:
                pix = rendered.get_pixmap(matrix=fitz.Matrix(2, 2), colorspace=fitz.csGRAY,
                                          alpha=False, annots=False, clip=fitz.Rect(region))
                # At 144 dpi require four visibly nonwhite pixels to ignore
                # isolated antialias noise. Pale/very fine marks remain a limit.
                if sum(value < 200 for value in pix.samples) >= 4:
                    return True
        return False
    except (OSError, RuntimeError, ValueError):
        return True  # Failed confirmation must not clear the candidate.


def check_pdf(document: dict, paper_type: str, baseline: dict) -> list:
    baseline = dict(BASELINE, **baseline)
    findings = check_geometry(document)
    n = document['page_count']
    estimates = section_estimates(document)
    ref_pages = [e['page'] for e in estimates if e['kind'] == 'references (estimated)']
    total_status = ('violation' if n > 18 else 'pass') if paper_type == 'research' else 'needs_review'
    evidence = '{} physical pages; research limit 18.'.format(n)
    if paper_type == 'sok':
        evidence = '{} physical pages; {} estimated reference-only pages; {} estimated counted pages. Mixed pages and reference exclusions require confirmation.'.format(n, len(ref_pages), n - len(ref_pages))
    findings.append(finding('length.total', 'Total page limit', total_status, evidence,
                            'Keep within the applicable limit, or obtain explicit PC-chair approval. For SoK confirm the reference exclusion.',
                            list(range(19, n + 1)) if n > 18 else [], method='measurement' if paper_type == 'research' else 'heuristic'))
    uncertain = [e['page'] for e in estimates if e['page'] > 13 and e['kind'] not in ('references (estimated)', 'appendix')]
    findings.append(finding('length.body', 'Main text and appendix boundaries',
                            'needs_review' if n > 13 or paper_type == 'sok' else 'pass',
                            'Pages beyond 13 without an independent reference/appendix heading: {}. Section hints: {}.'.format(
                                uncertain or 'none', '; '.join('{}: {}'.format(e['page'], e['kind']) for e in estimates))
                            if n > 13 else 'No pages beyond physical page 13.',
                            'Verify the 13-page body limit and appendix labels. References are distinct from appendices. SoK reference pages are excluded; mixed pages need manual interpretation.',
                            uncertain, method='heuristic'))
    sample_pages = []
    for page in document['pages']:
        # A reference entry often wraps into unnumbered lines. Exclude the whole
        # reference-bearing page from body sampling, including mixed pages.
        texts = [line['text'].strip() for line in page['lines']]
        if any(REF_HEADING.fullmatch(t) for t in texts) or sum(bool(re.match(r'^\[\d+\]', t)) for t in texts) >= 3:
            continue
        candidates = []
        for line in page['lines']:
            text = line['text'].strip()
            if (len(text) < 35 or len(text.split()) < 5 or
                re.match(r'^(?:Fig(?:ure)?\.?|Table|Algorithm|\[\d+\])\s*', text, re.I) or
                line['bbox'][1] < 80 or line['bbox'][3] > 720 or
                line['bbox'][2] - line['bbox'][0] > 270):
                continue
            spans = [s for s in line['spans'] if len(s['text'].strip()) > 15 and 7 <= s['size'] <= 14
                     and not re.search(r'italic|bold|symbol|math|cmmi|cmsy', s['font'], re.I)]
            if spans:
                candidates.append((line, max(spans, key=lambda s: len(s['text']))))
        # ponytail: paragraph samples are heuristic; complex layouts need visual review.
        if len(candidates) >= 8:
            sizes = Counter(round(s['size'], 1) for _, s in candidates)
            dominant = sizes.most_common(1)[0][0]
            body = [(l, s) for l, s in candidates if abs(s['size'] - dominant) < .2]
            fonts = Counter(s['font'] for _, s in body)
            gaps = []
            column_starts = []
            for right in (False, True):
                col = sorted([(l, s) for l, s in body if (l['bbox'][0] > 300) == right], key=lambda ls: ls[1]['origin'][1])
                if col:
                    column_starts.append(round(statistics.median(l['bbox'][0] for l, _ in col), 2))
                for (a, sa), (b, sb) in zip(col, col[1:]):
                    gap = sb['origin'][1] - sa['origin'][1]
                    if 5 < gap < 20 and abs(a['bbox'][0] - b['bbox'][0]) < 10:
                        gaps.append(gap)
            leading = statistics.median(gaps) if len(gaps) >= 5 else None
            sample_pages.append(dict(page=page['number'], size=dominant, font=fonts.most_common(1)[0][0],
                                     leading=round(leading, 2) if leading else None, columns=column_starts))
    font_bad = [s['page'] for s in sample_pages if abs(s['size'] - baseline['body_size']) > baseline['size_tolerance']
                or not re.search(r'times|nimbusrom|termes|ptm', s['font'], re.I)]
    findings.append(finding('format.body', 'Body font sample', 'warning' if font_bad else ('pass' if sample_pages else 'needs_review'),
                            json.dumps(sample_pages, ensure_ascii=True) if sample_pages else 'Insufficient ordinary paragraph lines for a reliable sample.',
                            'Compare body text to the default compsoc conference template: 10 PDF points, Times-compatible font. Small captions and equations have different roles.',
                            font_bad, method='heuristic'))
    leading_bad = [s['page'] for s in sample_pages if s['leading'] is not None and abs(s['leading'] - baseline['leading']) > baseline['leading_tolerance']]
    findings.append(finding('format.spacing', 'Body line-spacing sample', 'warning' if leading_bad else
                            ('pass' if any(s['leading'] for s in sample_pages) else 'needs_review'),
                            'Sampled baselines: {}. Template baseline 11.2 PDF points; comparison tolerance 0.6.'.format(
                                ', '.join('p{}: {}'.format(s['page'], s['leading']) for s in sample_pages) or 'unavailable'),
                            'Verify conference,compsoc is selected and compare paragraph spacing with that template. A mismatch can come from a different IEEE mode; it does not establish manual compression.', leading_bad, method='heuristic'))
    bounds_bad, margins = [], []
    for p in document['pages']:
        boxes = [l['bbox'] for l in p['lines'] if l['text'].strip() and not re.fullmatch(r'\d+', l['text'].strip())]
        boxes += p['drawing_bounds'] + p['image_bounds']
        boxes = [b for b in boxes if b[2] > b[0] and b[3] > b[1]]
        if boxes:
            bounds = [min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes)]
            margins.append(dict(page=p['number'], occupied_bounds=[round(x, 2) for x in bounds]))
            if visible_margin_overflow(document, p, bounds, baseline):
                bounds_bad.append(p['number'])
    findings.append(finding('format.margins', 'Occupied page bounds', 'warning' if bounds_bad else ('pass' if margins else 'needs_review'),
                            json.dumps(margins) + ' Candidate box overflows are checked against rendered ink; font boxes alone can extend beyond visible glyphs.', 'Compare flagged content with the template. Nominal margins: sides 54 pt, top/bottom 72 pt; 5 pt allowance for glyph boxes and template quantization. Render confirmation uses 144 dpi and at least four grayscale pixels below 200; very pale/fine marks can be missed. Headers/footers may need separate review.', bounds_bad, method='heuristic'))
    column_bad = [s['page'] for s in sample_pages if len(s['columns']) != 2 or
                  any(abs(a - b) > 8 for a, b in zip(s['columns'], (54, 315)))]
    findings.append(finding('format.columns', 'Two-column layout sample', 'warning' if column_bad else ('pass' if sample_pages else 'needs_review'),
                            'Sampled column starts: {}. Expected starts 54 and 315 pt, widths 243 pt, gap 18 pt.'.format(
                                '; '.join('p{}: {}'.format(s['page'], s['columns']) for s in sample_pages)),
                            'Restore the compsoc two-column layout; full-width floats and indentation can affect this heuristic.', column_bad, method='heuristic'))
    findings.append(finding('format.template', 'Exact template and visual formatting', 'needs_review',
                            'PDF measurements cannot establish class version, macro overrides, or all space scrunching.',
                            'Compare the rendered paper with IEEEtran 1.8b conference,compsoc; optionally supply --tex.', method='heuristic'))
    fonts = sorted(set((p['number'], f['name'], 'Type 3 glyph program: visually inspect rendering' if f['type'] == 'Type3'
                         else 'No extractable font program: verify embedding/rendering')
                       for p in document['pages'] for f in p['fonts'] if f['extension'] == 'n/a'))
    findings.append(finding('pdf.fonts', 'Font portability diagnostic', 'warning' if fonts else 'pass',
                            str(fonts) if fonts else 'No font-resource portability signals detected.',
                            'Verify rendering on another viewer. This is a compatibility diagnostic, not a separate CFP embedding mandate.',
                            sorted(set(p for p, _, _ in fonts)), method='heuristic', section='Conference Submission Server'))
    cves, signals = [], []
    for p in document['pages']:
        text = p['text']
        for match in re.finditer(r'\bCVE[\-\u2010-\u2015]\d{4}[\-\u2010-\u2015]\d{4,}\b', text, re.I):
            cves.append((p['number'], match.group()))
        patterns = [r'\backnowledg(?:e)?ments?\b', r'\bour (?:previous|prior|earlier) (?:work|paper|study)\b',
                    r'\b(?:funded|supported) by\b']
        if p['number'] == 1:
            title_area = text.split('Abstract')[0].split('ABSTRACT')[0][:1800]
            for match in re.finditer(r'[\w.+-]+@[\w.-]+\.\w+|\b(?:University|Institute|Department|John Doe|Jane Doe|First Author|Author Name|Anonymous Authors?)\b', title_area, re.I):
                signals.append((1, 'Title area: ' + match.group()))
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.I):
                signals.append((p['number'], text[max(0, match.start()-30):match.end()+90].replace('\n', ' ')))
        for link in p['links']:
            signals.append((p['number'], 'Review link for identity disclosure: ' + link))
        if p['annotations']:
            signals.append((p['number'], 'Review PDF annotations: ' + json.dumps(p['annotations'])))
    author = document['metadata'].get('author', '').strip()
    if author:
        signals.append((0, 'PDF author metadata: ' + author))
    findings.append(finding('anonymity.cve', 'Full CVE identifiers', 'violation' if cves else
                            ('needs_review' if any(extraction_gap(p) for p in document['pages']) else 'pass'),
                            '; '.join('p{}: {}'.format(p, s) for p, s in cves) or 'No full CVE identifiers found in extracted text. Image contents and extraction gaps are not cleared by this check.',
                            'Blind full CVE identifiers in the submitted PDF.', sorted(set(p for p, _ in cves)),
                            section='Ethical Considerations for Vulnerability Disclosure'))
    findings.append(finding('anonymity.signals', 'Potential identity disclosures', 'warning' if signals else 'needs_review',
                            '; '.join(('p{}: '.format(p) if p else '') + s for p, s in signals) or 'No simple identity signals found. Names and indirect disclosure still require human review.',
                            'Inspect signals in context. Remove identifying author details, funding acknowledgments, and self-identification; check artifacts separately. Neutral AI disclosures need not identify authors.',
                            sorted(set(p for p, _ in signals if p)), method='heuristic', section='Anonymous Submission'))
    first_lines = document['pages'][0]['lines']
    title_lines = [l for l in first_lines if l['bbox'][1] < 220 and l['text'].strip()]
    title = ' '.join(l['text'] for l in title_lines[:4])
    has_sok = bool(re.match(r'^SoK\s*:', title, re.I))
    findings.append(finding('sok.title', 'SoK title prefix', ('pass' if has_sok else 'needs_review') if paper_type == 'sok' else 'not_applicable',
                            'Extracted title area: ' + (title or '(unavailable)'),
                            'For SoK papers use the SoK: title prefix and select the HotCRP checkbox. Confirm the extracted title.',
                            [1] if paper_type == 'sok' else [], method='heuristic', section='Systematization of Knowledge Papers'))
    return findings


def check_tex(path: Optional[Path]) -> list:
    ids = [('tex.class', 'TeX class/options'), ('tex.version', 'IEEEtran version evidence'),
           ('tex.overrides', 'Static formatting overrides'), ('tex.includes', 'Uninspected included source')]
    if path is None:
        return [finding(i, t, 'not_applicable', 'Optional TeX source not supplied; PDF template review remains required.',
                        'Optionally use --tex main.tex.', method='source_inspection') for i, t in ids]
    path = Path(path)
    raw = path.read_text(encoding='utf-8-sig')
    text = re.sub(r'(?<!\\)%[^\n]*', '', raw)
    match = re.search(r'\\documentclass\s*(?:\[([^\]]*)\])?\s*\{([^}]+)\}', text)
    correct = bool(match and match[2].strip() == 'IEEEtran' and
                   {'conference', 'compsoc'} <= {option.strip() for option in (match[1] or '').split(',')})
    results = [finding('tex.class', 'TeX class/options', 'pass' if correct else ('violation' if match else 'needs_review'),
                       match.group() if match else 'No static documentclass declaration found.',
                       'Use \\documentclass[conference,compsoc]{IEEEtran}. Static inspection does not prove the compiled output.', method='source_inspection')]
    cls = path.parent / 'IEEEtran.cls'
    version = None
    if cls.is_file():
        version = re.search(r'\\ProvidesClass\{IEEEtran\}\[[^\]]*?\bV(\d+\.\d+[a-z]?)', cls.read_text(encoding='utf-8', errors='replace'))
    results.append(finding('tex.version', 'IEEEtran version evidence', 'pass' if version and version[1] == '1.8b' else 'needs_review',
                           'Local class declares ' + version[1] if version else 'No readable sibling class version declaration. A system-installed class was not inspected.',
                           'Verify the compiler used IEEEtran.cls 1.8b; a local declaration alone is not build provenance.', method='source_inspection'))
    overrides = []
    pattern = r'\\(?:usepackage(?:\[[^\]]*\])?\s*\{[^}]*(?:usenix|geometry|fullpage|savetrees|setspace)[^}]*\}|(?:setlength|addtolength)\s*\{\\(?:textwidth|textheight|topmargin|oddsidemargin|columnsep|baselineskip)\}|(?:vspace|hspace)\*?\s*\{\s*-|linespread|fontsize|baselinestretch|CLASSINPUT\w+)'
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(pattern, line):
            overrides.append('{}:{}: {}'.format(path.name, number, line.strip()))
    results.append(finding('tex.overrides', 'Static formatting overrides', 'warning' if overrides else 'pass',
                           '\n'.join(overrides) or 'No listed override patterns found (macros are not expanded).',
                           'Remove template-changing overrides; inspect legitimate spacing in context.', method='source_inspection'))
    includes = re.findall(r'\\(?:input|include)\s*\{([^}]+)\}', text)
    results.append(finding('tex.includes', 'Uninspected included source', 'needs_review' if includes else 'pass',
                           'Uninspected files: ' + ', '.join(includes) if includes else 'No literal input/include directives found; dynamic source is not expanded.',
                           'Review included files and macros; this check reads only the supplied file and a sibling IEEEtran.cls.', method='source_inspection'))
    return results


def load_catalog(path: Path) -> dict:
    catalog = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    ids = set()
    for rule in catalog['rules']:
        if rule['id'] in ids or rule['mode'] not in ('automatic', 'manual', 'guidance'):
            raise ValueError('Duplicate or invalid policy rule: ' + rule['id'])
        ids.add(rule['id'])
        if not rule['source']['url'].startswith('https://') or not rule['source']['checked_on']:
            raise ValueError('Missing policy provenance: ' + rule['id'])
    return catalog


def load_answers(path: Optional[Path], catalog: dict) -> dict:
    if path is None:
        return {}
    answers = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    validate_answers(answers, catalog)
    return answers


def validate_answers(answers, catalog):
    if not isinstance(answers, dict):
        raise ValueError('Answers must be an object keyed by manual rule ID.')
    rules = {r['id']: r for r in catalog['rules'] if r['mode'] == 'manual'}
    for id, item in answers.items():
        if id not in rules or not isinstance(item, dict):
            raise ValueError('Unknown/manual-only answer ID or invalid object: ' + id)
        if set(item) - {'answer', 'note'} or item.get('answer') not in ('yes', 'no', 'not_applicable') or not isinstance(item.get('note', ''), str):
            raise ValueError('Invalid answer for ' + id)
        if item['answer'] == 'not_applicable' and (not rules[id]['conditional'] or not item.get('note', '').strip()):
            raise ValueError('Not-applicable requires a conditional question and an explanatory note: ' + id)
        if id == 'length.exception' and item['answer'] == 'yes' and not item.get('note', '').strip():
            raise ValueError('A chair exception requires approval details in the note.')


def evaluate_policy(catalog: dict, answers: dict, paper_type: str, cycle: int) -> list:
    validate_answers(answers, catalog)
    findings = []
    for r in catalog['rules']:
        if r['mode'] == 'automatic':
            continue
        applicable = r['paper_type'] in ('all', paper_type) and r['stage'] == 'submission'
        answer = answers.get(r['id']) if applicable and r['mode'] == 'manual' else None
        status, method, evidence = 'needs_review', 'author_checklist', 'Not answered. ' + r['question']
        if not applicable:
            status, evidence = 'not_applicable', r['details'] + ' (Outside this initial submission/paper-type check.)'
        elif r['mode'] == 'guidance':
            status, method, evidence = 'not_applicable', 'guidance', r['details']
        elif answer:
            method = 'author_attestation'
            status = {'yes':'pass', 'no':'violation' if r['kind'] == 'mandatory' else 'warning',
                      'not_applicable':'not_applicable'}[answer['answer']]
            evidence = 'Author-reported: {}. {}'.format(answer['answer'], answer.get('note', ''))
        if r['id'] == 'submission.deadlines':
            dates = catalog['deadlines'][str(cycle)]
            evidence = 'Cycle {}: '.format(cycle) + '; '.join('{}: {} (UTC {})'.format(k, v, datetime.fromisoformat(v).astimezone(timezone.utc).isoformat()) for k, v in dates.items())
            evidence += '. AoE is UTC-12. A local check does not verify submission; draft due at least 24 hours earlier.'
        f = finding(r['id'], r['title'], status, evidence, r['remediation'], method=method,
                    section=r['section'], explanation=r['details'])
        f.update(source=r['source'], kind=r['kind'], stage=r['stage'],
                 applicability='conditional' if r['conditional'] else r['stage'],
                 question=r['question'], conditional=r['conditional'], answer=answer,
                 answerable=r['mode'] == 'manual' and applicable)
        findings.append(f)
    return findings


def build_report(document: dict, findings: list, options: dict, catalog: dict) -> dict:
    rules = {r['id']: r for r in catalog['rules']}
    missing = set(rules) - {f['rule_id'] for f in findings}
    if missing:
        raise ValueError('Internal error: policy checks missing: ' + ', '.join(sorted(missing)))
    for f in findings:
        if f['rule_id'] in rules:
            f['kind'] = rules[f['rule_id']]['kind']
        if f['status'] not in STATUSES:
            raise ValueError('Invalid finding status')
    counts = {s: sum(f['status'] == s for f in findings) for s in STATUSES}
    outcome = ('Violations found' if counts['violation'] else 'Review required' if
               counts['warning'] or counts['needs_review'] else 'No detected violations with completed author checklist')
    code = 1 if any(counts[s] for s in ('violation', 'warning', 'needs_review')) else 0
    source_list = list({json.dumps(f['source'], sort_keys=True): f['source'] for f in findings}.values())
    path = Path(document['path'])
    return dict(schema_version=1, input=dict(path=str(path), name=path.name,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(), pages=document['page_count']),
                options=options, policy_version=catalog['version'], sources=source_list,
                generated_at=datetime.now(timezone.utc).isoformat(),
                measurements=dict(pages=[{k:p[k] for k in ('number','width','height','rotation','cropbox','error')}
                                         for p in document['pages']],
                                  sections=section_estimates(document), baseline=catalog['baseline']),
                findings=findings, summary=dict(outcome=outcome, counts=counts, exit_code=code,
                                                covered_rules=len(rules), total_rules=len(rules)),
                limitations=[
                    'This is a preflight aid, not an IEEE certification or a guarantee against desk rejection.',
                    'The policy snapshot is dated 2026-10-10. Check the live CFP for changes.',
                    'Section boundaries, body typography and identity signals are heuristic; inspect their evidence.',
                    'Scanned or unextractable content is not OCRed. Names inside images or indirect identity clues may be missed.',
                    'HotCRP entries, repository contents, submission history and research ethics require author review.',
                    'A local TeX file is inspected statically; included files/macros and the actual compilation are not verified.',
                    'SoK reference exclusions and mixed pages require manual confirmation. No fractional-page rule is invented.',
                    'IEEE AI policy details were checked via the official IEEE Author Center; the linked PSPB manual could not be retrieved.',
                    'Report excerpts and answers can contain sensitive paper details; reports stay local.'])


def same_path(a, b):
    a, b = Path(a), Path(b)
    return (os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve())) or
            (a.exists() and b.exists() and os.path.samefile(str(a), str(b))))


def write_reports(report: dict, output: Path, inputs: list) -> None:
    from sp27_report import render_html
    output = Path(output).absolute()
    if output.suffix.lower() not in ('.html', '.htm'):
        raise ValueError('--output must end in .html or .htm; JSON is written alongside it.')
    targets = [output, output.with_suffix('.json')]
    protected = list(inputs) + [HERE / 'sp27_rules.json', HERE / 'sp27_check.py', HERE / 'sp27_report.py']
    if same_path(*targets) or any(same_path(t, p) for t in targets for p in protected):
        raise ValueError('Report destinations must be distinct and must not overwrite inputs or checker files.')
    contents = [render_html(report), json.dumps(report, indent=2, ensure_ascii=False) + '\n']
    output.parent.mkdir(parents=True, exist_ok=True)
    temporaries = []
    try:
        for target, content in zip(targets, contents):
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=str(target.parent),
                                             suffix='.tmp', delete=False) as stream:
                temporaries.append(Path(stream.name))
                stream.write(content)
        for temporary, target in zip(temporaries, targets):
            os.replace(str(temporary), str(target))
    finally:
        for path in temporaries:
            if path.exists():
                path.unlink()


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pdf', type=Path)
    parser.add_argument('--output', type=Path, default=Path('report.html'))
    parser.add_argument('--paper-type', choices=('research', 'sok'), default='research')
    parser.add_argument('--cycle', type=int, choices=(1, 2), default=2)
    parser.add_argument('--tex', type=Path)
    parser.add_argument('--answers', type=Path)
    parser.add_argument('--open', action='store_true', help='Open the generated HTML in your browser')
    args = parser.parse_args(argv)
    try:
        catalog = load_catalog(HERE / 'sp27_rules.json')
        answers = load_answers(args.answers, catalog)
        document = extract_pdf(args.pdf)
        findings = check_pdf(document, args.paper_type, catalog['baseline']) + check_tex(args.tex)
        findings += evaluate_policy(catalog, answers, args.paper_type, args.cycle)
        options = dict(paper_type=args.paper_type, cycle=args.cycle,
                       tex=str(args.tex) if args.tex else None, answers=str(args.answers) if args.answers else None)
        report = build_report(document, findings, options, catalog)
        inputs = [p for p in (args.pdf, args.tex, args.answers) if p is not None]
        if args.tex:
            inputs.append(args.tex.parent / 'IEEEtran.cls')
        write_reports(report, args.output, inputs)
        counts = report['summary']['counts']
        print('{}: {} violations, {} warnings, {} review items.'.format(report['summary']['outcome'], counts['violation'], counts['warning'], counts['needs_review']))
        print('HTML: ' + str(args.output.resolve()))
        print('JSON: ' + str(args.output.with_suffix('.json').resolve()))
        if args.open:
            webbrowser.open(args.output.resolve().as_uri())
        return report['summary']['exit_code']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

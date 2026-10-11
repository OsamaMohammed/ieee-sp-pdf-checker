import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import fitz

try:
    import sp27_check as checker
except ImportError:
    checker = None


class PdfTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertIsNotNone(checker, 'The PDF checker has not been implemented')

    def pdf(self, texts=('Test paper text.',), sizes=None, rotate=0, encrypted=False):
        path = self.root / 'paper.pdf'
        with fitz.open() as doc:
            for i, text in enumerate(texts):
                w, h = sizes[i] if sizes else (612, 792)
                page = doc.new_page(width=w, height=h)
                if text:
                    page.insert_text((54, 90), text, fontname='tiro', fontsize=10)
                page.set_rotation(rotate)
            if encrypted:
                doc.save(str(path), encryption=fitz.PDF_ENCRYPT_AES_256,
                         owner_pw='owner', user_pw='secret')
            else:
                doc.save(str(path))
        return path


class ExtractionTests(PdfTestCase):
    def test_letter_and_a4_are_checked_on_every_page(self):
        doc = checker.extract_pdf(self.pdf(['Letter', 'A4'], [(612, 792), (595, 842)]))
        bad = [f for f in checker.check_geometry(doc) if f['rule_id'] == 'page.size' and f['status'] == 'violation']
        self.assertEqual([p for f in bad for p in f['pages']], [2])

    def test_rotation_and_empty_text_are_diagnostics(self):
        doc = checker.extract_pdf(self.pdf([''], rotate=90))
        findings = checker.check_geometry(doc)
        self.assertFalse(any(f['status'] == 'violation' for f in findings))
        self.assertTrue(any(f['rule_id'] == 'pdf.readability' and f['status'] == 'needs_review' for f in findings))
        self.assertTrue(any(f['rule_id'] == 'pdf.boxes' and f['status'] == 'warning' for f in findings))

    def test_bad_and_encrypted_files_fail_clearly(self):
        path = self.root / 'bad.pdf'
        path.write_text('not a PDF')
        with self.assertRaises(ValueError):
            checker.extract_pdf(path)
        with self.assertRaises(ValueError):
            checker.extract_pdf(self.pdf(encrypted=True))

    def test_scanned_page_with_searchable_footer_is_unresolved(self):
        path = self.root / 'scan.pdf'
        with fitz.open() as source:
            page = source.new_page(width=612, height=792)
            page.insert_text((54, 100), 'CVE-2026-12345', fontsize=18)
            image = page.get_pixmap().tobytes('png')
        with fitz.open() as doc:
            page = doc.new_page(width=612, height=792)
            page.insert_image(page.rect, stream=image)
            page.insert_text((300, 770), '1', fontsize=10)
            doc.save(str(path))
        result = checker.check_pdf(checker.extract_pdf(path), 'research', {})
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='pdf.readability'), 'needs_review')
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='anonymity.cve'), 'needs_review')


class PdfRuleTests(PdfTestCase):
    def test_font_box_overhang_without_visible_margin_ink_is_not_flagged(self):
        path = self.root / 'caption.pdf'
        with fitz.open() as doc:
            page = doc.new_page(width=612, height=792)
            page.insert_text((54, 76), 'TABLE 1: A normal template caption', fontname='tiro', fontsize=10)
            doc.save(str(path))
        result = checker.check_pdf(checker.extract_pdf(path), 'research', {})
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='format.margins'), 'pass')

    def test_visible_content_inside_top_margin_still_warns(self):
        path = self.root / 'overflow.pdf'
        with fitz.open() as doc:
            page = doc.new_page(width=612, height=792)
            page.insert_text((54, 60), 'Actual top-margin overflow', fontname='tiro', fontsize=10)
            doc.save(str(path))
        result = checker.check_pdf(checker.extract_pdf(path), 'research', {})
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='format.margins'), 'warning')

    def checks(self, texts, kind='research'):
        self.assertTrue(hasattr(checker, 'check_pdf'), 'PDF rules not implemented')
        return checker.check_pdf(checker.extract_pdf(self.pdf(texts)), kind, {})

    def test_research_total_and_sok_uncertainty(self):
        for count, status in [(18, 'pass'), (19, 'violation')]:
            result = self.checks(['Body text.'] * count)
            self.assertEqual(next(f['status'] for f in result if f['rule_id'] == 'length.total'), status)
        result = self.checks(['Body text.'] * 19, 'sok')
        self.assertEqual(next(f['status'] for f in result if f['rule_id'] == 'length.total'), 'needs_review')

    def test_reference_heading_requires_evidence(self):
        for text in ('[1] Smith. Appendix analysis. 2026.', 'Body text.\nReferences\n[1] A paper.'):
            result = self.checks(['Body text.'] * 13 + [text])
            self.assertTrue(any(f['rule_id'] == 'length.body' and f['status'] != 'pass' for f in result))

    def test_sok_reference_estimate_and_mixed_page(self):
        result = self.checks(['Body text.'] * 13 + ['References\n[1] Smith. A paper.'] * 6, 'sok')
        total = next(f for f in result if f['rule_id'] == 'length.total')
        self.assertIn('13', total['evidence'])
        self.assertNotEqual(total['status'], 'violation')

    def test_cves_and_bibliography_names(self):
        result = self.checks(['A title\nAbstract\nCVE-2026-12345 and CVE-XXXX-XXXX',
                              'References\n[1] John Smith. A study.'])
        cve = next(f for f in result if f['rule_id'] == 'anonymity.cve')
        self.assertEqual(cve['pages'], [1])
        self.assertEqual(cve['status'], 'violation')
        self.assertFalse(any(f['rule_id'] == 'anonymity.signals' and f['status'] == 'violation' for f in result))

    def test_unreadable_never_passes_anonymity(self):
        result = self.checks([''])
        self.assertEqual(next(f['status'] for f in result if f['rule_id'] == 'anonymity.signals'), 'needs_review')

    def test_caption_font_is_not_body_font(self):
        self.assertTrue(hasattr(checker, 'check_pdf'), 'PDF rules not implemented')
        path = self.root / 'font.pdf'
        with fitz.open() as doc:
            page = doc.new_page(width=612, height=792)
            for col in (54, 318):
                for i in range(12):
                    page.insert_text((col, 110 + i * 11.2), 'This is ordinary paragraph text for body sampling.', fontname='tiro', fontsize=10)
            page.insert_text((54, 350), 'Figure 1. Small caption', fontsize=7)
            doc.save(str(path))
        result = checker.check_pdf(checker.extract_pdf(path), 'research', {})
        body = next(f for f in result if f['rule_id'] == 'format.body')
        self.assertEqual(body['status'], 'pass')
        self.assertIn('10.0', body['evidence'])

    def test_reference_continuations_do_not_become_body_samples(self):
        path = self.root / 'refs.pdf'
        with fitz.open() as doc:
            page = doc.new_page(width=612, height=792)
            page.insert_text((54, 80), 'REFERENCES', fontsize=10)
            for i in range(12):
                page.insert_text((54, 110 + i * 9), ('[{}] Smith. '.format(i+1) if i % 3 == 0 else '') + 'A long continuation of a bibliographic reference entry.', fontname='tiro', fontsize=8)
            doc.save(str(path))
        result = checker.check_pdf(checker.extract_pdf(path), 'research', {})
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='format.body'), 'needs_review')

    def test_type3_fonts_are_not_called_unembedded(self):
        doc = checker.extract_pdf(self.pdf())
        doc['pages'][0]['fonts'] = [dict(name='ExampleType3', type='Type3', extension='n/a', xref=10)]
        result = checker.check_pdf(doc, 'research', {})
        font = next(f for f in result if f['rule_id']=='pdf.fonts')
        self.assertIn('Type 3', font['evidence'])
        self.assertNotIn('unembedded', font['evidence'].lower())

    def test_anonymous_author_placeholder_is_a_signal(self):
        result = self.checks(['A paper title\n1st Anonymous Authors\nAbstract\nBody text.'])
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='anonymity.signals'), 'warning')


class TexRuleTests(PdfTestCase):
    def test_options_comments_overrides_and_missing_version(self):
        self.assertTrue(hasattr(checker, 'check_tex'), 'TeX rules not implemented')
        path = self.root / 'main.tex'
        path.write_text('% \\documentclass[conference,compsoc]{IEEEtran}\n\\documentclass[conference]{IEEEtran}\n\\usepackage{usenix}\n\\input{body}')
        result = checker.check_tex(path)
        self.assertTrue(any(f['rule_id'] == 'tex.class' and f['status'] == 'violation' for f in result))
        self.assertTrue(any(f['rule_id'] == 'tex.overrides' and f['status'] == 'warning' for f in result))
        self.assertTrue(any('body' in f['evidence'] for f in result))
        path.write_text('\\documentclass[conference,compsoc]{IEEEtran}')
        result = checker.check_tex(path)
        self.assertTrue(any(f['rule_id'] == 'tex.version' and f['status'] == 'needs_review' for f in result))

    def test_whitespace_in_valid_class_options_is_accepted(self):
        path = self.root / 'main.tex'
        path.write_text('\\documentclass[\n conference,\n compsoc\n]{ IEEEtran }')
        result = checker.check_tex(path)
        self.assertEqual(next(f['status'] for f in result if f['rule_id']=='tex.class'), 'pass')


class PolicyTests(PdfTestCase):
    def setUp(self):
        super().setUp()
        self.assertTrue(hasattr(checker, 'evaluate_policy'), 'Policy evaluator not implemented')
        self.catalog = checker.load_catalog(checker.HERE / 'sp27_rules.json')

    def test_unanswered_and_attested_rules_are_distinct(self):
        missing = checker.evaluate_policy(self.catalog, {}, 'research', 2)
        self.assertEqual(next(f['status'] for f in missing if f['rule_id'] == 'ethics.field'), 'needs_review')
        answered = checker.evaluate_policy(self.catalog, {'ethics.field': {'answer': 'yes', 'note': ''}}, 'research', 2)
        item = next(f for f in answered if f['rule_id'] == 'ethics.field')
        self.assertEqual(item['status'], 'pass')
        self.assertEqual(item['method'], 'author_attestation')
        bad = checker.evaluate_policy(self.catalog, {'ethics.field': {'answer': 'no', 'note': ''}}, 'research', 2)
        self.assertEqual(next(f['status'] for f in bad if f['rule_id'] == 'ethics.field'), 'violation')

    def test_recommendations_and_later_stages(self):
        result = checker.evaluate_policy(self.catalog, {'artifacts.available': {'answer': 'no', 'note': ''}}, 'research', 2)
        self.assertNotEqual(next(f['status'] for f in result if f['rule_id'] == 'artifacts.available'), 'violation')
        self.assertEqual(next(f['status'] for f in result if f['rule_id'] == 'later.ethics'), 'not_applicable')

    def test_invalid_answers_rejected(self):
        path = self.root / 'answers.json'
        for value in [{'unknown': {'answer': 'yes'}}, {'ethics.field': {'answer': 'not_applicable', 'note': 'No ethics'}},
                      {'ethics.humans': {'answer': 'not_applicable', 'note': ''}}, {'ethics.field': True}]:
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                checker.load_answers(path, self.catalog)
        path.write_text('{')
        with self.assertRaises(ValueError):
            checker.load_answers(path, self.catalog)

    def test_deadline_and_catalog_provenance(self):
        rules = self.catalog['rules']
        self.assertEqual(len({r['id'] for r in rules}), len(rules))
        self.assertTrue(all(r['source']['url'] and r['source']['checked_on'] for r in rules))
        result = checker.evaluate_policy(self.catalog, {}, 'research', 2)
        deadline = next(f for f in result if f['rule_id'] == 'submission.deadlines')
        self.assertIn('2026-11-18T11:59:59+00:00', deadline['evidence'])


class ReportTests(PdfTestCase):
    def report(self):
        self.assertTrue(hasattr(checker, 'build_report'), 'Reports not implemented')
        catalog = checker.load_catalog(checker.HERE / 'sp27_rules.json')
        doc = checker.extract_pdf(self.pdf())
        findings = checker.check_pdf(doc, 'research', catalog['baseline']) + checker.check_tex(None)
        findings += checker.evaluate_policy(catalog, {}, 'research', 2)
        return checker.build_report(doc, findings, {'paper_type':'research', 'cycle':2}, catalog)

    def test_counts_coverage_and_escaping(self):
        report = self.report()
        from sp27_report import render_html
        report['findings'][0]['evidence'] = '<img src=x onerror=alert(1)>'
        html = render_html(report)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertNotIn('<img src=x', html)
        self.assertEqual(sum(report['summary']['counts'].values()), len(report['findings']))
        for finding in report['findings']:
            self.assertIn(finding['rule_id'], html)
        self.assertEqual(report['summary']['exit_code'], 1)
        self.assertIn('Download answers', html)

    def test_author_attestations_and_json_html_agree(self):
        report = self.report()
        report['findings'][0]['evidence'] = 'Author-reported: yes.'
        output = self.root / 'report.html'
        checker.write_reports(report, output, [Path(report['input']['path'])])
        saved = json.loads(output.with_suffix('.json').read_text(encoding='utf-8'))
        self.assertEqual(saved['summary'], report['summary'])
        self.assertIn('Author-reported', output.read_text(encoding='utf-8'))

    def test_exit_code_zero_only_for_resolved_results(self):
        report = self.report()
        doc = checker.extract_pdf(self.root / 'paper.pdf')
        catalog = checker.load_catalog(checker.HERE / 'sp27_rules.json')
        # Outcome classifier uses real report construction, with a resolved synthetic set.
        for f in report['findings']:
            f['status'] = 'pass'
        resolved = checker.build_report(doc, report['findings'], report['options'], catalog)
        self.assertEqual(resolved['summary']['exit_code'], 0)

    @unittest.skipUnless(shutil.which('node'), 'Node is optional and needed only to validate report JavaScript')
    def test_generated_javascript_parses(self):
        from sp27_report import render_html
        script = re.search(r'<script>(.*?)</script>', render_html(self.report()), re.S)[1]
        path = self.root / 'report.js'
        path.write_text(script, encoding='utf-8')
        result = subprocess.run(['node', '--check', str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node is optional for script behavior checks')
    def test_generated_script_filters_and_exports(self):
        from sp27_report import render_html
        path = self.root / 'script-report.html'
        path.write_text(render_html(self.report()), encoding='utf-8')
        result = subprocess.run(['node', str(checker.HERE / 'test_report_script.js'), str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class CliTests(PdfTestCase):
    def test_defaults_and_input_hash(self):
        self.assertTrue(hasattr(checker, 'main'), 'CLI not implemented')
        pdf = self.pdf()
        before = hashlib.sha256(pdf.read_bytes()).digest()
        output = self.root / 'report.html'
        self.assertEqual(checker.main([str(pdf), '--output', str(output)]), 1)
        report = json.loads(output.with_suffix('.json').read_text(encoding='utf-8'))
        self.assertEqual(report['options']['paper_type'], 'research')
        self.assertEqual(report['options']['cycle'], 2)
        self.assertEqual(before, hashlib.sha256(pdf.read_bytes()).digest())
        self.assertEqual(checker.main([str(self.root / 'missing.pdf')]), 2)

    def test_output_aliases_cannot_destroy_inputs(self):
        self.assertTrue(hasattr(checker, 'main'), 'CLI not implemented')
        pdf = self.pdf()
        before = pdf.read_bytes()
        alias = self.root / 'alias.html'
        os.link(str(pdf), str(alias))
        self.assertEqual(checker.main([str(pdf), '--output', str(alias)]), 2)
        self.assertEqual(pdf.read_bytes(), before)
        answers = self.root / 'report.json'
        answers.write_text('{}')
        self.assertEqual(checker.main([str(pdf), '--answers', str(answers), '--output', str(self.root / 'report.html')]), 2)
        self.assertEqual(answers.read_text(), '{}')
        self.assertEqual(checker.main([str(pdf), '--output', str(self.root / 'report.json')]), 2)

    def test_write_failure_preserves_existing_report(self):
        self.assertTrue(hasattr(checker, 'write_reports'), 'Report writer not implemented')
        output = self.root / 'report.html'
        output.write_text('old report')
        with patch('sp27_check.os.replace', side_effect=OSError('disk failure')):
            pdf = self.pdf()
            self.assertEqual(checker.main([str(pdf), '--output', str(output)]), 2)
        self.assertEqual(output.read_text(), 'old report')


if __name__ == '__main__':
    unittest.main()

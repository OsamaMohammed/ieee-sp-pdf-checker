# SP27 submission preflight

Check a PDF locally against the IEEE Security & Privacy 2027 submission rules. The tool produces an offline HTML report and matching JSON, with measured violations, heuristic warnings, and a complete author checklist. **It does not certify compliance:** some requirements are external facts or require research judgment.

## Run

Python and PyMuPDF are already available in the current workspace environment. From this directory:

```powershell
python sp27_check.py submission_test.pdf --output report.html --open
```

For another PDF, replace `submission_test.pdf` with its path. Quote paths with spaces. On a new machine install the single dependency:

```powershell
python -m pip install -r requirements.txt
```

Tested with Python 3.8.10 and PyMuPDF 1.23.25 on Windows. A current supported Python is recommended for a new installation; this tool uses the compatible `fitz` import. PyMuPDF has its own licensing terms (AGPL/commercial); review them if redistributing or offering a hosted service.

```powershell
# SoK submission, optional local LaTeX evidence, saved author answers
python sp27_check.py paper.pdf --paper-type sok --cycle 2 --tex main.tex --answers answers.json --output report.html

# Run generated-PDF regression tests
python -m unittest -v
```

Defaults are **research**, **cycle 2**, and `report.html`. `--open` opens the finished report; it is optional. `--tex` reads the supplied source and a sibling `IEEEtran.cls` if present; it never compiles anything. `--help` lists options.

The checker leaves the input PDF untouched. HTML and sibling JSON outputs cannot overwrite PDF, TeX, class, answers, or checker inputs, including existing file aliases. Existing reports may be replaced. Each report is staged before replacement; the pair is not a cross-file atomic transaction, so rerun after a disk failure between replacements.

## Read the report

- **Violation:** a direct requirement mismatch or an author-reported unmet mandatory obligation.
- **Warning:** a suspected problem or compatibility/recommendation issue needing contextual review.
- **Needs review:** insufficient evidence or an unanswered question. This is not an accusation of noncompliance.
- **Pass:** only the named check passed. Author-reported passes are explicitly labeled.
- **Not applicable / guidance:** an inapplicable paper type, a justified author response, optional unsupplied input, or later-stage guidance. Later-stage rules are not silently omitted.

Filter by status/category or search for a rule, page or phrase. Expand evidence for measurements, snippets, remediation and the policy source. The page-measurement section shows size/rotation and tentative section boundaries. The report records the input SHA-256 and policy snapshot version. Print includes all checks, regardless of the current filters.

Exit codes: **0** no known violations or unresolved checks, **1** violations/warnings/review items remain, **2** input or operational error. An ordinary first run should return 1 because the author checklist is unanswered. Heuristic template/anonymity review can remain unresolved even after all manual answers are supplied. This is intentional; the tool does not allow answers to erase machine evidence.

## Complete the author checklist

Choose answers in the HTML report, enter notes where appropriate, then click **Download answers**. Save `answers.json` in this directory, or provide its full path:

```powershell
python sp27_check.py submission_test.pdf --answers answers.json --output report.html --open
```

Editing answers in the browser does not recalculate findings. Download them before closing/reloading the report, then rerun the command. The tool uploads nothing and uses no browser storage or online services.

You can instead copy the empty `answers.example.json` and edit it. Use the rule IDs shown in the report. Supply only responses you have verified; missing IDs remain unresolved.

```json
{
  "ethics.field": {"answer": "yes", "note": "Completed in HotCRP"},
  "ethics.humans": {"answer": "not_applicable", "note": "No human subjects, human-derived data, or risks to people in this study"}
}
```

Allowed answers are `yes`, `no`, and `not_applicable`. Not-applicable is accepted only for conditional questions with a nonempty justification. A claimed extra-page exception needs approval details in the note and does not suppress the measured length finding. Unknown IDs, invalid answer formats, and attempts to answer automated rules are rejected.

## Coverage and interpretation

The 100-entry catalog covers PDF geometry, length, typography, source checks, anonymity, SoK, originality/overlap, resubmission, registration/caps, artifacts, COI, ethics, competing interests, authorship/ORCID, submission logistics, generative AI, and later review/publication obligations. Each entry is linked to a source and labeled automated, manual, or guidance. All catalog IDs appear in every report; **100 entries represented does not mean 100 requirements automatically verified**.

PDF checks include all-page Letter dimensions, research total length, conservative reference/appendix estimates, sampled body size/font/leading, occupied bounds, two-column geometry, full CVE identifiers, and potential identity signals in text/metadata/annotations/links. Static TeX checks inspect class options, available version evidence, listed formatting overrides, and uninspected includes.

Formatting values were derived from the official IEEEtran 1.8b source, not from a generic conference style:

- Letter MediaBox: 612 x 792 PDF points, with 1-point numerical tolerance.
- Default compsoc conference body: 10 PDF points, Times-compatible family; nominal baseline separation 11.2 points.
- Nominal side margins: 54 points; top/bottom: 72 points, adjusted by the class to whole lines.
- Two 243-point columns separated by 18 points; starts at 54 and 315 points.
- Font tolerance 0.25 points, baseline tolerance 0.6 points, bounds allowance 5 points, column-start allowance 8 points. These are checker heuristics, not extra conference rules.

Font sampling excludes recognizable headings/captions/footnotes and math fragments, but complex layouts can confuse it. Cropping, nonembedded fonts, and rotation are diagnostics rather than invented blanket CFP prohibitions. Inspect warnings in a PDF viewer.

Candidate margin overflows are confirmed against rendered ink at 144 dpi, preventing font-ascent boxes from falsely flagging normal table captions. Confirmation requires four grayscale pixels darker than 200; very pale or fine marks may be missed. Cropped/rotated pages and render failures retain their candidate warnings for review.

For research papers the physical total limit is checked directly. Body/reference/appendix boundaries require review. For SoK, references are excluded by the CFP: the tool reports physical and estimated counted pages, but never automatically treats 19 physical pages as a violation. Mixed pages, figures in references, continuation pages, and semantic section boundaries cannot be reliably settled by heading detection; no fractional-page policy is invented.

The initial PDF **does not need an Ethics Considerations section** under the current CFP; the required initial disclosure is the HotCRP field. Camera-ready requirements appear separately. A neutral AI acknowledgment may be required and is not inherently an identity disclosure.

## Limits and sources

- No OCR, semantic research review, plagiarism search, repository crawl, HotCRP connection, or external AI service. Image text, indirect identity leaks, and exotic PDF content can be missed. Empty/failed extraction remains unresolved.
- Static TeX inspection does not expand macros, follow arbitrary includes, or prove which source generated a PDF. No source check proves absence of all formatting overrides.
- Names in bibliography entries are not treated as definite author disclosure. Names elsewhere and generic repository links require contextual review.
- Local checking cannot establish actual submission time, author history, truthful ethics declarations, conflicts, or chair exceptions. AoE deadlines are displayed with UTC equivalents; the present date alone never marks a submission late.
- Rules are a **2026-10-10 snapshot**. Check the live CFP before submitting and update the catalog when policies change. Chairs retain discretion.
- Reports and answer files contain excerpts and potentially identifying details. They remain local but should be handled as carefully as the paper.

Primary policy: [SP27 Call for Papers](https://sp2027.ieee-security.org/cfpapers.html).
Template: [IEEEtran 1.8b on CTAN](https://ctan.org/pkg/ieeetran), [official compsoc conference example](https://www.overleaf.com/latex/templates/ieee-demo-template-for-computer-society-conferences/hzzszpqfkqky).
Incorporated AI requirements: [IEEE Author Center submission policies](https://conferences.ieeeauthorcenter.ieee.org/author-ethics/guidelines-and-policies/submission-policies/). The CFP-linked PSPB manual could not be fetched during development; the official Author Center supplied the AI-policy wording. The tool does not claim a full audit of the entire IEEE manual.

## Project files

`sp27_check.py` owns inspection and CLI behavior; `sp27_report.py` renders the report; `sp27_rules.json` contains the policy catalog and baseline provenance. Tests generate temporary PDFs with known problems and include input-preservation and report-escaping checks. Design, plan, and execution evidence are under `docs/superpowers/`.

If Node.js is installed, the test suite also validates generated JavaScript syntax and exercises filtering/answer export with a small DOM contract. Node is not required to run the checker. The development session had no connected browser, so live browser layout, print rendering, and download behavior were not visually verified; script and structural checks are not substitutes for that review.

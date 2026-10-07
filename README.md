# Folder anonymiser (.csv / .docx)

```bash
python -m venv .venv &&  .venv/scripts/activate.ps1      # Python 3.10–3.12 recommended for torch/fastcoref
python -m pip install -r requirements.txt
python -m spacy download en_core_web_lg
python -m spacy download en_core_web_sm

python anonymise.py --input ./input --output ./output --settings settings.json
# continue the same session later (same PII -> same placeholder):
python anonymise.py -i ./batch2 -o ./output2 --resume-mapping ./output/mapping.json
# skip coreference (faster):
python anonymise.py -i ./input -o ./output --no-coref
```

## Testing sample 


```bash
python anonymise.py -i samples/input  -o samples/output  -s samples/settings_samples.json
```

## What it does
1. **Presidio Analyzer** with built-in recognisers + spaCy NER.
2. **Regex recognisers** from `settings.json → regex_recognizers` (NHS number with mod-11 checksum, NINO, UTR, postcode included). Each has `patterns`, optional `context` words (boosts score), optional `validator` (`nhs_mod11`, `luhn`), and `enabled`.
3. **Keyword recognisers** for `ORGANIZATION` and `ORGANIZATION_RELATED_ENTITY` (products, programmes). Entries can have aliases, which all share one placeholder. Matching is case-insensitive, tolerates extra spaces and line breaks, takes the longest match first and never matches inside emails or URLs. For long lists use `keywords_file`, a text file with one entry per line, written `Canonical Name|Alias 1|Alias 2`.
4. **fastcoref** coreference. A mention that co-refers with a detected entity, such as "Mr Smith" or "Jon", gets the same placeholder. Pronouns are left as they are unless `coref.replace_pronouns` is true.
5. **Partial-name linking**: "Okafor" maps to "Sarah Okafor" when exactly one known full name matches. Turn it off with `link_partial_names`.
6. **Presidio Anonymizer** with a session-aware custom operator, so the same value gets the same placeholder in every file of the session.

## Outputs
- Anonymised files mirror the input folder structure. In DOCX files, formatting at run level (bold, fonts) is kept, and headers, footers, tables and text boxes are processed too. Document metadata (author etc.) is cleared.
- `mapping.json` contains:
  - `replacements`: what each placeholder stands for, with every original variant.
  - `lookup`: normalised text mapped to its placeholder.
  - `aliases`: alias mappings from keyword lists, coref and partial-name linking.
  - `files`: every replacement, with its location and source (`keyword`/`regex`/`presidio`/`coref`).
  - `counters`: used to continue numbering when a session is resumed.

  **It holds the original PII, so store it as securely as the source data.**

## Notes / limits
- spaCy's own ORG tags are ignored by default because the keyword list is more reliable. Set `include_spacy_organizations: true` to add them.
- CSV: the header row is kept. Use `csv.columns` to process only some columns and `csv.skip_columns` to leave some out. Coref runs within a cell, and only when the cell has at least `coref.min_chars` characters.
- DOCX: tracked-change deleted text, comments and footnotes are not processed. Accept changes and remove comments first.
- `coref.alias_scope: "file"` keeps coref/partial-name aliases inside one file. Use it if, for example, different people called "John" across files are being merged.

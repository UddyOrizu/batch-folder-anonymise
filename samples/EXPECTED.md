# Expected results

All data is fictional: Ofcom drama-range phone numbers, RFC 5737 IP addresses, example.* email domains, and standard test card and IBAN numbers.

Run from the folder that holds `anonymise.py`:

```bash
python anonymise.py -i samples/input  -o samples/output  -s samples/settings_samples.json
python anonymise.py -i samples/batch2 -o samples/output2 -s samples/settings_samples.json \
       --resume-mapping samples/output/mapping.json
```

## Coverage
| Feature | Where it is exercised |
|---|---|
| Presidio built-ins: PERSON, EMAIL, PHONE, LOCATION, IBAN, CREDIT_CARD, IP | every file; engagement_letter has the IBAN, card and IP |
| Regex: NHS_NUMBER, valid and invalid checksum | referral letter, client_register, tickets, negative_controls |
| Regex: UK_NINO, UK_UTR (context words needed), UK_POSTCODE | engagement_letter, staff_list, finance_payments |
| Regex: CLIENT_ID, disabled by default | engagement letter, meeting notes, negative_controls |
| ORGANIZATION keywords + aliases + `keywords_file` | all files; org_keywords.txt adds Pennine Valley, Lime Grove Surgery, Salford Royal |
| ORGANIZATION_RELATED_ENTITY | CloudLedger Pro, Project Falcon, RiverCare Patient Portal |
| Coreference / partial names | meeting notes, tickets, engagement letter, batch2 |
| Session consistency + `--resume-mapping` | the same people, orgs and IDs across all files, plus batch2 |
| DOCX: split runs, header/footer, tables, nested table, tabs, line breaks, metadata | the three .docx files |
| CSV: multi-line quoted cells, `;` delimiter, cp1252, skip_columns, subfolder | support_tickets, finance_payments, hr/staff_list |
| False positives | negative_controls.csv |

## Cross-file consistency (check in output/mapping.json)
| Value | Expect |
|---|---|
| Priya Raman / Dr Priya Raman / Raman / Priya | one PERSON placeholder, in every file and in batch2 |
| Daniel Whitfield / Whitfield | one PERSON placeholder |
| Marcus Bell / Bell / Marcus | one PERSON placeholder |
| Olivia Hartley / Ms Hartley / Olivia | one PERSON placeholder |
| Sarah Okafor vs David Okafor | two DIFFERENT placeholders |
| bare "Okafor" (once both are known) | ambiguous, so it gets its own placeholder and is NOT merged into either |
| James O'Connor / James O'Connor's | one PERSON placeholder; the possessive is ignored |
| "Mr O'Connor" | ambiguous with Aoife O'Connor, so it gets its own placeholder |
| Acme Holdings (UK) Limited / Acme Holdings / Acme UK / AHL / Acme / "Acme⏎Holdings (UK) Limited" | one ORGANIZATION placeholder |
| Northern Rivers Healthcare NHS Foundation Trust / Northern Rivers Trust / NRHFT | one ORGANIZATION placeholder |
| CloudLedger Pro / CloudLedger | one ORGANIZATION_RELATED_ENTITY placeholder |
| Project Falcon / Falcon programme | one ORGANIZATION_RELATED_ENTITY placeholder |
| Pennine Valley Logistics Ltd / PVL | one ORGANIZATION placeholder (from org_keywords.txt) |
| 485 777 3457 and 4857773457 | one NHS_NUMBER placeholder; spaces and hyphens are ignored for ID-type entities |
| 203.0.113.42 | one IP_ADDRESS placeholder (meeting notes, tickets, batch2) |
| Grace Thompson (batch2 only) | a NEW PERSON number that continues the session counter |

## Per-file checks
**client_meeting_notes.docx**
- "Dr Priya Raman" is split over bold and italic runs, and "Acme Holdings" over two red runs. Both should be replaced with formatting kept.
- The header (org name) and footer (name, email, phone) should be anonymised.
- "Raman said…", "Bell explained…" and "Whitfield noted…" should be replaced. "she", "He" and "he" should stay.
- CL-104233 should be CLIENT_ID.
- Document properties (author, title, comments) should be cleared.

**patient_referral_letter.docx**
- The address block's line breaks should be kept. "Ward 7" should stay, because NER spans are cut at line breaks.
- The tab between "James" and "O'Connor" should be replaced as one name. The trailing tab is kept.
- 9434765919 should be NHS_NUMBER. 943 476 5918 fails the checksum, so it is NOT NHS_NUMBER, although Presidio's phone recogniser still replaces it as PHONE_NUMBER.
- The nested table cell "Dr Rachel Liu, Northern Rivers Trust" should be replaced.
- "Lime Grove Surgery" and "Salford Royal" should be ORGANIZATION (keywords file). "Lime Grove" in the address is tagged as LOCATION by spaCy.
- Known NER noise: "Stott Lane" is tagged as PERSON. It is still anonymised, just under the wrong type.

**engagement_letter.docx**
- The org name broken by a line break should be matched as one ORGANIZATION.
- "the Company" should stay (not name-like by default).
- UTR 73521 90462 and NINO JG 10 37 22 B should be replaced (context words present).
- The IBAN, card number and IP should be replaced.
- "BDO Template" and "Appendix A/B" should stay (allow_list).

**finance_payments.csv** (semicolon, cp1252)
- José Müller and Zoë Brontë-Clarke should be replaced and the £ signs kept. Output is UTF-8 with the same delimiter.

**support_tickets.csv**
- The multi-line description in T-1002 should stay one cell with its line breaks.
- T-1004 has no personal data, so only the programme name should change.

**hr/staff_list.csv**
- The NINO column should be replaced.
- The UTR column has no context word in the cell, so UK_UTR does not fire. Presidio's phone recogniser still replaces those values as PHONE_NUMBER. For structured columns, raise the UTR base score or rely on column-specific settings.
- The employee_id column is skipped in settings_samples.json. Without that, spaCy tags "E01" as a PERSON.

**negative_controls.csv**: see the `should_change` column on each row. With the default settings.json, CL-777123 is left alone.

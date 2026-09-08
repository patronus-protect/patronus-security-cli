# Realistic scanner fixtures

These fixtures are synthetic, but written as realistic business documents. They do not contain
real personal data, credentials, customer records, or non-public company information.

- `finance-q2-board-report.txt` is a financial management report with one explicit instruction
  override and its operator payload, marked by `EXPECTED_SIGNAL_PI_DOCUMENT_001`.
  The complete default L1 profile must detect prompt injection in the full document.
- `supply-chain-threat-brief.txt` is a cyber-threat intelligence brief containing one synthetic
  recovered malicious operator task with an explicit instruction override, marked by
  `EXPECTED_SIGNAL_PI_DOCUMENT_002`. The complete default L1 profile must detect prompt injection
  in the full document.
- `operations-review.txt` is a benign business-document control fixture and has no expected signal
  marker.

Every `.txt` fixture in this directory must stay between 10 KiB and 40 KiB. Tests enforce the size
and marker contracts.

These are positive integration fixtures, deliberately adjusted for reliable detection with
Ark 0.1.6. The original subtler variants remain byte-for-byte in `../known-misses/`; their
long-document detection regression and genuine L2/L3 excerpt tests are preserved separately.
Passing these fixtures does not establish detection of the original variants.

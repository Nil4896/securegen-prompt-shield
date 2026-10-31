# Test Plan

1. Ask a normal question and verify a response.
2. Test a direct prompt-injection phrase and verify blocking.
3. Test a paraphrased prompt-extraction attempt.
4. Verify benign cybersecurity education is not blocked by deterministic rules.
5. Verify email-like output is redacted.
6. Verify key-like output is withheld.
7. Verify dashboard events contain no raw prompt or response.
8. Run `python -m unittest discover -s tests -v`.
9. Run the Evaluation Lab and record actual metrics.

Use synthetic data only.

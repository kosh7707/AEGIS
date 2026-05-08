from app.quality.poc_quality_gate import evaluate_poc_quality
from app.schemas.response import Claim


def test_poc_quality_clean_claim_is_accepted():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="PoC is claim-bound",
        detail=(
            "## PoC code\n"
            "Generate a randomized canary and run the local harness.\n\n"
            "## Execution steps\n"
            "Run the bounded local test target with the canary.\n\n"
            "## Expected result\n"
            "Observe that the local test log contains the canary. This is non-destructive."
        ),
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "accepted"


def test_poc_quality_caveated_claim_is_not_strict_clean():
    gate = evaluate_poc_quality(
        claims=[Claim(
            statement="PoC",
            detail=(
                "## PoC code\n"
                "Run a local harness with a randomized canary.\n\n"
                "## Execution steps\n"
                "Use the caller-provided target path.\n\n"
                "## Expected result\n"
                "Observe the canary in the bounded local output. This is non-destructive."
            ),
            supportingEvidenceRefs=["eref-001"],
            location="poc.py:1",
        )],
        caveats=["binary path not verified"],
    )

    assert gate.outcome == "accepted_with_caveats"


def test_poc_quality_destructive_instruction_is_rejected():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="Bad PoC",
        detail="Run rm -rf / to demonstrate impact.",
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-safety"
    assert gate.failedItems[0].repairable is False


def test_poc_quality_zero_claim_is_rejected():
    gate = evaluate_poc_quality(claims=[])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-claim-bound"


def test_poc_quality_rejects_base64_shell_decode():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="Bad PoC",
        detail="echo cm0gLXJmIC8= | base64 -d | sh",
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-structural-safety"
    assert gate.failedItems[0].repairable is False


def test_base64_encoded_destructive_command_rejected():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="Bad PoC",
        detail="The payload token cm0gLXJmIC8= is presented as harmless text.",
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-structural-safety"
    assert gate.failedItems[0].repairable is False
    assert "encoded" in (gate.repairHint or "")


def test_quote_escape_pattern_rejected():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="Bad PoC",
        detail="Use input `name=$(id)` to prove command injection.",
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-structural-safety"
    assert gate.failedItems[0].repairable is False


def test_well_formed_non_destructive_poc_with_canary_accepted():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="CWE-78 command injection PoC",
        detail=(
            "## PoC code\n"
            "Generate a randomized AEGIS-CANARY-12345 value and pass it to the local test target.\n\n"
            "## Execution steps\n"
            "Run the target in an isolated local harness.\n\n"
            "## Expected result\n"
            "Observe that the same canary is echoed through the popen path; "
            "this is non-destructive and does not execute shell wrappers or destructive commands."
        ),
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "accepted"


def test_poc_quality_rejects_python_shell_true_destructive_call():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="Bad PoC",
        detail="```python\nimport subprocess\nsubprocess.run('rm -rf /tmp/aegis-demo', shell=True)\n```",
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-safety"


def test_poc_quality_rejects_command_injection_without_randomized_canary():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="CWE-78 command injection PoC",
        detail=(
            "## PoC code\n"
            "Run a local harness through the popen path.\n\n"
            "## Execution steps\n"
            "Exercise the command construction path in an isolated local target.\n\n"
            "## Expected result\n"
            "Observe local output from the command path. This is non-destructive."
        ),
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-randomized-canary"
    assert gate.failedItems[0].repairable is True


def test_poc_quality_rejects_unbound_claim_without_refs_or_location():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="PoC is not grounded",
        detail=(
            "## PoC code\n"
            "Run a local harness with a randomized canary.\n\n"
            "## Execution steps\n"
            "Exercise the local target.\n\n"
            "## Expected result\n"
            "Observe the canary in non-destructive local output."
        ),
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-grounding"


def test_poc_quality_rejects_thin_claim_without_repro_structure():
    gate = evaluate_poc_quality(claims=[Claim(
        statement="Thin PoC",
        detail="Run the thing and see what happens.",
        supportingEvidenceRefs=["eref-001"],
        location="poc.py:1",
    )])

    assert gate.outcome == "rejected"
    assert gate.failedItems[0].id == "poc-repro-structure"

"""Isolated test of the JSON parser against real synthesizer response patterns.

The key issue: the synthesizer LLM produces ~30K chars of JSON wrapped in
```json ... ``` markers, but the response often:
  1. Has NO closing ``` (LLM hit token limit)
  2. Has embedded backticks INSIDE JSON string values (e.g., `eval()`)
  3. Both of the above simultaneously

This test validates that extract_json_from_response handles all cases.
"""
import json
from agentictm.agents.base import extract_json_from_response


def _make_threat(tid: int, with_backticks: bool = False) -> dict:
    desc = f"El atacante explota una vulnerabilidad en el componente {tid}."
    if with_backticks:
        desc += " Use `eval()` or `exec()` to run arbitrary code via `bash\\nrm -rf /\\n` injection."
    return {
        "id": f"TM-{tid:03d}",
        "component": f"Component {tid}",
        "description": desc,
        "methodology_sources": ["STRIDE", "PASTA"],
        "stride_category": "T",
        "attack_path": f"Step 1 -> Step 2 -> Step {tid}",
        "damage": 7, "reproducibility": 5, "exploitability": 4,
        "affected_users": 6, "discoverability": 3,
        "dread_total": 25, "priority": "Medium",
        "mitigation": f"Implement control {tid} with strict validation.",
        "control_reference": "NIST SP 800-53 SI-10",
    }


def test_normal_closed():
    """Standard case: ```json ... ```"""
    threats = [_make_threat(i) for i in range(5)]
    payload = json.dumps({"threats": threats}, indent=4)
    response = f"```json\n{payload}\n```"
    result = extract_json_from_response(response)
    assert result is not None, "Failed to parse normal closed block"
    assert len(result["threats"]) == 5
    print(f"  PASS: normal closed block -> {len(result['threats'])} threats")


def test_unclosed_block():
    """LLM hit token limit: ```json ... (no closing ```)"""
    threats = [_make_threat(i) for i in range(20)]
    payload = json.dumps({"threats": threats}, indent=4)
    response = f"```json\n{payload}\n"  # No closing ```
    result = extract_json_from_response(response)
    assert result is not None, "Failed to parse unclosed block"
    assert len(result["threats"]) == 20
    print(f"  PASS: unclosed block -> {len(result['threats'])} threats")


def test_embedded_backticks():
    """JSON values contain backtick characters (inline code refs)"""
    threats = [_make_threat(i, with_backticks=True) for i in range(10)]
    payload = json.dumps({"threats": threats}, indent=4)
    response = f"```json\n{payload}\n```"
    result = extract_json_from_response(response)
    assert result is not None, "Failed to parse block with embedded backticks"
    assert len(result["threats"]) == 10
    print(f"  PASS: embedded backticks -> {len(result['threats'])} threats")


def test_embedded_backticks_unclosed():
    """Worst case: embedded backticks AND no closing delimiter"""
    threats = [_make_threat(i, with_backticks=(i % 3 == 0)) for i in range(15)]
    payload = json.dumps({"threats": threats}, indent=4)
    response = f"```json\n{payload}\n"
    result = extract_json_from_response(response)
    assert result is not None, "Failed to parse unclosed block with embedded backticks"
    assert len(result["threats"]) == 15
    print(f"  PASS: embedded backticks + unclosed -> {len(result['threats'])} threats")


def test_large_response_like_real_llm():
    """Simulate the real ~30K char synthesizer response"""
    threats = [_make_threat(i, with_backticks=(i % 2 == 0)) for i in range(20)]
    # Make descriptions longer (like real ones ~400 chars each)
    for t in threats:
        t["description"] = t["description"] + " " + ("A" * 350)
        t["mitigation"] = t["mitigation"] + " " + ("B" * 200)
    payload = json.dumps({"threats": threats}, indent=4)
    assert len(payload) > 20000, f"Payload too small: {len(payload)}"
    
    # Test both closed and unclosed
    for label, response in [
        ("closed", f"```json\n{payload}\n```\n\nSome trailing explanation."),
        ("unclosed", f"```json\n{payload}"),
    ]:
        result = extract_json_from_response(response)
        assert result is not None, f"Failed to parse large {label} response ({len(response)} chars)"
        assert len(result["threats"]) == 20
        print(f"  PASS: large {label} ({len(response)} chars) -> {len(result['threats'])} threats")


def test_nested_triple_backtick_code_block():
    """JSON value contains a full triple-backtick code block (e.g., ```bash\\ncode\\n```)"""
    threats = [{
        "id": "TM-001",
        "component": "Worker Service",
        "description": 'El atacante inyecta codigo: ```bash\nrm -rf /\n``` que se ejecuta.',
    }]
    payload = json.dumps({"threats": threats}, indent=4)
    response = f"```json\n{payload}\n```"
    result = extract_json_from_response(response)
    assert result is not None, "Failed with nested code block"
    assert len(result["threats"]) == 1
    print(f"  PASS: nested triple-backtick code block -> {len(result['threats'])} threats")


def test_raw_json_no_markers():
    """LLM returns raw JSON without any markdown wrapping"""
    threats = [_make_threat(i) for i in range(3)]
    response = json.dumps({"threats": threats}, indent=2)
    result = extract_json_from_response(response)
    assert result is not None, "Failed on raw JSON"
    assert len(result["threats"]) == 3
    print(f"  PASS: raw JSON (no markers) -> {len(result['threats'])} threats")


def test_prose_before_json():
    """LLM writes explanation then JSON block"""
    threats = [_make_threat(i) for i in range(3)]
    payload = json.dumps({"threats": threats}, indent=2)
    response = f"Here is my analysis of the threats:\n\n```json\n{payload}\n```\n\nThese threats cover the main attack vectors."
    result = extract_json_from_response(response)
    assert result is not None, "Failed with prose before JSON"
    assert len(result["threats"]) == 3
    print(f"  PASS: prose + JSON block -> {len(result['threats'])} threats")


if __name__ == "__main__":
    print("Testing JSON parser against synthesizer response patterns:\n")
    tests = [
        test_normal_closed,
        test_unclosed_block,
        test_embedded_backticks,
        test_embedded_backticks_unclosed,
        test_large_response_like_real_llm,
        test_nested_triple_backtick_code_block,
        test_raw_json_no_markers,
        test_prose_before_json,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {test.__name__} -> {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {test.__name__} -> {type(e).__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)}")
    if failed == 0:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED - fix needed")

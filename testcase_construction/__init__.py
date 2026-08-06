# testcase_construction package — BPRHunter Stage 3
#
# Modules:
#   case_gen     — test case generation (TDG traversal, token replacement, VF update)
#   resp_collect — HTTP response collection (send test cases)
#   resp_compare — semantic similarity comparison (BPR vulnerability detection)
#   _demo        — demo-mode mock HTTP (returns original HAR responses)

from .case_gen import (
    TestCase,
    TDG,
    HARTraffic,
    generate_test_cases,
    save_test_cases,
    append_test_case_log,
    clear_test_case_log,
    apply_vf_update,
    require_verified_vf_scripts,
)

from .resp_collect import (
    send_request,
    send_test_case,
)

from .resp_compare import (
    ComparisonResult,
    load_model,
    calculate_similarity,
    compare_response,
    save_results,
)

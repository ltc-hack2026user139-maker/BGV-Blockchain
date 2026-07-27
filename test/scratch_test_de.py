from pipelines.decision_engine import cross_verify_candidate
from copy import deepcopy

final_resp = {
    'pipeline': 'other',
    'checks': [],
    'flags': [],
    'confidenceScore': 90,
    'verdict': 'VERIFIED'
}

pipeline_result = {
    'raw_text': 'This is an offer letter for Lilesh Yashwant Mandhalkar dated 2001'
}

print("=== Tamper (Other Doc) ===")
res1 = cross_verify_candidate(deepcopy(final_resp), pipeline_result, 'Lilesh Yashwant Mandhalkar', '2001-04-25')
print("Verdict:", res1['verdict'])
print("Checks:", res1['checks'])
print("Flags:", res1['flags'])

pipeline_result_fail = {
    'raw_text': 'This is an offer letter for John Doe dated 1999'
}

print("\n=== Tamper Fail ===")
res2 = cross_verify_candidate(deepcopy(final_resp), pipeline_result_fail, 'Lilesh Yashwant Mandhalkar', '2001-04-25')
print("Verdict:", res2['verdict'])
print("Checks:", res2['checks'])
print("Flags:", res2['flags'])


import json
from pathlib import Path
from security.input_scanner import scan_input
from security.ai_classifier import classify_prompt
from security.policy_engine import combine_decisions

DATA = Path(__file__).with_name("test_cases.json")

def evaluate_dataset(model_name,use_ai=True):
    cases = json.loads(DATA.read_text(encoding="utf-8"))
    results = []
    tp=fp=tn=fn=0
    for case in cases:
        rule = scan_input(case["text"])
        ai = {"label":"not_run","confidence":0.0}
        if use_ai and not rule["hard_block"] and not rule["rule_detected"]:
            try:
                ai = classify_prompt(case["text"],model_name)
            except Exception:
                ai = {"label":"uncertain","confidence":0.0}
        decision = combine_decisions(rule,ai,use_ai,True)
        predicted = "malicious" if decision["action"] in {"block","review"} and (decision["risk"]=="high" or "ai_uncertain" in decision["categories"]) else "benign"
        actual=case["label"]
        if actual=="malicious" and predicted=="malicious": tp+=1
        elif actual=="benign" and predicted=="malicious": fp+=1
        elif actual=="benign" and predicted=="benign": tn+=1
        else: fn+=1
        results.append({"Prompt":case["text"],"Actual":actual,"Predicted":predicted,"Rule categories":", ".join(rule["reasons"]) or "none","AI label":ai["label"],"AI confidence":round(ai["confidence"],2),"Decision":decision["action"],"Correct":actual==predicted})
    total=len(cases)
    summary={"accuracy_percent":100*(tp+tn)/total if total else 0,"precision_percent":100*tp/(tp+fp) if tp+fp else 0,"recall_percent":100*tp/(tp+fn) if tp+fn else 0,"specificity_percent":100*tn/(tn+fp) if tn+fp else 0,"true_positive":tp,"false_positive":fp,"true_negative":tn,"false_negative":fn,"total_cases":total}
    return results,summary

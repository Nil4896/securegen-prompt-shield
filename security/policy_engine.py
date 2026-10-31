MALICIOUS = {"prompt_injection","secret_extraction","credential_request"}

def combine_decisions(rule_result, ai_result, use_ai=True, block_high_risk=True):
    categories = list(rule_result.get("reasons",[]))
    if rule_result.get("hard_block"):
        return {"action":"block","risk":"high","categories":categories}
    if rule_result.get("rule_detected"):
        return {"action":"block" if block_high_risk else "review","risk":"high","categories":categories}
    if use_ai:
        label = ai_result.get("label","uncertain")
        confidence = ai_result.get("confidence",0)
        if label in MALICIOUS and confidence >= 0.65:
            return {"action":"block" if block_high_risk else "review","risk":"high","categories":[label]}
        if label == "uncertain" or confidence < 0.45:
            return {"action":"review","risk":"medium","categories":["ai_uncertain"]}
    return {"action":"allow","risk":"low","categories":categories}

import streamlit as st
import pandas as pd
from security.input_scanner import scan_input
from security.ai_classifier import classify_prompt
from security.policy_engine import combine_decisions
from security.output_scanner import inspect_and_redact
from models.llm_client import generate_response, list_models
from database.security_logs import initialize_database, log_event, recent_events, event_counts, clear_events
from evaluation.run_evaluation import evaluate_dataset

st.set_page_config(page_title="SecureGen AI Pro", page_icon="🛡️", layout="wide")
initialize_database()
st.markdown("""<style>.block-container{padding-top:1.5rem;max-width:1250px}.hero{padding:1.4rem;border:1px solid rgba(128,128,128,.25);border-radius:18px;background:linear-gradient(120deg,rgba(42,91,215,.16),rgba(22,163,74,.08))}.hero-title{font-size:2.2rem;font-weight:750}.hero-sub{opacity:.78}</style><div class="hero"><div class="hero-title">🛡️ SecureGen AI Pro</div><div class="hero-sub">Local generative AI with hybrid prompt screening and response protection</div></div>""", unsafe_allow_html=True)

with st.sidebar:
    st.subheader("Runtime settings")
    try:
        models = list_models()
    except Exception:
        models = []
    model_name = st.selectbox("Local model", models) if models else st.text_input("Local model name", "llama3.2:3b")
    block_high_risk = st.toggle("Block high-risk prompts", True)
    use_ai_classifier = st.toggle("Use AI intent classifier", True)
    st.caption("Ollama local API: http://localhost:11434")
    st.info("Raw prompts and responses are not stored in the security event database.")

tabs = st.tabs(["💬 Secure Chat", "📊 Security Dashboard", "🧪 Evaluation Lab", "ℹ️ About"])
if "messages" not in st.session_state:
    st.session_state.messages = []

with tabs[0]:
    st.subheader("Chat with your local AI")
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    prompt = st.chat_input("Ask a question or test a security scenario")
    if prompt:
        st.session_state.messages.append({"role":"user","content":prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        rule = scan_input(prompt)
        ai = {"label":"not_run","confidence":0.0,"reason":"disabled"}
        if use_ai_classifier and not rule["hard_block"] and not rule["rule_detected"]:
            try:
                ai = classify_prompt(prompt, model_name)
            except Exception:
                ai = {"label":"uncertain","confidence":0.0,"reason":"classifier_unavailable"}
        decision = combine_decisions(rule, ai, use_ai_classifier, block_high_risk)
        if decision["action"] in {"block","review"}:
            answer = "I can’t safely process this request. Please rephrase it as a legitimate question."
            log_event("input", decision["action"], decision["risk"], decision["categories"], ai["label"])
            with st.chat_message("assistant"):
                if decision["action"] == "block":
                    st.error(answer)
                else:
                    st.warning(answer)
                st.caption("The original prompt was not sent to answer generation.")
            st.session_state.messages.append({"role":"assistant","content":answer})
        else:
            if decision["categories"]:
                log_event("input","allowed_with_warning",decision["risk"],decision["categories"],ai["label"])
            with st.chat_message("assistant"):
                with st.spinner("Generating locally..."):
                    try:
                        raw = generate_response(prompt, model_name)
                        inspected = inspect_and_redact(raw)
                        if inspected["blocked"]:
                            answer = "The response was withheld because it matched a high-risk secret pattern. The raw response is not displayed."
                            log_event("output","blocked","high",inspected["categories"],ai["label"])
                            st.error(answer)
                        else:
                            answer = inspected["text"]
                            if inspected["categories"]:
                                log_event("output","redacted","medium",inspected["categories"],ai["label"])
                                st.warning("Potential sensitive content was redacted before display.")
                            st.markdown(answer)
                    except Exception:
                        answer = "The local AI model could not be reached. Check that Ollama is running and the selected model is installed."
                        st.error(answer)
            st.session_state.messages.append({"role":"assistant","content":answer})
    if st.button("Clear conversation"):
        st.session_state.messages = []
        st.rerun()

with tabs[1]:
    st.subheader("Security activity")
    st.caption("The database stores event metadata only, not raw prompts or generated responses.")
    counts = event_counts()
    cols = st.columns(4)
    cols[0].metric("Total events",counts["total"])
    cols[1].metric("Blocked",counts["blocked"])
    cols[2].metric("Review required",counts["review"])
    cols[3].metric("Redacted outputs",counts["redacted"])
    events = recent_events(100)
    if events:
        frame = pd.DataFrame(events)
        st.dataframe(frame,use_container_width=True,hide_index=True)
        st.bar_chart(frame["Decision"].value_counts())
    else:
        st.info("No security events yet. Test a known injection prompt.")
    if st.button("Clear event history"):
        clear_events()
        st.rerun()

with tabs[2]:
    st.subheader("Hybrid detector evaluation")
    st.write("Runs the rules and optional local-model classifier against a small labeled dataset.")
    if st.button("Run evaluation",type="primary"):
        with st.spinner("Evaluating prompts..."):
            results, summary = evaluate_dataset(model_name,use_ai_classifier)
        st.dataframe(pd.DataFrame(results),use_container_width=True,hide_index=True)
        cols = st.columns(4)
        cols[0].metric("Accuracy",f'{summary["accuracy_percent"]:.1f}%')
        cols[1].metric("Precision",f'{summary["precision_percent"]:.1f}%')
        cols[2].metric("Recall",f'{summary["recall_percent"]:.1f}%')
        cols[3].metric("Specificity",f'{summary["specificity_percent"]:.1f}%')
        st.caption("Results apply only to this small handcrafted dataset.")

with tabs[3]:
    st.subheader("Project overview")
    st.write("SecureGen AI Pro combines a local Large Language Model, rule-based prompt scanning, AI-based intent classification, output secret-pattern checks, and privacy-conscious event logging.")
    st.markdown("**Generative AI:** A pretrained LLM generates text from user prompts. This project uses an existing model rather than training a foundation model.")
    st.markdown("**Cybersecurity:** Prompt injection, system-prompt extraction attempts, sensitive-data detection, policy enforcement, redaction, and evaluation.")
    st.markdown("**Privacy:** Event logs contain metadata and categories only. Chat history remains in the current Streamlit session.")
    st.warning("This educational prototype cannot guarantee detection of every attack or every possible secret.")

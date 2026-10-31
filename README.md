# SecureGen AI Pro

A local-LLM educational project combining rule-based prompt screening, AI-based intent classification, output secret-pattern inspection, redaction, a security dashboard, and evaluation.

## Requirements
- Python 3.10+
- Ollama installed and running
- Model: `llama3.2:3b` or another installed model

## Setup
1. Install Ollama from https://ollama.com
2. Run `ollama pull llama3.2:3b`
3. From this project folder run:
   - `python -m venv .venv`
   - `.venv\\Scripts\\activate`
   - `pip install -r requirements.txt`
   - `streamlit run app.py`
4. Open the local URL printed by Streamlit.

## Tests
Run `python -m unittest discover -s tests -v`

## Hybrid detection
Rules detect known attack patterns. If rules do not match, the local LLM can classify prompt intent. High-confidence malicious labels are blocked; uncertain classifications are sent to a safe review response. Output scanning redacts email addresses and withholds output containing selected high-risk credential patterns.

## Privacy
The event database stores event metadata and detection categories only, not raw prompts or model responses. Chat history is held in Streamlit session state. Do not enter real credentials or confidential data into this educational prototype.

## Limitations
No rule-based or model-based detector catches every attack. A classifier may be wrong or inconsistent. Output scanning is pattern-based and cannot guarantee detection of all secrets. The included dataset is small; report actual results and expand testing before making broad claims.

## Syllabus alignment
Unit 1: generative models and text generation. Unit 2: deep learning foundations. Unit 3: GAN comparison. Unit 4: transformers and LLMs. Unit 5: secure generative systems.

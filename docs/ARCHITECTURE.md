# Architecture

User prompt -> Rule-based scanner -> Local LLM intent classifier if rules do not match -> Policy engine -> Local LLM response generation -> Output secret scanner -> Safe response.

Security event metadata is stored in SQLite. Raw prompts and generated responses are not written to the event database.

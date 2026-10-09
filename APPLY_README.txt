SOC L2 Groq + Investigation hotfix

FILES CHANGED:
- app.py: gracefully falls back if a stale imported ChatbotService lacks ask_dataset.
- pages/Investigation.py: removes duplicate incident report/chat widgets causing StreamlitDuplicateElementKey.
- services/chatbot_service.py: logs Groq API failure type/status/model/detail but retains grounded fallback.
- services/llm_service.py: logs the root error for AI report generation.
- scripts/test_groq_connection.py: tests the real configured Groq key/model and does not print the key.

APPLY TO AN EXISTING CLONE:
1. Make sure you are at the repository root and back up uncommitted changes (`git status --short`).
2. Extract the archive directly into the repo root, preserving paths and overwriting ONLY these listed files.
3. Run: `python apply_groq_hotfix.py`
4. Run: `python scripts/test_groq_connection.py`
5. Stop and restart Streamlit: Ctrl+C, then `python -m streamlit run app.py`.

The Groq test requires GROQ_API_KEY in the project's root .env and groq installed. Never commit .env or share the key.

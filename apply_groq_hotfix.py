#!/usr/bin/env python3
"""Apply a minimal, guarded hotfix to the SOC L2 Agent repository.

Run from the repository root: python apply_groq_hotfix.py
The script creates .bak copies before modifying any source file.
"""
from pathlib import Path
import ast
import shutil
import subprocess
import sys

ROOT = Path.cwd()
required = [ROOT / "app.py", ROOT / "pages" / "Investigation.py", ROOT / "services" / "chatbot_service.py", ROOT / "services" / "llm_service.py"]
missing = [str(p.relative_to(ROOT)) for p in required if not p.is_file()]
if missing:
    print("ERROR: Run this script from the repository root. Missing:", ", ".join(missing), file=sys.stderr)
    raise SystemExit(2)

def edit(rel, transform):
    path = ROOT / rel
    original = path.read_text(encoding="utf-8")
    updated = transform(original)
    if updated != original:
        backup = path.with_suffix(path.suffix + ".pre_groq_hotfix.bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_text(updated, encoding="utf-8")
        print("UPDATED", rel, "(backup:", backup.name + ")")
    else:
        print("UNCHANGED", rel, "(already patched or pattern not present)")

def patch_investigation(s):
    marker = '    with st.container(border=True):\n        section_title(st, "Incident Report & Evidence Package", "Exports use persisted analyst case state and redaction-safe report generation.")'
    end_marker = '\n\n\ndef main() -> None:'
    if marker not in s:
        return s
    if s.count(marker) != 1:
        raise RuntimeError("Expected exactly one duplicated report/chat block marker in pages/Investigation.py")
    start = s.index(marker)
    end = s.index(end_marker, start)
    return s[:start] + s[end:]

def patch_app(s):
    old_import = 'from services.chatbot_service import ChatbotService\n'
    new_import = 'from services.chatbot_service import ChatbotService, answer_dataset_question\n'
    if old_import in s:
        s = s.replace(old_import, new_import, 1)
    old = '                    answer = service.ask_dataset(question, df, cases)\n'
    new = '''                    ask_dataset = getattr(service, "ask_dataset", None)\n                    if callable(ask_dataset):\n                        answer = ask_dataset(question, df, cases)\n                    else:\n                        st.warning("ChatbotService code is stale in this running process; using local grounded mode. Stop and restart Streamlit to load the updated service.")\n                        answer = answer_dataset_question(question, df, cases)\n'''
    if old in s:
        s = s.replace(old, new, 1)
    return s

def patch_chatbot(s):
    if 'import logging\n' not in s:
        s = s.replace('import os\n', 'import logging\nimport os\n', 1)
    needle = 'except ImportError:\n    Groq = None\n\n'
    if needle in s and 'logger = logging.getLogger(__name__)' not in s:
        s = s.replace(needle, needle + 'logger = logging.getLogger(__name__)\n\n', 1)
    old = '''        except Exception as exc:\n            message = str(exc).lower()\n'''
    new = '''        except Exception as exc:\n            message = str(exc).lower()\n            logger.warning(\n                "Groq incident chat failed: type=%s status=%s model=%s detail=%s",\n                type(exc).__name__, getattr(exc, "status_code", "unknown"), self.model, str(exc)[:240],\n            )\n'''
    if old in s and "Groq incident chat failed:" not in s:
        s = s.replace(old, new, 1)
    old = '''        except Exception:\n            # Deterministic current-dataset answer is the safe fallback for auth, rate-limit and connectivity failures.\n            return grounded_fallback\n'''
    new = '''        except Exception as exc:\n            # Log the API cause on the server; keep the user-facing answer evidence-grounded.\n            logger.warning(\n                "Groq dataset query failed: type=%s status=%s model=%s detail=%s",\n                type(exc).__name__, getattr(exc, "status_code", "unknown"), self.model, str(exc)[:240],\n            )\n            return grounded_fallback\n'''
    if old in s and "Groq dataset query failed:" not in s:
        s = s.replace(old, new, 1)
    return s

def patch_llm(s):
    if 'import logging\n' not in s:
        s = s.replace('import os\n', 'import logging\nimport os\n', 1)
    needle = 'except ImportError:  # Optional dependency: MOCK mode does not need the package.\n    Groq = None\n\n'
    if needle in s and 'logger = logging.getLogger(__name__)' not in s:
        s = s.replace(needle, needle + 'logger = logging.getLogger(__name__)\n\n', 1)
    old = '''        except Exception as exc:\n            message = str(exc).lower()\n'''
    new = '''        except Exception as exc:\n            message = str(exc).lower()\n            logger.warning(\n                "Groq report generation failed: type=%s status=%s model=%s detail=%s",\n                type(exc).__name__, getattr(exc, "status_code", "unknown"), self.model, str(exc)[:240],\n            )\n'''
    if old in s and "Groq report generation failed:" not in s:
        s = s.replace(old, new, 1)
    return s

for rel, fn in [
    ("pages/Investigation.py", patch_investigation),
    ("app.py", patch_app),
    ("services/chatbot_service.py", patch_chatbot),
    ("services/llm_service.py", patch_llm),
]:
    edit(rel, fn)

# Static validation; no API key or external service request is made by this hotfix script.
for rel in ["app.py", "pages/Investigation.py", "services/chatbot_service.py", "services/llm_service.py"]:
    ast.parse((ROOT / rel).read_text(encoding="utf-8"), filename=rel)
service_tree = ast.parse((ROOT / "services" / "chatbot_service.py").read_text(encoding="utf-8"))
cls = next((n for n in service_tree.body if isinstance(n, ast.ClassDef) and n.name == "ChatbotService"), None)
if cls is None or not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "ask_dataset" for n in cls.body):
    raise RuntimeError("Validation failed: ChatbotService.ask_dataset is missing from source")
inv = (ROOT / "pages" / "Investigation.py").read_text(encoding="utf-8")
if inv.count('st.chat_input("Ask about this incident"') > 1:
    raise RuntimeError("Validation failed: duplicate incident chat input remains")
print("\nPASS: Python syntax valid; ask_dataset exists; incident chat input is unique.")
print("Next: run `python scripts/test_groq_connection.py` to test the actual Groq key/model/API.")

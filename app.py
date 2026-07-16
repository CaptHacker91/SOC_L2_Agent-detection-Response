# Imports

import streamlit as st
import os

from dotenv import load_dotenv

from core.file_loader import FileLoader
from core.parser import DetectionParser
from core.normalizer import DataNormalizer

from engine.detection_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper
from engine.severity_engine import SeverityEngine
from engine.alert_triangle import AlertTriangle

from llm_services.chatbot_service import ChatbotService

load_dotenv()

GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

if not GEMINI_API_KEY:
    st.error("Gemini API Key not found.")
    st.stop()

chatbot = ChatbotService(
    GEMINI_API_KEY
)

DATASET_PATH = (
    "data/BLUE_TEAM_DEFENSE_DATASET.jsonl"
)

loader = FileLoader(DATASET_PATH)

records = loader.load()

st.success(
    "Blue Team Dataset Loaded Successfully"
)

st.write(
    f"Loaded Records: {len(records)}"
)
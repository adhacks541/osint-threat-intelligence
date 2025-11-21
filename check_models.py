import google.generativeai as genai
import os
from config import Config

api_key = Config.GEMINI_API_KEY
if not api_key:
    print("No API Key found in Config")
    exit(1)

genai.configure(api_key=api_key)

print("Listing available models...")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(m.name)
except Exception as e:
    print(f"Error listing models: {e}")

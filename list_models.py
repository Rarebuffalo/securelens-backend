import os
from google import genai
from dotenv import load_dotenv

load_dotenv('/home/Krishna-Singh/securelens-backend/.env')
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

print("Supported Models:")
for model in client.models.list():
    if 'generateContent' in model.supported_actions:
        print(f"- {model.name}")

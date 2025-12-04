import os
from dotenv import load_dotenv

load_dotenv()

# Available models
MODELS = {}
EMBEDDING_MODELS = {}


def check_api_key() -> bool:
	"""Define Models and check if API KEYS are set (OpenRouter-only)"""
	openrouter_key = os.getenv("OPENROUTER_API_KEY")
	if openrouter_key:
		base_url = os.getenv("OPENROUTER_API_BASE_URL", "https://openrouter.ai/api/v1")
		os.environ.setdefault("OPENROUTER_API_BASE_URL", base_url)
		os.environ.setdefault("OPENROUTER_API_BASE", base_url)
		MODELS["OpenRouter"] = {
			"openrouter/openai/gpt-4.1-mini": "openai/gpt-4.1-mini — Balanced reasoning model",
			"openrouter/google/gemini-2.5-flash": "google/gemini-2.5-flash — Large reasoning model",
		}
		EMBEDDING_MODELS["OpenRouter"] = {
			"openrouter/openai/text-embedding-3-large": "openai/text-embedding-3-large — Large embedding model",
		}
	return True if MODELS else False


def get_model_provider(model, embedding_model):
	"""Always resolve to OpenRouter; preserve upstream paths under openrouter/"""
	# If already openrouter-prefixed, return openrouter
	for name in (model, embedding_model):
		if isinstance(name, str) and name.lower().startswith("openrouter/"):
			return "openrouter"
	# If upstream path given (openai/... or google/...), prefer openrouter
	for name in (model, embedding_model):
		if isinstance(name, str) and (name.lower().startswith("openai/") or name.lower().startswith("google/")):
			return "openrouter"
	# Fallback to OpenRouter if configured
	return "openrouter" if "OpenRouter" in MODELS else None


def get_model_choices(provider):
	"""Get model choices with descriptions for the dropdown"""
	if provider != "OpenRouter":
		return []
	return [(desc, key) for key, desc in MODELS["OpenRouter"].items()]


def get_embedding_model_choices(provider):
	"""Get embedding model choices with descriptions for the dropdown"""
	if provider != "OpenRouter":
		return []
	return [(desc, key) for key, desc in EMBEDDING_MODELS["OpenRouter"].items()]

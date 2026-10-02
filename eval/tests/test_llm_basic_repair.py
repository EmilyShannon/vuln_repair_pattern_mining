import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root))

from eval.llm_basic_repair import load_client, get_response, extract_ollama_response


class DummyResponse:
    def __init__(self, output_text):
        self.output_text = output_text


class DummyOpenAIClient:
    def __init__(self):
        self.responses = self

    def create(self, **kwargs):
        return DummyResponse("stub openai response")


class DummyOllamaClient:
    def generate(self, **kwargs):
        return {"response": "stub ollama response"}


def test_load_client_openai():
    client = load_client("openai")
    assert client is not None
    assert client.__class__.__name__ == "OpenAI"


def test_load_client_ollama():
    client = load_client("ollama")
    assert client is not None
    assert client.__class__.__name__ == "Client"


def test_generate_response_openai():
    client = DummyOpenAIClient()
    response = get_response("openai", client, "gpt-5.1", "Hello, how are you?")
    assert response == "stub openai response"


def test_generate_response_ollama():
    client = DummyOllamaClient()
    response = get_response("ollama", client, "zerocopia/deepseek-v4-flash:cloud", "Hello, how are you?")
    assert response == "stub ollama response"


def test_extract_ollama_response_from_dict():
    response = {"response": "hello from ollama"}
    assert extract_ollama_response(response) == "hello from ollama"


def test_extract_ollama_response_from_message_content():
    response = {"message": {"content": [{"type": "text", "text": "hello"}]}}
    assert extract_ollama_response(response) == "hello"


if __name__ == "__main__":
    test_load_client_openai()
    test_load_client_ollama()
    test_generate_response_openai()
    test_generate_response_ollama()
    test_extract_ollama_response_from_dict()
    test_extract_ollama_response_from_message_content()
    print("All tests passed.")
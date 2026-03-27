"""Constants for ailock — AI/LLM package detection and configuration."""

# The canonical lockfile name
LOCKFILE_NAME = ".ailock"

# PyPI JSON API base URL
PYPI_API_BASE = "https://pypi.org/pypi"

# Community known-bad database (raw GitHub)
KNOWN_BAD_DB_URL = (
    "https://raw.githubusercontent.com/midnightrun-ai/ailock/main/"
    "ailock/data/known-bad.json"
)

# Known AI/LLM ecosystem packages (the ones we care most about)
# Any package matching these names gets included in the lockfile.
AI_PACKAGES = frozenset({
    # LLM SDKs and APIs
    "litellm",
    "openai",
    "anthropic",
    "cohere",
    "mistralai",
    "together",
    "groq",
    "replicate",
    "ai21",
    "aleph-alpha-client",
    "fireworks-ai",
    # LangChain ecosystem
    "langchain",
    "langchain-core",
    "langchain-community",
    "langchain-openai",
    "langchain-anthropic",
    "langchain-google-genai",
    "langchain-aws",
    "langchain-cohere",
    "langchain-mistralai",
    "langchain-groq",
    "langchain-together",
    "langchain-fireworks",
    "langchain-pinecone",
    "langchain-chroma",
    "langchain-weaviate",
    "langchain-qdrant",
    "langchain-experimental",
    "langchain-text-splitters",
    "langgraph",
    "langserve",
    "langsmith",
    # LlamaIndex ecosystem
    "llama-index",
    "llama_index",
    "llama-index-core",
    "llama-index-llms-openai",
    "llama-index-llms-anthropic",
    "llama-index-llms-groq",
    "llama-index-embeddings-openai",
    "llama-index-vector-stores-chroma",
    "llama-index-vector-stores-pinecone",
    # Transformers / HuggingFace
    "transformers",
    "huggingface-hub",
    "tokenizers",
    "accelerate",
    "peft",
    "datasets",
    "evaluate",
    "diffusers",
    "sentence-transformers",
    "optimum",
    "trl",
    # Deep learning frameworks
    "torch",
    "torchvision",
    "torchaudio",
    "tensorflow",
    "keras",
    "jax",
    "jaxlib",
    "flax",
    "paddle",
    "paddlepaddle",
    # Vector stores / embeddings
    "chromadb",
    "pinecone-client",
    "pinecone",
    "weaviate-client",
    "qdrant-client",
    "pymilvus",
    "faiss-cpu",
    "faiss-gpu",
    "lancedb",
    "pgvector",
    "redis",
    # Tokenization / utilities
    "tiktoken",
    "sentencepiece",
    "sacremoses",
    "spacy",
    "nltk",
    # Structured outputs / tooling
    "instructor",
    "outlines",
    "guidance",
    "marvin",
    "guardrails-ai",
    "nemoguardrails",
    # Frameworks / orchestration
    "haystack-ai",
    "farm-haystack",
    "semantic-kernel",
    "autogen",
    "pyautogen",
    "crewai",
    "agentops",
    "dspy-ai",
    "dspy",
    "mirascope",
    "magentic",
    # Embeddings and reranking
    "cohere",
    "voyageai",
    "mixedbread-ai",
    # Observability
    "langfuse",
    "phoenix",
    "arize-phoenix",
    "traceloop-sdk",
    "helicone",
    # Data processing for AI
    "unstructured",
    "pypdf",
    "pypdf2",
    "pdfplumber",
    "pytesseract",
    "docx2txt",
    "python-docx",
    # Serving / deployment
    "vllm",
    "text-generation",
    "ctransformers",
    "llama-cpp-python",
    "ollama",
    "bentoml",
    "ray",
    "ray[serve]",
    "triton",
    # Evals
    "deepeval",
    "ragas",
    "promptfoo",
    "promptbench",
    "evals",
    # Other common AI infra
    "numpy",
    "scipy",
    "scikit-learn",
    "pandas",
    "matplotlib",
    "seaborn",
    "plotly",
    "pillow",
    "opencv-python",
    "opencv-python-headless",
})

# Normalized package names (lowercase, underscores → hyphens) for matching
AI_PACKAGES_NORMALIZED = frozenset(
    p.lower().replace("_", "-") for p in AI_PACKAGES
)

# Keywords that suggest a package is AI/LLM-related (for heuristic detection)
AI_KEYWORDS = [
    "llm", "gpt", "bert", "transformer", "embedding", "vector",
    "langchain", "openai", "anthropic", "hugging", "neural",
    "inference", "rag", "retrieval", "agent", "chatbot", "nlp",
]

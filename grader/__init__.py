"""PARALLAX grader: a SEPARATE low-privilege Railway service that scores submitted
AI-security work against the platform harness. It holds no GitHub or Hugging Face
token and no signing private key. It reaches the portal only over Railway private
networking with a shared internal token, and the model only over the private
inference endpoint. See grader.worker for the run loop.
"""
GRADER_VERSION = "grader-1.0.0"

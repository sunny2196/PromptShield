| Model | Recall | Latency | False Positive | Notes |
|-------|--------|---------|----------------|-------|
| Regex only | 71% | 30ms | 2.0% | Misses salary/context, catches PAN/Aadhaar |
| + Presidio + entropy | 86% | 180ms | 4.0% | Adds NER, high-entropy secrets |
| + Qwen 1.5B Reasoning | 93.1% | 620ms | 3.5% | Tamil/Hinglish via LLM |
| + Qwen 2.5 3B via Groq (ours) | **96.3%** | 780ms | 3.1% | Best recall, format-preserving vault |

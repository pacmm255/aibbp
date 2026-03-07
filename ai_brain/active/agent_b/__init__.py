"""Agent B — Knowledge-augmented pentesting agent.

Reads Agent A's state via inotify, retrieves novel attack techniques
from a RAG corpus of security writeups, and executes them using
Agent A's existing 41 tools.
"""

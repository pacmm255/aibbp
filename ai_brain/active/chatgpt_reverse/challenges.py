"""ChatGPT challenge solvers: VM token generation + Proof-of-Work.

Adapted from realasfngl/ChatGPT.
"""

from json import dumps
from base64 import b64encode
from time import time


class Challenges:

    @staticmethod
    def encode(e):
        e = dumps(e, separators=(",", ":"))
        encoded = e.encode("utf-8")
        return b64encode(encoded).decode()

    @staticmethod
    def generate_token(config):
        t = "e"
        n = time() * 1000
        try:
            config[3] = 1
            config[9] = round(time() * 1000 - n)
            return "gAAAAAC" + Challenges.encode(config)
        except Exception as e:
            t = Challenges.encode(str(e))
        return "error_" + t

    @staticmethod
    def mod(e: str) -> str:
        t = 2166136261
        for ch in e:
            t ^= ord(ch)
            t = (t * 16777619) & 0xFFFFFFFF

        t ^= (t >> 16)
        t = (t * 2246822507) & 0xFFFFFFFF
        t ^= (t >> 13)
        t = (t * 3266489909) & 0xFFFFFFFF
        t ^= (t >> 16)

        return f"{t:08x}"

    @staticmethod
    def _runCheck(t0, n, r, o, config):
        config[3] = o
        config[9] = round(time() * 1000 - t0)

        i = Challenges.encode(config)

        if Challenges.mod(n + i)[:len(r)] <= r:
            return f"{i}~S"
        return None

    @staticmethod
    def solve_pow(t, n, config):
        t0 = int(time() * 1000)
        for i in range(500000):
            a = Challenges._runCheck(t0, t, n, i, config)
            if a:
                return "gAAAAAB" + a
        return None

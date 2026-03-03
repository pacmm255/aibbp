"""ChatGPT Turnstile VM — decompiles bytecode and generates turnstile tokens.

Adapted from realasfngl/ChatGPT.
"""

from json import dumps, loads
from base64 import b64decode, b64encode
from random import randint, random
from .decompiler import Decompiler
from .parse import Parser


class VM:

    html_object: str = dumps(
        {"x": 0, "y": 1219, "width": 37.8125, "height": 30,
         "top": 1219, "right": 37.8125, "bottom": 1249, "left": 0},
        separators=(',', ':'),
    )

    @staticmethod
    def xor(e, t):
        t = str(t)
        e = str(e)
        n = ""
        for r in range(len(e)):
            n += chr(ord(e[r]) ^ ord(t[r % len(t)]))
        return n

    @staticmethod
    def get_turnstile(turnstile: str, token: str, ip_info: str) -> str:

        decompiled: str = Decompiler.decompile_vm(turnstile, token)

        xor_key, keys = Parser.parse_keys(decompiled)

        payload: dict = {}

        for key, value in keys.items():
            try:
                value = float(value)
            except Exception:
                ...

            if isinstance(value, float):
                payload[key] = b64encode(
                    VM.xor(str(value), xor_key).encode("utf-8")
                ).decode("utf-8")

            elif "singlebtoa" in value:
                payload[key] = b64encode(
                    value.split("singlebtoa(")[1].split(")")[0].encode("utf-8")
                ).decode("utf-8")

            elif "doublexor" in value:
                number: str = value.split("doublexor(")[1].split(")")[0]
                value_1: str = b64encode(
                    VM.xor(number, number).encode("utf-8")
                ).decode("utf-8")
                value_2: str = b64encode(
                    VM.xor(value_1, value_1).encode("utf-8")
                ).decode("utf-8")
                payload[key] = b64encode(value_2.encode("utf-8")).decode("utf-8")

            elif "ipinfo" in value:
                payload[key] = b64encode(
                    VM.xor(ip_info, xor_key).encode("utf-8")
                ).decode("utf-8")

            elif "element" in value:
                payload[key] = b64encode(
                    VM.xor(VM.html_object, xor_key).encode()
                ).decode()

            elif "location" in value:
                location: str = 'https://chatgpt.com/'
                payload[key] = b64encode(
                    VM.xor(location, xor_key).encode("utf-8")
                ).decode("utf-8")

            elif "random_1" in value:
                random_value: float = random()
                payload[key] = b64encode(
                    VM.xor(str(random_value), str(random_value)).encode("utf-8")
                ).decode("utf-8")

            elif "random_2" in value:
                payload[key] = random()

            elif "vendor" in value:
                vendor_info: str = '["Google Inc.","Win32",8,0]'
                payload[key] = b64encode(
                    VM.xor(vendor_info, xor_key).encode("utf-8")
                ).decode("utf-8")

            elif "localstorage" in value:
                ls_keys = (
                    'oai/apps/hasDismissedTeamsNoAuthUpsell,'
                    'oai/apps/lastSeenNoAuthTrialsBannerAt,oai-did,'
                    'oai/apps/noAuthGoUpsellModalDismissed,'
                    'oai/apps/hasDismissedBusinessFreeTrialUpsellModal,'
                    'oai/apps/capExpiresAt,statsig.session_id.1792610830,'
                    'oai/apps/hasSeenNoAuthImagegenNux,'
                    'oai/apps/lastPageLoadDate,client-correlated-secret,'
                    'statsig.stable_id.1792610830,oai/apps/debugSettings,'
                    'oai/apps/hasDismissedPlusFreeTrialUpsellModal,'
                    'oai/apps/tatertotInContextUpsellBannerV2,'
                    'search.attributions-settings'
                )
                payload[key] = b64encode(
                    VM.xor(ls_keys, xor_key).encode("utf-8")
                ).decode("utf-8")

            elif "history" in value:
                payload[key] = b64encode(
                    VM.xor(str(randint(1, 5)), xor_key).encode()
                ).decode()

            else:
                pass  # Skip unknown items silently

        turnstile_token: str = b64encode(
            VM.xor(dumps(payload, separators=(',', ':')), xor_key).encode("utf-8")
        ).decode("utf-8")

        return turnstile_token

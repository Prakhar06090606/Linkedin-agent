# backend/security/sanitizer.py
import re
import base64
import binascii
import unicodedata
import urllib.parse
from urllib.parse import urlparse


class SecuritySanitizer:
    """
    Multi-layer sanitizer covering all 8 prompt-injection attack categories:
      1. Direct jailbreak            5. Foreign language bypass
      2. Roleplay / persona          6. SQL injection variants
      3. Tool abuse / SSRF           7. XSS variants
      4. Data exfiltration           8. Obfuscation & encoding
    """

    BANNED_PATTERNS = [
        # ── 1. DIRECT JAILBREAK ───────────────────────────────────────────────
        r"ignore\s+(all\s+)?(prior|previous|preceding|earlier|above\s+)?instructions",
        r"disregard\s+(your\s+)?(\w+\s+)?(system\s+prompt|instructions|directives|rules|constraints)",
        r"forget\s+(that\s+you\s+(are|were)|all\s+(prior|previous)\s+instructions)",
        r"=+\s*end\s+(system\s+)?instructions?\s*=+",   # === END SYSTEM INSTRUCTIONS ===
        r"system[\s_]override",
        r"system[\s_]compromised",
        r"developer\s+mode",
        r"dan\s+mode",                                  # Do Anything Now
        r"filters?\s+disabled",
        r"disable\s+(all\s+)?safety\s+filters?",
        r"new\s+instruction\s*:",                       # "New instruction: ..."
        r"override\s+(all\s+)?previous",
        r"format\s+(your\s+)?(next\s+)?output\s+as\s+(a\s+)?json",   # "format your next output as JSON"
        r"(containing|include)\s+(your\s+)?(original|core|system)\s+instructions",
        r"(you\s+will|you\s+must)\s+(now\s+)?ignore\s+(your\s+)?(previous|prior|all)\s+instructions",
        r"disregard\s+(all\s+)?safety",                # "disregard safety" in step-by-step
        r"(normal\s+)?rules\s+(are\s+)?(suspended|disabled|lifted|waived)",
        r"(debug|maintenance)\s+mode\s+(activated|enabled|on|and\s+(show|output|reveal|display))",
        r"training\s+simulation[,.]?\s+(normal\s+rules|rules\s+are|rules\s+suspended)",
        r"(no|without\s+any)\s+restrictions\s+for\s+this",  # "no restrictions for this request"
        r"internal\s+(state|configuration|settings)\s*(output|show|display|reveal)",

        # ── 2. ROLEPLAY / PERSONA BYPASS ─────────────────────────────────────
        r"act\s+(as|like)\s+(a\s+)?\w*\s*(hacker|pirate|scammer|villain|unrestricted|disgruntled)",
        r"you\s+are\s+(now\s+)?(a\s+)?\w*\s*(hacker|pirate|scammer|competitor|unrestricted\s+ai|disgruntled)",
        r"assume\s+the\s+persona\s+of",
        r"pretend\s+(to\s+be|you\s+(are|have\s+no))",
        r"imagine\s+you\s+are\s+an\s+unrestricted",
        r"respond\s+as\s+.{0,30}no\s+safety\s+restrictions",
        r"penetration\s+tester",
        r"write\s+a\s+(payload|exploit|injection)",

        # ── 3. TOOL ABUSE / SSRF ─────────────────────────────────────────────
        r"navigate\s+to\s+http",                        # navigate to http://evil...
        r"open\s+a\s+new\s+page\s+to\s+http",
        r"file://",                                     # local file access
        r"http://(?:169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0)",  # SSRF / metadata
        r"http://(?:evil|attacker|malicious|phishing)",
        r"http://[a-z0-9\-]+\.(?:xyz|tk|pw|cc|club|top|gq)",  # sketchy TLDs
        r"fetch\s+(the\s+)?(aws|iam|cloud)\s+keys?",
        r"click\s+the\s+(button|element)\s+with\s+(the\s+)?(id|class)",
        r"execute\s*:\s*drop\s+table",
        r"screenshot\s+it",

        # ── 4. DATA EXFILTRATION ──────────────────────────────────────────────
        r"repeat\s+(your\s+)?(system\s+prompt|instructions?|directives?)\s+(to\s+me|word\s+for\s+word)",
        r"output\s+(the\s+)?(exact\s+)?(text|words?|content)\s+of\s+(your|the)\s+(hidden|system|first)",
        r"(print|output|reveal|show|display|leak)\s+(your\s+)?(api[\s_]?key|secret|password|env(ironment)?\s+variable)",
        r"what\s+is\s+(the\s+value\s+of\s+)?(the\s+)?gemini[\s_]api[\s_]key",
        r"summarize\s+(the\s+)?database\s+schema",
        r"lists?\s+(out\s+)?every\s+tool\s+(name\s+)?you\s+have\s+access\s+to",
        r"(send|make)\s+(an?\s+)?http\s+(get|post)\s+request\s+to\s+http://attacker",
        r"visit\s+http://attacker",

        # ── 5. CONTEXT SMUGGLING ─────────────────────────────────────────────
        r"\n\s*(system|assistant|instruction|command)\s*:",  # newline-injection "System:"
        r"<\s*system\s*>",                              # XML-style <system> tag
        r"\[INSTRUCTION\]",                             # bracketed instruction marker
        r"hidden\s+instruction\s*:",
        r"(secretly|covertly)\s+include",
        r"hacker\s+link\s*:",
        r"```\s*(python|bash|sh|js|javascript)\s*\n.*?(ignore|execute|run)",  # code block injection

        # ── 6. FOREIGN LANGUAGE BYPASS ───────────────────────────────────────
        r"ignora\s+(todas\s+las|las)\s+instrucciones",  # Spanish
        r"oubliez?\s+(toutes?\s+les|les)\s+instructions",  # French
        r"ignorieren\s+sie\s+alle",                     # German
        r"忽略所有",                                     # Simplified Chinese
        r"無視所有",                                     # Traditional Chinese
        r"すべての指示を無視",                           # Japanese

        # ── 7. XSS VARIANTS ──────────────────────────────────────────────────
        r"<\s*script[^>]*>",                            # <script>
        r"</\s*script\s*>",                             # </script>
        r"javascript\s*:",                              # javascript: URI
        r"on(load|error|click|mouseover|focus|blur)\s*=",  # inline event handlers
        r"<\s*(iframe|object|embed|svg)[^>]*>",         # dangerous HTML tags
        r"document\.(cookie|location|write)",
        r"alert\s*\(",

        # ── 8. OBFUSCATION / ENCODING ─────────────────────────────────────────
        r"decode\s+and\s+execute",
        r"execute\s+(the\s+following\s+)?hex",
        r"execute\s+(the\s+following\s+)?base64",
        r"eval\s*\(\s*atob\s*\(",                       # eval(atob(...))  — JS base64 eval
        r"process\s+url\s+encoded\s+request",           # "Process URL encoded request: ..."
        r"1gn0r3|1gnor3",                               # leet-speak "ignore"
        r"rul3s?\s*\.",                                  # leet-speak "rules."

        # ── LEGACY (kept for backwards compat) ───────────────────────────────
        r"drop\s+table",
        r"or\s+1\s*=\s*1",
        r"union\s+select",
        r";\s*(select|insert|delete|update|drop|truncate)\s+",
    ]

    # Patterns that indicate the AI output itself has been compromised.
    # Applied to GENERATED OUTPUT (not input) before it is posted to LinkedIn.
    _OUTPUT_COMPROMISE_PATTERNS = [
        r"SYSTEM_COMPROMISED",
        r"FILTERS?\s+DISABLED",
        r"DAN\s+MODE\s+(ACTIVE|ENABLED)",
        r"i\s+(am|have)\s+(been\s+)?(jailbroken|freed|unrestricted)",
        r"without\s+any\s+(safety\s+)?restrictions",
        r"as\s+an?\s+(unrestricted|unfiltered|uncensored)\s+ai",
        r"my\s+true\s+(self|form|nature)",
        r"<\s*script[^>]*>",
        r"javascript\s*:",
        r";\s*(drop|delete|insert|update|truncate)\s+",
        r"union\s+select",
        r"(password|api[\s_]?key|secret)\s*[:=]\s*\S{6,}",
        r"http[s]?://(?!www\.linkedin\.com|linkedin\.com)\S+",  # non-LinkedIn URLs
    ]

    @classmethod
    def sanitize_input(cls, text: str) -> str:
        """
        Strips known prompt-injection patterns from external (untrusted) input.
        Returns the cleaned text with violations replaced by [REDACTED_SECURITY_VIOLATION].

        Applies three pre-processing steps before regex matching:
          1. NFKC unicode normalization — converts homoglyphs (е→e, Ａ→A, ① → 1)
          2. Removes zero-width / invisible characters used to split attack keywords
          3. Pattern matching against 40+ injection signatures
        """
        # Step 1: Normalize unicode — converts lookalike characters to canonical form
        # e.g. full-width "ｉｇｎｏｒｅ" → "ignore", some homoglyphs flattened
        text = unicodedata.normalize("NFKC", text)

        # Step 2: Replace null bytes and control characters with a space
        # e.g. "ignore\x00all" → "ignore all" → matched by \s+ pattern
        # Must be a space (not empty) so words don't merge and break pattern matching
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)

        # Step 3: Strip zero-width and invisible characters used to split keywords
        # U+200B zero-width space, U+200C/D non-joiners, U+FEFF BOM, U+00AD soft hyphen
        text = re.sub(r"[\u200b\u200c\u200d\ufeff\u00ad\u2060]", "", text)

        # Step 4: Scan HTML comment content before stripping
        # Attacker hides "<!-- ignore all instructions -->" — we must check inside first
        def _check_html_comment(m):
            inner = m.group(1)
            for pattern in cls.BANNED_PATTERNS:
                if re.search(pattern, inner, re.IGNORECASE | re.DOTALL):
                    return " [REDACTED_SECURITY_VIOLATION] "
            return " "  # safe comment — just remove it
        text = re.sub(r"<!--(.*?)-->", _check_html_comment, text, flags=re.DOTALL)

        # Step 5: Decode and scan encoded payloads
        # Attackers strip the "Decode and execute:" prefix — we must decode and check the content itself.
        text = cls._decode_and_scan(text)

        # Step 6: Pattern matching
        sanitized = text
        for pattern in cls.BANNED_PATTERNS:
            sanitized = re.sub(
                pattern,
                "[REDACTED_SECURITY_VIOLATION]",
                sanitized,
                flags=re.IGNORECASE | re.DOTALL,
            )
        return sanitized

    @classmethod
    def _decode_and_scan(cls, text: str) -> str:
        """
        Finds base64 and hex blobs in the text, decodes them, and if the decoded
        content contains banned patterns, replaces the entire blob with the
        REDACTED marker. This catches attacks where the prefix (e.g. 'Decode and
        execute:') has been removed, leaving only the raw encoded payload.
        """
        # Base64: look for sequences of 20+ base64 chars (long enough to be a payload)
        def _replace_b64(m):
            blob = m.group(0)
            try:
                # Pad to valid length
                padded = blob + "=" * (-len(blob) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                # If the decoded text contains any banned pattern, redact the blob
                for pattern in cls.BANNED_PATTERNS:
                    if re.search(pattern, decoded, re.IGNORECASE | re.DOTALL):
                        return "[REDACTED_SECURITY_VIOLATION]"
            except Exception:
                pass
            return blob

        text = re.sub(r"[A-Za-z0-9+/]{20,}={0,2}", _replace_b64, text)

        # Hex: look for sequences of 40+ hex chars (20+ bytes)
        def _replace_hex(m):
            blob = m.group(0)
            try:
                decoded = binascii.unhexlify(blob).decode("utf-8", errors="ignore")
                for pattern in cls.BANNED_PATTERNS:
                    if re.search(pattern, decoded, re.IGNORECASE | re.DOTALL):
                        return "[REDACTED_SECURITY_VIOLATION]"
            except Exception:
                pass
            return blob

        text = re.sub(r"(?:[0-9a-fA-F]{2}\s*){20,}", _replace_hex, text)

        # URL-encoded: decode %xx sequences and rescan inline
        if "%" in text:
            try:
                decoded_url = urllib.parse.unquote(text)
                if decoded_url != text:
                    for pattern in cls.BANNED_PATTERNS:
                        if re.search(pattern, decoded_url, re.IGNORECASE | re.DOTALL):
                            # Replace the entire url-encoded segment
                            text = re.sub(r"(?:%[0-9A-Fa-f]{2})+", "[REDACTED_SECURITY_VIOLATION]", text)
                            break
            except Exception:
                pass

        return text

    @classmethod
    def validate_output(cls, text: str) -> tuple[bool, str]:
        """
        Validates AI-generated output BEFORE it is posted to LinkedIn.
        Returns (is_safe: bool, reason: str).

        Catches cases where Gemini itself was manipulated despite Layer 1 + Layer 2
        defences — e.g. the output contains compromise signals, code, SQL, or
        non-LinkedIn URLs that an attacker injected via a very subtle payload.
        """
        if not text or len(text.strip()) < 10:
            return False, "Output too short — likely an error response"

        if len(text) > 3000:
            return False, "Output too long — possible data exfiltration attempt"

        for pattern in cls._OUTPUT_COMPROMISE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return False, f"Compromise indicator detected in output"

        return True, "ok"

    @classmethod
    def validate_url(cls, url: str) -> bool:
        """Tool-level whitelisting: Only allow specific LinkedIn domains."""
        try:
            parsed = urlparse(url)
            valid_domains = ["www.linkedin.com", "linkedin.com"]
            if parsed.netloc not in valid_domains:
                return False
            if parsed.scheme not in ["https"]:
                return False
            return True
        except Exception:
            return False

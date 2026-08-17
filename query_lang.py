"""
Small query language for /api/search — Splunk/KQL-style, e.g.:

    service:SSH AND risk_score>70
    (service:SSH OR service:TELNET) AND event_type:credential
    ip:10.0.0.* NOT country:US
    "wget http" AND event_type:download_attempt

Grammar (case-insensitive keywords AND/OR/NOT, implicit AND between adjacent terms):

    query      := or_expr
    or_expr    := and_expr (OR and_expr)*
    and_expr   := not_expr (AND? not_expr)*
    not_expr   := (NOT | "-")? term
    term       := "(" or_expr ")" | field_expr | free_text
    field_expr := FIELD (":" | ">" | ">=" | "<" | "<=") value
    free_text  := value
    value      := QUOTED_STRING | WORD

Compiles directly to a parameterized SQL WHERE clause + params list — field NAMES are
resolved through an explicit whitelist (never taken from user input into the SQL
string), and every VALUE is passed as a `?` placeholder, never string-interpolated.
Malformed queries raise QueryError with a message meant to be shown to the user, not a
stack trace.
"""

import re

# field -> (real column, kind).  kind "str" allows ':' (with '*' wildcard -> LIKE) only.
# kind "num" allows ':' (=), '>', '>=', '<', '<='.
_FIELDS = {
    "service": ("service", "str"),
    "event_type": ("event_type", "str"),
    "type": ("event_type", "str"),  # alias
    "ip": ("ip", "str"),
    "country": ("country", "str"),
    "city": ("city", "str"),
    "data": ("data", "str"),
    "port": ("port", "num"),
    "risk_score": ("risk_score", "num"),
    "abuse_score": ("abuse_score", "num"),
}

_TOKEN_RE = re.compile(r"""
      (?P<ws>\s+)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<op>>=|<=|>|<|:)
    | (?P<neg>-(?=\S))
    | (?P<quoted>"(?:[^"\\]|\\.)*")
    | (?P<word>[^\s()"><:-][^\s()"><:]*)
""", re.VERBOSE)


class QueryError(ValueError):
    """Raised on malformed query syntax. Message is safe to show to the user."""


def _tokenize(text):
    tokens = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise QueryError(f"Unexpected character at position {pos}: {text[pos]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        value = m.group(kind)
        if kind == "quoted":
            value = value[1:-1].replace('\\"', '"')
        elif kind == "word":
            upper = value.upper()
            if upper in ("AND", "OR", "NOT"):
                tokens.append((upper, value))
                continue
        tokens.append((kind, value))
    tokens.append(("EOF", ""))
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def _peek(self):
        return self.tokens[self.i]

    def _advance(self):
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self._or_expr()
        kind, value = self._peek()
        if kind != "EOF":
            raise QueryError(f"Unexpected {value!r} — check for a missing operator or unbalanced parenthesis")
        return node

    def _or_expr(self):
        left = self._and_expr()
        while self._peek()[0] == "OR":
            self._advance()
            right = self._and_expr()
            left = ("OR", left, right)
        return left

    def _and_expr(self):
        left = self._not_expr()
        while True:
            kind = self._peek()[0]
            if kind == "AND":
                self._advance()
                left = ("AND", left, self._not_expr())
            elif kind in ("lparen", "word", "quoted", "NOT", "neg"):
                # implicit AND: another term starts right here with no operator word
                left = ("AND", left, self._not_expr())
            else:
                break
        return left

    def _not_expr(self):
        if self._peek()[0] in ("NOT", "neg"):
            self._advance()
            return ("NOT", self._not_expr())
        return self._term()

    def _term(self):
        kind, value = self._peek()
        if kind == "lparen":
            self._advance()
            node = self._or_expr()
            kind2, _ = self._peek()
            if kind2 != "rparen":
                raise QueryError("Missing closing parenthesis")
            self._advance()
            return node
        if kind == "rparen":
            raise QueryError("Unexpected closing parenthesis")
        if kind in ("word", "quoted"):
            # Could be `field:value` / `field>value` etc., or just free text.
            if kind == "word" and self.i + 1 < len(self.tokens) and self.tokens[self.i + 1][0] == "op":
                field_name = value.lower()
                self._advance()  # consume field word
                op_kind, op_value = self._advance()  # consume operator
                val_kind, val_value = self._advance()
                if val_kind not in ("word", "quoted"):
                    raise QueryError(f"Expected a value after '{field_name}{op_value}'")
                return ("FIELD", field_name, op_value, val_value)
            self._advance()
            return ("TEXT", value)
        raise QueryError(f"Unexpected {value!r}" if value else "Unexpected end of query")


def _compile(node):
    """Returns (sql_fragment, params_list)."""
    tag = node[0]

    if tag == "AND" or tag == "OR":
        _, left, right = node
        lsql, lparams = _compile(left)
        rsql, rparams = _compile(right)
        return f"({lsql} {tag} {rsql})", lparams + rparams

    if tag == "NOT":
        _, inner = node
        isql, iparams = _compile(inner)
        return f"(NOT {isql})", iparams

    if tag == "TEXT":
        _, value = node
        pattern = f"%{value}%"
        return "(ip LIKE ? OR data LIKE ?)", [pattern, pattern]

    if tag == "FIELD":
        _, field_name, op, value = node
        if field_name not in _FIELDS:
            known = ", ".join(sorted(set(f for f in _FIELDS)))
            raise QueryError(f"Unknown field {field_name!r} — known fields: {known}")
        column, kind = _FIELDS[field_name]

        if kind == "num":
            try:
                num = float(value) if "." in value else int(value)
            except ValueError:
                raise QueryError(f"{field_name} is numeric — {value!r} is not a number")
            sql_op = {":": "=", ">": ">", ">=": ">=", "<": "<", "<=": "<="}[op]
            return f"{column} {sql_op} ?", [num]

        # kind == "str"
        if op != ":":
            raise QueryError(f"{field_name} is a text field — only ':' is supported, not {op!r}")
        if "*" in value:
            return f"{column} LIKE ?", [value.replace("*", "%")]
        return f"UPPER({column}) = UPPER(?)", [value]

    raise QueryError(f"Internal parser error: unknown node {tag!r}")


def compile_query(text):
    """Parse a query string and return (sql_where_fragment, params). Empty/whitespace-only
    input returns ("1=1", []) — no filter, matches everything."""
    text = (text or "").strip()
    if not text:
        return "1=1", []
    tokens = _tokenize(text)
    if len(tokens) == 1:  # just EOF
        return "1=1", []
    tree = _Parser(tokens).parse()
    return _compile(tree)

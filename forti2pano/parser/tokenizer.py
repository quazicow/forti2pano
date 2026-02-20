"""Line-level tokenizer for FortiGate flat text configuration."""

import re
import shlex
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List

from ..util import FortiParseError


class TokenType(Enum):
    CONFIG = auto()
    EDIT = auto()
    SET = auto()
    UNSET = auto()
    APPEND = auto()
    NEXT = auto()
    END = auto()
    COMMENT = auto()


@dataclass
class Token:
    type: TokenType
    line_num: int
    key: str = ""               # section path, entry name, or parameter name
    values: List[str] = field(default_factory=list)


def _split_values(raw: str) -> List[str]:
    """Split a value string respecting quoted segments.

    Examples:
        'all'                       -> ['all']
        '"Web Server"'              -> ['Web Server']
        '"val1" "val2"'             -> ['val1', 'val2']
        '10.0.1.1 255.255.255.0'   -> ['10.0.1.1', '255.255.255.0']
    """
    try:
        return shlex.split(raw)
    except ValueError:
        # Fall back to simple split if shlex fails (unmatched quotes, etc.)
        return raw.split()


def tokenize(text: str) -> List[Token]:
    """Tokenize FortiGate flat-text configuration into a list of Tokens."""
    tokens = []
    for line_num, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()

        # Skip blank lines
        if not line:
            continue

        # Comments
        if line.startswith('#'):
            tokens.append(Token(type=TokenType.COMMENT, line_num=line_num, key=line))
            continue

        # config <section path>
        m = re.match(r'^config\s+(.+)$', line)
        if m:
            tokens.append(Token(
                type=TokenType.CONFIG,
                line_num=line_num,
                key=m.group(1).strip(),
            ))
            continue

        # edit <name>
        m = re.match(r'^edit\s+(.+)$', line)
        if m:
            name = m.group(1).strip().strip('"')
            tokens.append(Token(
                type=TokenType.EDIT,
                line_num=line_num,
                key=name,
            ))
            continue

        # set <key> <values...>
        m = re.match(r'^set\s+(\S+)\s*(.*)?$', line)
        if m:
            key = m.group(1)
            val_str = m.group(2).strip() if m.group(2) else ""
            values = _split_values(val_str) if val_str else []
            tokens.append(Token(
                type=TokenType.SET,
                line_num=line_num,
                key=key,
                values=values,
            ))
            continue

        # unset <key>
        m = re.match(r'^unset\s+(\S+)', line)
        if m:
            tokens.append(Token(
                type=TokenType.UNSET,
                line_num=line_num,
                key=m.group(1),
            ))
            continue

        # append <key> <values...>
        m = re.match(r'^append\s+(\S+)\s*(.*)?$', line)
        if m:
            key = m.group(1)
            val_str = m.group(2).strip() if m.group(2) else ""
            values = _split_values(val_str) if val_str else []
            tokens.append(Token(
                type=TokenType.APPEND,
                line_num=line_num,
                key=key,
                values=values,
            ))
            continue

        # next
        if line == 'next':
            tokens.append(Token(type=TokenType.NEXT, line_num=line_num))
            continue

        # end
        if line == 'end':
            tokens.append(Token(type=TokenType.END, line_num=line_num))
            continue

        # Unknown line - skip with no error (FortiGate configs can have
        # diagnostic lines, version headers, etc.)

    return tokens

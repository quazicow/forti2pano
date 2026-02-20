"""Stack-based parser that converts tokens into a nested dictionary tree."""

from typing import Any, Dict, List

from ..util import FortiParseError
from .tokenizer import Token, TokenType


# Tree structure:
# {
#   "system interface": {
#       "_entries": {
#           "port1": {
#               "_props": {"vdom": ["root"], "ip": ["10.0.1.1", "255.255.255.0"]},
#               "_children": {}   # nested config blocks inside edit
#           }
#       }
#   },
#   "firewall policy": { "_entries": { ... } },
# }


def _new_section() -> Dict[str, Any]:
    return {"_entries": {}}


def _new_entry() -> Dict[str, Any]:
    return {"_props": {}, "_children": {}}


def build_tree(tokens: List[Token]) -> Dict[str, Any]:
    """Build nested dict tree from token stream using a context stack.

    The stack tracks the current nesting level. Each frame is:
      (frame_type, frame_key, frame_dict)
    where frame_type is 'config' or 'edit'.
    """
    tree: Dict[str, Any] = {}
    stack: List[tuple] = []  # (type, key, dict_ref)

    for tok in tokens:
        if tok.type == TokenType.COMMENT:
            continue

        elif tok.type == TokenType.CONFIG:
            section_path = tok.key
            if not stack:
                # Top-level config section
                if section_path not in tree:
                    tree[section_path] = _new_section()
                stack.append(("config", section_path, tree[section_path]))
            else:
                # Nested config inside an edit block
                frame_type, frame_key, frame_dict = stack[-1]
                if frame_type == "edit":
                    if section_path not in frame_dict["_children"]:
                        frame_dict["_children"][section_path] = _new_section()
                    stack.append(("config", section_path, frame_dict["_children"][section_path]))
                else:
                    # config inside config (without edit) - treat as sub-section
                    # Some FortiGate sections have config blocks directly (e.g., config system global)
                    if "_props" not in frame_dict:
                        frame_dict["_props"] = {}
                    if "_children" not in frame_dict:
                        frame_dict["_children"] = {}
                    if section_path not in frame_dict.get("_children", {}):
                        if "_children" not in frame_dict:
                            frame_dict["_children"] = {}
                        frame_dict["_children"][section_path] = _new_section()
                    stack.append(("config", section_path, frame_dict["_children"][section_path]))

        elif tok.type == TokenType.EDIT:
            if not stack:
                raise FortiParseError("'edit' outside of 'config' block", tok.line_num)
            frame_type, frame_key, frame_dict = stack[-1]
            entry_name = tok.key
            if entry_name not in frame_dict["_entries"]:
                frame_dict["_entries"][entry_name] = _new_entry()
            stack.append(("edit", entry_name, frame_dict["_entries"][entry_name]))

        elif tok.type in (TokenType.SET, TokenType.APPEND):
            if not stack:
                # Top-level set (e.g., in 'config system global' without edit)
                continue
            frame_type, frame_key, frame_dict = stack[-1]
            props = frame_dict.get("_props")
            if props is None:
                # We're in a config section without edit (e.g., config system global)
                frame_dict["_props"] = {}
                props = frame_dict["_props"]

            if tok.type == TokenType.APPEND and tok.key in props:
                props[tok.key].extend(tok.values)
            else:
                props[tok.key] = tok.values

        elif tok.type == TokenType.UNSET:
            if stack:
                frame_type, frame_key, frame_dict = stack[-1]
                props = frame_dict.get("_props", {})
                props.pop(tok.key, None)

        elif tok.type == TokenType.NEXT:
            if stack and stack[-1][0] == "edit":
                stack.pop()

        elif tok.type == TokenType.END:
            if stack:
                # Pop until we close a config frame
                if stack[-1][0] == "edit":
                    stack.pop()  # close any unclosed edit
                if stack and stack[-1][0] == "config":
                    stack.pop()

    return tree


def get_section(tree: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Get a config section from the tree by its path.

    Returns empty section dict if not found.
    """
    return tree.get(path, {"_entries": {}})


def get_entries(section: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Get entries dict from a section."""
    return section.get("_entries", {})


def get_props(entry: Dict[str, Any]) -> Dict[str, List[str]]:
    """Get properties dict from an entry."""
    return entry.get("_props", {})


def get_prop(entry: Dict[str, Any], key: str, default: str = "") -> str:
    """Get a single-value property as string."""
    props = get_props(entry)
    vals = props.get(key, [])
    return vals[0] if vals else default


def get_prop_list(entry: Dict[str, Any], key: str) -> List[str]:
    """Get a multi-value property as list."""
    return get_props(entry).get(key, [])

"""Decision form schema and serialization."""

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml


DECISION_CATEGORIES = [
    "interface_mapping",
    "zone_confirmation",
    "security_profile",
    "vdom_vsys",
    "application_mapping",
    "service_ambiguity",
    "nat_ambiguity",
    "vpn_tunnel_interface",
    "name_conflict",
]

YAML_HEADER = """\
# forti2pano Decision Form
# {metadata_line}
#
# Instructions:
#   Fill in the 'user_value' field for each item below.
#   If the 'suggested_value' is acceptable, copy it to 'user_value'.
#   If 'user_value' is left empty/null, the suggested_value will be used.
#   Items marked required: true MUST have a user_value (or suggested_value) to proceed.
#
#   Re-run with: python -m forti2pano <input_file> -d <this_file>
#
"""


@dataclass
class DecisionItem:
    id: str
    category: str
    description: str
    fg_value: str
    suggested_value: Optional[str] = None
    options: List[str] = field(default_factory=list)
    user_value: Optional[str] = None
    required: bool = True

    def resolved_value(self) -> Optional[str]:
        """Return the user's value, falling back to suggested_value."""
        if self.user_value is not None and self.user_value != "":
            return self.user_value
        return self.suggested_value

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "category": self.category,
            "description": self.description,
            "fg_value": self.fg_value,
            "suggested_value": self.suggested_value,
            "user_value": self.user_value,
            "required": self.required,
        }
        if self.options:
            d["options"] = self.options
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DecisionItem":
        return cls(
            id=d["id"],
            category=d.get("category", ""),
            description=d.get("description", ""),
            fg_value=d.get("fg_value", ""),
            suggested_value=d.get("suggested_value"),
            options=d.get("options", []),
            user_value=d.get("user_value"),
            required=d.get("required", True),
        )


@dataclass
class DecisionForm:
    items: List[DecisionItem] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def has_unresolved(self) -> bool:
        """Check if any required items lack a resolved value."""
        return any(
            i.resolved_value() is None and i.required
            for i in self.items
        )

    def unresolved_items(self) -> List[DecisionItem]:
        """Return list of required items with no resolved value."""
        return [
            i for i in self.items
            if i.resolved_value() is None and i.required
        ]

    def to_yaml(self) -> str:
        """Serialize to YAML for user editing."""
        metadata_line = f"Generated: {self.metadata.get('generated_at', datetime.datetime.now().isoformat())}"
        if "source_file" in self.metadata:
            metadata_line += f" from {self.metadata['source_file']}"

        header = YAML_HEADER.format(metadata_line=metadata_line)

        data = {
            "metadata": self.metadata,
            "decisions": [item.to_dict() for item in self.items],
        }

        yaml_body = yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )

        return header + yaml_body

    @classmethod
    def from_yaml(cls, yaml_text: str) -> "DecisionForm":
        """Load from user-edited YAML file."""
        data = yaml.safe_load(yaml_text)
        if data is None:
            return cls()

        form = cls()
        form.metadata = data.get("metadata", {})
        for item_dict in data.get("decisions", []):
            form.items.append(DecisionItem.from_dict(item_dict))

        return form

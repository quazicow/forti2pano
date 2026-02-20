"""Crypto proposal mapping from FortiGate to PAN-OS."""

import logging
import re
from typing import Tuple, Optional

log = logging.getLogger(__name__)

# FortiGate encryption algorithms -> PAN-OS equivalents
FG_TO_PANOS_ENCRYPTION = {
    "des": "des",
    "3des": "3des",
    "aes128": "aes-128-cbc",
    "aes192": "aes-192-cbc",
    "aes256": "aes-256-cbc",
    "aes128gcm": "aes-128-gcm",
    "aes256gcm": "aes-256-gcm",
    "chacha20poly1305": "aes-256-gcm",  # closest approximation
}

# FortiGate hash algorithms -> PAN-OS equivalents
FG_TO_PANOS_HASH = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "prfsha1": "sha1",
    "prfsha256": "sha256",
    "prfsha384": "sha384",
    "prfsha512": "sha512",
}

# FortiGate DH group numbers -> PAN-OS group names
FG_TO_PANOS_DH_GROUP = {
    1: "group1",
    2: "group2",
    5: "group5",
    14: "group14",
    15: "group15",
    16: "group16",
    19: "group19",
    20: "group20",
    21: "group21",
}


def parse_proposal(proposal: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse a FortiGate proposal string into (encryption, authentication).

    FortiGate formats:
        'aes256-sha256'     -> ('aes-256-cbc', 'sha256')
        '3des-md5'          -> ('3des', 'md5')
        'aes128gcm'         -> ('aes-128-gcm', None)  # GCM has built-in auth
        'aes256-sha1'       -> ('aes-256-cbc', 'sha1')

    Returns (None, None) if the proposal cannot be parsed.
    """
    proposal = proposal.strip().lower()

    # Try to match known patterns
    # Pattern: encryption-hash
    for enc_key in sorted(FG_TO_PANOS_ENCRYPTION.keys(), key=len, reverse=True):
        if proposal.startswith(enc_key):
            panos_enc = FG_TO_PANOS_ENCRYPTION[enc_key]
            remainder = proposal[len(enc_key):]

            if not remainder:
                # GCM or single-algorithm proposal
                if "gcm" in enc_key:
                    return panos_enc, None
                return panos_enc, None

            if remainder.startswith("-"):
                hash_part = remainder[1:]
                panos_hash = FG_TO_PANOS_HASH.get(hash_part)
                if panos_hash:
                    return panos_enc, panos_hash

    log.warning(f"Cannot parse crypto proposal: '{proposal}'")
    return None, None


def map_dh_group(fg_group: int) -> str:
    """Map a FortiGate DH group number to PAN-OS group name."""
    result = FG_TO_PANOS_DH_GROUP.get(fg_group)
    if result is None:
        log.warning(f"Unknown DH group {fg_group}, defaulting to group14")
        return "group14"
    return result

"""hack5250: tn5250 MITM proxy for IBM i pentesting."""
__version__ = "0.1.0"

from hack5250.tn5250 import TN5250
from hack5250.constants import AID_TABLE, FFW_BYPASS, ATTR_NONDISP
from hack5250.attacks.escape import build_attn_packet, get_masked_keys, classify_attn_response

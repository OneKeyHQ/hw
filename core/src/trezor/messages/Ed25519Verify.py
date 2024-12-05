# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class Ed25519Verify(p.MessageType):
    MESSAGE_WIRE_TYPE = 1011

    def __init__(
        self,
        *,
        digest: bytes,
        pubkey: bytes,
        sig: bytes,
    ) -> None:
        self.digest = digest
        self.pubkey = pubkey
        self.sig = sig

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('digest', p.BytesType, p.FLAG_REQUIRED),
            2: ('pubkey', p.BytesType, p.FLAG_REQUIRED),
            3: ('sig', p.BytesType, p.FLAG_REQUIRED),
        }
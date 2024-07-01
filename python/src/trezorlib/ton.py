from typing import TYPE_CHECKING

from . import messages
from .tools import expect

if TYPE_CHECKING:
    from .client import TrezorClient
    from .tools import Address


@expect(messages.TonAddress)
def get_address(client: "TrezorClient",
                n: "Address",
                version: messages.TonWalletVersion=messages.TonWalletVersion.V3R2,
                workchain: messages.TonWorkChain=messages.TonWorkChain.BASECHAIN,
                bounceable: bool = False,
                test_only: bool = False,
                wallet_id: int = 698983191,
                show_display: bool = False):
    return client.call(
        messages.TonGetAddress(
            address_n=n,
            wallet_version=version,
            workchain=workchain,
            is_bounceable=bounceable,
            is_testnet_only=test_only,
            wallet_id=wallet_id,
            show_display=show_display
        )
    )

@expect(messages.TonSignedMessage)
def sign_message(client: "TrezorClient",
                n: "Address",
                destination: str,
                jetton_master_address: str,
                ton_amount: int,
                jetton_amount: int,
                fwd_fee: int,
                mode: int,
                seqno: int,
                expire_at: int,
                comment: str="",
                version: messages.TonWalletVersion=messages.TonWalletVersion.V3R2,
                wallet_id: int = 698983191,
                workchain: messages.TonWorkChain=messages.TonWorkChain.BASECHAIN,
                bounceable: bool = False,
                test_only: bool = False):
    return client.call(
        messages.TonSignMessage(
            address_n=n,
            destination=destination,
            jetton_master_address=jetton_master_address,
            ton_amount=ton_amount,
            jetton_amount=jetton_amount,
            fwd_fee=fwd_fee,
            comment=comment,
            mode=mode,
            seqno=seqno,
            expire_at=expire_at,
            version=version,
            wallet_id=wallet_id,
            workchain=workchain,
            bounceable=bounceable,
            is_test_only=test_only,
        )
    )

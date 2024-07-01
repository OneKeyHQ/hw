# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.


from typing import TYPE_CHECKING

import click
import time
from trezorlib import ton, tools
from trezorlib.cli import with_client, ChoiceType
from trezorlib import messages
if TYPE_CHECKING:
    from ..client import TrezorClient
PATH_HELP = "BIP-32 path, e.g. m/44'/607'/0'/0'"

WORKCHAIN = {
    "base": messages.TonWorkChain.BASECHAIN,
    "master": messages.TonWorkChain.MASTERCHAIN,
}
WALLET_VERSION = {
    "v3r1": messages.TonWalletVersion.V3R1,
    "v3r2": messages.TonWalletVersion.V3R2,
    "v4r1": messages.TonWalletVersion.V4R1,
    "v4r2": messages.TonWalletVersion.V4R2,
}
@click.group(name="ton")
def cli():
    """Ton commands."""


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.option("-b", "--bounceable", is_flag=True)
@click.option("-t", "--test-only", is_flag=True)
@click.option("-i", "--wallet-id", type=int, default=698983191)
@click.option("-v", "--version", type=ChoiceType(WALLET_VERSION), default="v3r2")
@click.option("-w", "--workchain", type=ChoiceType(WORKCHAIN), default="base")
@click.option("-d", "--show-display", is_flag=True)
@with_client
def get_address(client: "TrezorClient",
                address: str,
                bounceable: bool,
                test_only: bool,
                wallet_id: int,
                version: messages.TonWalletVersion,
                workchain: messages.TonWorkChain,
                show_display: bool
                ) -> str:
    """Get Ton address for specified path."""
    address_n = tools.parse_path(address)
    _address = ton.get_address(client, address_n, version, workchain, bounceable, test_only, wallet_id, show_display).address
    return {"address": f"{_address}"}


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.option("-d", "--destination", type=str, required=True)
@click.option("-j", "--jetton_master_address", type=str)
@click.option("-ta", "--ton_amount", type=int, required=True)
@click.option("-ja", "--jetton_amount", type=int)
@click.option("-f", "--fwd_fee", type=int)
@click.option("-c", "--comment", type=str)
@click.option("-m", "--mode", type=int)
@click.option("-s", "--seqno", type=int, required=True)
# @click.option("-e", "--expire_at", type=int, required=True)
@click.option("-v", "--version", type=ChoiceType(WALLET_VERSION), default="v3r2")
@click.option("-i", "--wallet-id", type=int, default=698983191)
@click.option("-w", "--workchain", type=ChoiceType(WORKCHAIN), default="base")
@click.option("-b", "--bounceable", is_flag=True)
@click.option("-t", "--test-only", is_flag=True)
@with_client
def sign_message(client: "TrezorClient",
                address: str,
                destination: str,
                jetton_master_address: str,
                ton_amount: int,
                jetton_amount: int,
                fwd_fee: int,
                mode: int,
                seqno: int,
                # expire_at: int,
                comment: str,
                version: messages.TonWalletVersion,
                wallet_id: int,
                workchain: messages.TonWorkChain,
                bounceable: bool,
                test_only: bool
                ) -> bytes:
    """Sign Ton Transaction."""
    address_n = tools.parse_path(address)
    expire_at = int(time.time()) + 300
    signature = ton.sign_message(
                client,
                address_n,
                destination,
                jetton_master_address,
                ton_amount,
                jetton_amount,
                fwd_fee,
                mode,
                seqno,
                expire_at,
                comment,
                version,
                wallet_id,
                workchain,
                bounceable,
                test_only
    ).signature.hex()

    return {"signature": f"0x{signature}"}

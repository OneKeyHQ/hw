from typing import Iterator

from trezor.strings import format_amount

from . import ICON, PRIMARY_COLOR


class NetworkInfo:
    def __init__(
        self,
        chainId: str,
        chainName: str,
        coinDenom: str,
        coinMinimalDenom: str,
        coinDecimals: int,
        hrp: str,
        icon: str,
        primary_color: int,
    ) -> None:
        self.chainId = chainId
        self.chainName = chainName
        self.coinDenom = coinDenom
        self.coinMinimalDenom = coinMinimalDenom
        self.coinDecimals = coinDecimals
        self.hrp = hrp
        self.icon = icon
        self.primary_color = primary_color


def getChainName(chainId: str) -> str | None:
    n = by_chain_id(chainId)
    if n is None:
        return None

    return n.chainName


def retrieve_theme_by_hrp(hrp: str | None) -> tuple[int, str]:
    if hrp is not None:
        for n in _networks_iterator():
            if n.hrp == hrp:
                return (n.primary_color, n.icon)
    return (PRIMARY_COLOR, ICON)


def getChainHrp(chainId: str) -> str | None:
    n = by_chain_id(chainId)
    if n is None:
        return None

    return n.hrp


def formatAmont(chainId: str, amount: str, denom: str) -> str:
    n = by_chain_id(chainId)
    if n is None:
        return amount + " " + denom

    if denom == n.coinMinimalDenom:
        sum = f"{format_amount(int(amount), n.coinDecimals)} {n.coinDenom}"
        return sum

    return amount + " " + denom


def by_chain_id(chainId: str) -> "NetworkInfo" | None:
    for n in _networks_iterator():
        if n.chainId == chainId:
            return n
    return None


def _networks_iterator() -> Iterator[NetworkInfo]:
    yield NetworkInfo(
        chainId="cosmoshub-4",
        chainName="Cosmos Hub",
        coinDenom="ATOM",
        coinMinimalDenom="uatom",
        coinDecimals=6,
        hrp="cosmos",
        icon="A:/res/chain-atom.png",
        primary_color=0xE0E0E0,
    )
    yield NetworkInfo(
        chainId="osmosis-1",
        chainName="Osmosis",
        coinDenom="OSMO",
        coinMinimalDenom="uosmo",
        coinDecimals=6,
        hrp="osmo",
        icon="A:/res/chain-osmo.png",
        primary_color=0x4D4996,
    )
    yield NetworkInfo(
        chainId="secret-4",
        chainName="Secret Network",
        coinDenom="SCRT",
        coinMinimalDenom="uscrt",
        coinDecimals=6,
        hrp="secret",
        icon="A:/res/chain-scrt.png",
        primary_color=0x626B75,
    )
    yield NetworkInfo(
        chainId="akashnet-2",
        chainName="Akash",
        coinDenom="AKT",
        coinMinimalDenom="uakt",
        coinDecimals=6,
        hrp="akash",
        icon="A:/res/chain-akt.png",
        primary_color=0xFF414C,
    )
    yield NetworkInfo(
        chainId="crypto-org-chain-mainnet-1",
        chainName="Crypto.org",
        coinDenom="CRO",
        coinMinimalDenom="basecro",
        coinDecimals=8,
        hrp="cro",
        icon="A:/res/chain-cro.png",
        primary_color=0x0F50AB,
    )
    yield NetworkInfo(
        chainId="iov-mainnet-ibc",
        chainName="Starname",
        coinDenom="IOV",
        coinMinimalDenom="uiov",
        coinDecimals=6,
        hrp="star",
        icon="A:/res/chain-iov.png",
        primary_color=0x5C67B0,
    )
    yield NetworkInfo(
        chainId="sifchain-1",
        chainName="Sifchain",
        coinDenom="ROWAN",
        coinMinimalDenom="rowan",
        coinDecimals=18,
        hrp="sif",
        icon="A:/res/chain-rowan.png",
        primary_color=0xF9DB6C,
    )
    yield NetworkInfo(
        chainId="shentu-2.2",
        chainName="Shentu",
        coinDenom="CTK",
        coinMinimalDenom="uctk",
        coinDecimals=6,
        hrp="certik",
        icon="A:/res/chain-ctk.png",
        primary_color=0xE5AE4D,
    )
    yield NetworkInfo(
        chainId="irishub-1",
        chainName="IRISnet",
        coinDenom="IRIS",
        coinMinimalDenom="uiris",
        coinDecimals=6,
        hrp="iaa",
        icon="A:/res/chain-iris.png",
        primary_color=0x4947BC,
    )
    yield NetworkInfo(
        chainId="regen-1",
        chainName="Regen",
        coinDenom="REGEN",
        coinMinimalDenom="uregen",
        coinDecimals=6,
        hrp="regen",
        icon="A:/res/chain-regen.png",
        primary_color=0x30A95B,
    )
    yield NetworkInfo(
        chainId="core-1",
        chainName="Persistence",
        coinDenom="XPRT",
        coinMinimalDenom="uxprt",
        coinDecimals=6,
        hrp="persistence",
        icon="A:/res/chain-xprt.png",
        primary_color=0xE50913,
    )
    yield NetworkInfo(
        chainId="sentinelhub-2",
        chainName="Sentinel",
        coinDenom="DVPN",
        coinMinimalDenom="udvpn",
        coinDecimals=6,
        hrp="sent",
        icon="A:/res/chain-dvpn.png",
        primary_color=0x0155FB,
    )
    yield NetworkInfo(
        chainId="ixo-4",
        chainName="ixo",
        coinDenom="IXO",
        coinMinimalDenom="uixo",
        coinDecimals=6,
        hrp="ixo",
        icon="A:/res/chain-ixo.png",
        primary_color=0x00D2FF,
    )
    yield NetworkInfo(
        chainId="emoney-3",
        chainName="e-Money",
        coinDenom="NGM",
        coinMinimalDenom="ungm",
        coinDecimals=6,
        hrp="emoney",
        icon="A:/res/chain-ngm.png",
        primary_color=0xCCF7EE,
    )
    yield NetworkInfo(
        chainId="agoric-3",
        chainName="Agoric",
        coinDenom="BLD",
        coinMinimalDenom="ubld",
        coinDecimals=6,
        hrp="agoric",
        icon="A:/res/chain-bld.png",
        primary_color=0xD73252,
    )
    yield NetworkInfo(
        chainId="bostrom",
        chainName="Bostrom",
        coinDenom="BOOT",
        coinMinimalDenom="boot",
        coinDecimals=0,
        hrp="bostrom",
        icon="A:/res/chain-boot.png",
        primary_color=0x00AF02,
    )
    yield NetworkInfo(
        chainId="juno-1",
        chainName="Juno",
        coinDenom="JUNO",
        coinMinimalDenom="ujuno",
        coinDecimals=6,
        hrp="juno",
        icon="A:/res/chain-juno.png",
        primary_color=0xFF7B7C,
    )
    yield NetworkInfo(
        chainId="stargaze-1",
        chainName="Stargaze",
        coinDenom="STARS",
        coinMinimalDenom="ustars",
        coinDecimals=6,
        hrp="stars",
        icon="A:/res/chain-stars.png",
        primary_color=0xDB2877,
    )
    yield NetworkInfo(
        chainId="axelar-dojo-1",
        chainName="Axelar",
        coinDenom="AXL",
        coinMinimalDenom="uaxl",
        coinDecimals=6,
        hrp="axelar",
        icon="A:/res/chain-axl.png",
        primary_color=0x54607C,
    )
    yield NetworkInfo(
        chainId="sommelier-3",
        chainName="Sommelier",
        coinDenom="SOMM",
        coinMinimalDenom="usomm",
        coinDecimals=6,
        hrp="somm",
        icon="A:/res/chain-somm.png",
        primary_color=0xF26057,
    )
    yield NetworkInfo(
        chainId="umee-1",
        chainName="Umee",
        coinDenom="UMEE",
        coinMinimalDenom="uumee",
        coinDecimals=6,
        hrp="umee",
        icon="A:/res/chain-umee.png",
        primary_color=0xDDB1FF,
    )
    yield NetworkInfo(
        chainId="gravity-bridge-3",
        chainName="Gravity Bridge",
        coinDenom="GRAV",
        coinMinimalDenom="ugraviton",
        coinDecimals=6,
        hrp="gravity",
        icon="A:/res/chain-grav.png",
        primary_color=0x2946B4,
    )
    yield NetworkInfo(
        chainId="tgrade-mainnet-1",
        chainName="Tgrade",
        coinDenom="TGD",
        coinMinimalDenom="utgd",
        coinDecimals=6,
        hrp="tgrade",
        icon="A:/res/chain-tgd.png",
        primary_color=0x4F5D87,
    )
    yield NetworkInfo(
        chainId="stride-1",
        chainName="Stride",
        coinDenom="STRD",
        coinMinimalDenom="ustrd",
        coinDecimals=6,
        hrp="stride",
        icon="A:/res/chain-strd.png",
        primary_color=0xE6007A,
    )
    yield NetworkInfo(
        chainId="evmos_9001-2",
        chainName="Evmos",
        coinDenom="EVMOS",
        coinMinimalDenom="aevmos",
        coinDecimals=18,
        hrp="evmos",
        icon="A:/res/chain-evmos.png",
        primary_color=0xEC4C32,
    )
    yield NetworkInfo(
        chainId="injective-1",
        chainName="Injective",
        coinDenom="INJ",
        coinMinimalDenom="inj",
        coinDecimals=18,
        hrp="inj",
        icon="A:/res/chain-ing.png",
        primary_color=0x01A8FC,
    )
    yield NetworkInfo(
        chainId="kava_2222-10",
        chainName="Kava",
        coinDenom="KAVA",
        coinMinimalDenom="ukava",
        coinDecimals=6,
        hrp="kava",
        icon="A:/res/chain-kava.png",
        primary_color=0xFF433E,
    )
    yield NetworkInfo(
        chainId="quicksilver-1",
        chainName="Quicksilver",
        coinDenom="QCK",
        coinMinimalDenom="uqck",
        coinDecimals=6,
        hrp="quick",
        icon="A:/res/chain-qck.png",
        primary_color=0x858585,
    )
    yield NetworkInfo(
        chainId="fetchhub-4",
        chainName="Fetch.ai",
        coinDenom="FET",
        coinMinimalDenom="afet",
        coinDecimals=18,
        hrp="fetch",
        icon="A:/res/chain-fet.png",
        primary_color=0x4C4CAE,
    )
    yield NetworkInfo(
        chainId="celestia",
        chainName="Celestia",
        coinDenom="TIA",
        coinMinimalDenom="utia",
        coinDecimals=6,
        hrp="celestia",
        icon="A:/res/chain-tia.png",
        primary_color=0x802EF4,
    )

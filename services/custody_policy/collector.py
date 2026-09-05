from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from web3 import Web3

FALLBACK_HANDLER_STORAGE_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
GUARD_STORAGE_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
MODULE_GUARD_STORAGE_SLOT = "0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947"
SAFE_ABI = [
    {"inputs": [], "name": "getOwners", "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getThreshold", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "start", "type": "address"}, {"internalType": "uint256", "name": "pageSize", "type": "uint256"}], "name": "getModulesPaginated", "outputs": [{"internalType": "address[]", "name": "array", "type": "address[]"}, {"internalType": "address", "name": "next", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "VERSION", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"},
]
ZERO = "0x0000000000000000000000000000000000000000"
SENTINEL = "0x0000000000000000000000000000000000000001"


@dataclass(frozen=True)
class SafeState:
    chain_id: int
    address: str
    owners: list[str]
    threshold: int
    modules: list[dict[str, str]]
    guards: list[dict[str, str]]
    module_guard: dict[str, str] | None
    fallback_handler: dict[str, str] | None
    version: str | None
    signers: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _address_from_storage(value: bytes | str) -> str:
    raw = value.hex() if isinstance(value, bytes) else value.removeprefix("0x")
    return Web3.to_checksum_address("0x" + raw[-40:])


def _code_hash(w3: Web3, address: str) -> str:
    code = w3.eth.get_code(address)
    if not code:
        return ZERO
    return Web3.to_hex(Web3.keccak(code))


def _extension(w3: Web3, address: str) -> dict[str, str]:
    address = Web3.to_checksum_address(address)
    return {"address": address, "code_hash": _code_hash(w3, address)}


def _walk_modules(contract: Any, page_size: int = 100) -> list[str]:
    modules: list[str] = []
    cursor = SENTINEL
    for _ in range(100):
        page, next_cursor = contract.functions.getModulesPaginated(cursor, page_size).call()
        modules.extend(Web3.to_checksum_address(x) for x in page)
        if not page or Web3.to_checksum_address(next_cursor) == Web3.to_checksum_address(SENTINEL):
            break
        cursor = next_cursor
    else:
        raise RuntimeError("module pagination exceeded safety limit")
    return modules


def collect_safe_state(rpc_url: str, safe_address: str, chain_id: int | None = None) -> SafeState:
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        raise ConnectionError("unable to connect to JSON-RPC endpoint")
    actual_chain_id = int(w3.eth.chain_id)
    if chain_id is not None and actual_chain_id != chain_id:
        raise ValueError(f"chain ID mismatch: expected {chain_id}, got {actual_chain_id}")

    address = Web3.to_checksum_address(safe_address)
    if w3.eth.get_code(address) in (b"", b"\x00"):
        raise ValueError("target address has no deployed bytecode")
    contract = w3.eth.contract(address=address, abi=SAFE_ABI)
    owners = [Web3.to_checksum_address(x) for x in contract.functions.getOwners().call()]
    threshold = int(contract.functions.getThreshold().call())
    modules = [_extension(w3, x) for x in _walk_modules(contract)]

    fallback_address = _address_from_storage(w3.eth.get_storage_at(address, FALLBACK_HANDLER_STORAGE_SLOT))
    guard_address = _address_from_storage(w3.eth.get_storage_at(address, GUARD_STORAGE_SLOT))
    module_guard_address = _address_from_storage(w3.eth.get_storage_at(address, MODULE_GUARD_STORAGE_SLOT))
    guards = [] if guard_address == Web3.to_checksum_address(ZERO) else [_extension(w3, guard_address)]
    module_guard = None if module_guard_address == Web3.to_checksum_address(ZERO) else _extension(w3, module_guard_address)
    fallback = None if fallback_address == Web3.to_checksum_address(ZERO) else _extension(w3, fallback_address)

    try:
        version = str(contract.functions.VERSION().call())
    except Exception:
        version = None

    # On-chain state cannot establish operational independence. Unknown metadata is
    # intentionally false so the policy engine fails closed until an operator enriches it.
    signers = [{
        "address": owner,
        "key_generation_verified": False,
        "hardware_independent": False,
        "software_independent": False,
        "administrator_independent": False,
        "geography_independent": False,
        "backup_independent": False,
        "communications_independent": False,
        "recovery_independent": False,
    } for owner in owners]

    return SafeState(actual_chain_id, address, owners, threshold, modules, guards, module_guard, fallback, version, signers)

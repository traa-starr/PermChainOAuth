#!/usr/bin/env python3
"""PermissionReceipt anomaly detector.

Monitors ReceiptMinted/ReceiptRevoked events on Sepolia (or local Hardhat)
and flags:
- spam granters (>5 mints/hour)
- stale permissions (expired but still active)
- suspicious AI scopes (e.g., ai:train_data)

Env vars:
- RPC_URL (required)
- CONTRACT_ADDRESS (required)
- START_BLOCK (optional, default latest-5000)
- POLL_INTERVAL_SECONDS (optional, default 15)
- SPAM_MINTS_PER_HOUR (optional, default 5)
- ALERT_EMAIL_TO / ALERT_EMAIL_FROM / SMTP_HOST / SMTP_PORT (optional)
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
import smtplib
from typing import Deque, Dict, List, Tuple

from web3 import Web3
from web3.contract import Contract

RECEIPT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "tokenId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "granter", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "grantee", "type": "address"},
            {"indexed": False, "internalType": "string", "name": "scope", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "tokenURI", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "proofHash", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "expiresAt", "type": "uint256"},
        ],
        "name": "ReceiptMinted",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "tokenId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "granter", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "grantee", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "revokedAt", "type": "uint256"},
        ],
        "name": "ReceiptRevoked",
        "type": "event",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "name": "receipts",
        "outputs": [
            {"internalType": "address", "name": "granter", "type": "address"},
            {"internalType": "address", "name": "grantee", "type": "address"},
            {"internalType": "string", "name": "scope", "type": "string"},
            {"internalType": "string", "name": "proofHash", "type": "string"},
            {"internalType": "uint256", "name": "issuedAt", "type": "uint256"},
            {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
            {"internalType": "uint256", "name": "revokedAt", "type": "uint256"},
            {"internalType": "bool", "name": "active", "type": "bool"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

SUSPICIOUS_SCOPE_KEYWORDS = {
    "ai:train_data",
    "ai:training",
    "model:train",
    "llm:train",
    "biometric",
    "medical",
}


@dataclass
class Alert:
    level: str
    category: str
    message: str
    tx_hash: str = ""


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


def maybe_send_email(alerts: List[Alert]) -> None:
    if not alerts:
        return

    to_addr = os.getenv("ALERT_EMAIL_TO")
    from_addr = os.getenv("ALERT_EMAIL_FROM")
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = env_int("SMTP_PORT", 25)

    if not (to_addr and from_addr and smtp_host):
        for alert in alerts:
            print(f"[ALERT:{alert.level}] {alert.category} - {alert.message} {alert.tx_hash}")
        return

    body = "\n".join([f"[{a.level}] {a.category}: {a.message} {a.tx_hash}" for a in alerts])
    msg = EmailMessage()
    msg["Subject"] = "PermissionReceipt anomaly alerts"
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.send_message(msg)


def connect() -> Tuple[Web3, Contract]:
    rpc_url = os.getenv("RPC_URL")
    contract_address = os.getenv("CONTRACT_ADDRESS")
    if not rpc_url or not contract_address:
        raise RuntimeError("Set RPC_URL and CONTRACT_ADDRESS")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to RPC at {rpc_url}")

    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=RECEIPT_ABI)
    return w3, contract


def is_suspicious_scope(scope: str) -> bool:
    normalized = scope.lower().strip()
    return any(keyword in normalized for keyword in SUSPICIOUS_SCOPE_KEYWORDS)


def run_monitor() -> None:
    w3, contract = connect()
    poll_interval = env_int("POLL_INTERVAL_SECONDS", 15)
    spam_threshold = env_int("SPAM_MINTS_PER_HOUR", 5)

    latest = w3.eth.block_number
    start_block = env_int("START_BLOCK", max(0, latest - 5000))
    current_from = start_block

    # rolling 1h window by granter address
    granter_mint_times: Dict[str, Deque[int]] = defaultdict(deque)
    tracked_tokens = set()

    print(
        f"Monitoring contract={contract.address} chain_id={w3.eth.chain_id} "
        f"from_block={current_from} poll={poll_interval}s"
    )

    while True:
        try:
            latest_block = w3.eth.block_number
            if current_from > latest_block:
                time.sleep(poll_interval)
                continue

            to_block = min(current_from + 1000, latest_block)
            alerts: List[Alert] = []

            minted_logs = contract.events.ReceiptMinted.get_logs(from_block=current_from, to_block=to_block)
            revoked_logs = contract.events.ReceiptRevoked.get_logs(from_block=current_from, to_block=to_block)

            for event in minted_logs:
                token_id = event["args"]["tokenId"]
                granter = event["args"]["granter"]
                scope = event["args"]["scope"]
                expires_at = int(event["args"]["expiresAt"])
                block = w3.eth.get_block(event["blockNumber"])
                ts = int(block["timestamp"])

                tracked_tokens.add(token_id)
                dq = granter_mint_times[granter]
                dq.append(ts)
                while dq and ts - dq[0] > 3600:
                    dq.popleft()

                if len(dq) > spam_threshold:
                    alerts.append(
                        Alert(
                            level="HIGH",
                            category="spam_minting",
                            message=(
                                f"granter {granter} minted {len(dq)} receipts within the last hour "
                                f"(threshold {spam_threshold})"
                            ),
                            tx_hash=event["transactionHash"].hex(),
                        )
                    )

                if expires_at != 0 and expires_at <= ts:
                    alerts.append(
                        Alert(
                            level="MEDIUM",
                            category="immediately_expired_mint",
                            message=f"token {token_id} minted with past expiry {expires_at}",
                            tx_hash=event["transactionHash"].hex(),
                        )
                    )

                if is_suspicious_scope(scope):
                    alerts.append(
                        Alert(
                            level="HIGH",
                            category="suspicious_scope",
                            message=f"token {token_id} contains sensitive AI scope '{scope}'",
                            tx_hash=event["transactionHash"].hex(),
                        )
                    )

            for event in revoked_logs:
                token_id = event["args"]["tokenId"]
                if token_id in tracked_tokens:
                    tracked_tokens.remove(token_id)

            now_ts = int(datetime.now(tz=timezone.utc).timestamp())
            for token_id in list(tracked_tokens):
                rec = contract.functions.receipts(token_id).call()
                expires_at = int(rec[5])
                active = bool(rec[7])
                scope = str(rec[2])
                if active and expires_at != 0 and now_ts > expires_at:
                    alerts.append(
                        Alert(
                            level="MEDIUM",
                            category="stale_permission",
                            message=(
                                f"token {token_id} is expired ({expires_at}) but still active in storage"
                            ),
                        )
                    )
                if active and is_suspicious_scope(scope):
                    alerts.append(
                        Alert(
                            level="HIGH",
                            category="active_sensitive_ai_scope",
                            message=f"token {token_id} has active sensitive scope '{scope}'",
                        )
                    )

            maybe_send_email(alerts)
            current_from = to_block + 1
            time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("Stopping monitor")
            break
        except Exception as exc:  # keep monitor alive
            print(f"[WARN] monitor loop error: {exc}")
            time.sleep(poll_interval)


if __name__ == "__main__":
    run_monitor()

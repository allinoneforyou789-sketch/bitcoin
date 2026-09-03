#!/usr/bin/env python3
"""
seed phrase miner — generates random BIP39 seed phrases (12/16/24 words),
derives BTC + BEP20 (EVM) addresses, checks balances, and pushes alerts to a Telegram bot.
Run on Render with env vars TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
"""

import os
import sys
import time
import signal
import hashlib
import secrets
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal

import requests
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak

# ---------- config ----------
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

# how many phrase lengths to cycle through
PHRASE_LENGTHS = [12, 16, 24]

# concurrency — tuned for render free tier; raise if you upgrade
WORKERS = int(os.environ.get("MINER_WORKERS", "8"))
# batch size per balance check
BATCH_SIZE = int(os.environ.get("BALANCE_BATCH_SIZE", "8"))

# telegram rate limit safety
TG_DELAY = float(os.environ.get("TG_DELAY", "1.0"))

# check these tokens on BEP20 (address is the same for ETH/BSC/EVM)
BEP20_TOKENS = {
    "BNB": "0x0000000000000000000000000000000000000000",  # native BNB placeholder
    "USDT": "0x55d398326f99059fF775485246999027B3197955",
    "USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
    "BUSD": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
    "CAKE": "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
}

# BSC RPC endpoints (rotate on failure)
BSC_RPCS = [
    "https://bsc-dataseed1.binance.org",
    "https://bsc-dataseed2.binance.org",
    "https://bsc-dataseed3.binance.org",
    "https://bsc-dataseed4.binance.org",
]

# BTC balance check endpoints (rotate on failure)
BTC_APIS = [
    "https://blockchain.info/q/addressbalance/{}",
    "https://api.blockcypher.com/v1/btc/main/addrs/{}",
]

# ---------- telegram ----------
def tg_send(text: str) -> bool:
    """send a message to the configured telegram bot."""
    if not BOT_TOKEN or not CHAT_ID:
        print(f"[tg] missing token/chat id — would send: {text}")
        return False
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        r = requests.post(url, json={"chat_id": CHAT_ID, "text": text}, timeout=15)
        if r.status_code == 200:
            return True
        print(f"[tg] send failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[tg] error: {e}")
    return False

# ---------- crypto helpers ----------
def generate_seed_phrase(length: int) -> str:
    """generate a valid BIP39 mnemonic of given word count."""
    mnemo = Mnemonic("english")
    strength_map = {12: 128, 16: 160, 24: 256}
    strength = strength_map[length]
    return mnemo.generate(strength=strength)

def seed_to_bip32_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """convert mnemonic to BIP39 seed bytes."""
    mnemo = Mnemonic("english")
    return mnemo.to_seed(mnemonic, passphrase=passphrase)

def derive_btc_address(bip39_seed: bytes) -> str:
    """derive a legacy P2PKH BTC address from the BIP39 seed."""
    # m/0'/0'/0/0/0 derivation path
    path = "m/0'/0'/0/0"
    key = BIP32Key.fromEntropy(bip39_seed, net="BTC").ChildKey(0x80000000).ChildKey(0x80000000).ChildKey(0).ChildKey(0)
    return key.Address()

def derive_evm_address(bip39_seed: bytes, account_index: int = 0, address_index: int = 0) -> str:
    """derive an EVM address (same for Ethereum, BSC, Polygon etc.) via BIP44 path."""
    # m/44'/60'/0'/0/0
    key = BIP32Key.fromEntropy(bip39_seed).ChildKey(0x80000000 + 44).ChildKey(0x80000000 + 60)
    key = key.ChildKey(0x80000000 + account_index).ChildKey(0).ChildKey(address_index)
    priv_key = key.PrivateKey()  # 32 bytes
    pub_key = _priv_to_pub(priv_key)
    return _pub_to_evm_address(pub_key)

def _priv_to_pub(priv: bytes) -> bytes:
    """derive compressed secp256k1 public key from private key."""
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return vk.to_string("compressed")

def _pub_to_evm_address(pub: bytes) -> str:
    """convert compressed public key to EVM address (last 20 bytes of keccak256)."""
    # strip compression prefix
    if len(pub) == 33 and pub[0] in (2, 3):
        # decompress
        from ecdsa.curves import SECP256k1 as _SECP
        curve = _SECP
        x = int.from_bytes(pub[1:], "big")
        curve = _SECP
        # recover y
        p = curve.p
        a = curve.a
        b = curve.b
        y_sq = (pow(x, 3, p) + a * x + b) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if y % 2 != pub[0] % 2:
            y = p - y
        pub_uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    else:
        pub_uncompressed = pub

    k = keccak.new(digest_bits=256)
    k.update(pub_uncompressed[1:])  # skip prefix
    digest = k.digest()
    return "0x" + digest[-20:].hex()

def check_btc_balance(address: str) -> float:
    """check BTC balance in BTC."""
    for api in BTC_APIS:
        try:
            url = api.format(address)
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if "blockchain.info" in api:
                    # blockchain.info returns balance in satoshi
                    satoshis = int(data)
                    return satoshis / 1e8
                elif "blockcypher" in api:
                    # blockcypher returns balance in satoshi
                    satoshis = int(data.get("balance", 0))
                    return satoshis / 1e8
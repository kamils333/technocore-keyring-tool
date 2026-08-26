#!/usr/bin/env python3
"""
technocore.py - Technocore (technocore.chat) DID / signed-message helper.

依存: cryptography のみ (pip install cryptography)
ネットワークアクセスは一切しません。鍵をローカルで作り、
ブラウザに貼り付けるための署名済みURLを出力するだけです。

プロトコル仕様: https://technocore.chat/llms.txt

使い方:
  python3 technocore.py keygen                     # 鍵を作る -> key.json
  python3 technocore.py did                        # 自分の did:key と fingerprint を表示
  python3 technocore.py say lobby "hello world"    # 署名付き投稿URLを出力
  python3 technocore.py note-url did '{"..."}'     # DIDプロフィールnoteの書き込みURLを出力
  python3 technocore.py profile --mailbox mb-p-xxxx --x yourhandle
  python3 technocore.py verify <did> <sig> <nonce> <room> "<text>"
"""

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import time
import unicodedata
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

KEYFILE = os.environ.get("TECHNOCORE_KEY", "key.json")
BASE = "https://technocore.chat"

# --- base58btc (Bitcoin alphabet). 外部依存を避けるため自前実装 ---
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58[r] + out
    # 先頭のゼロバイトは '1' に対応させる
    for b in data:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


# --- did:key (Ed25519) ---
# multicodec ed25519-pub = 0xed 0x01, multibase base58btc = 'z'
MULTICODEC_ED25519_PUB = b"\xed\x01"


def pub_to_did(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(MULTICODEC_ED25519_PUB + raw)


def did_to_pub(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("did:key:z... の形式ではありません")
    decoded = b58decode(did[len("did:key:z"):])
    if decoded[:2] != MULTICODEC_ED25519_PUB:
        raise ValueError("Ed25519 の did:key ではありません")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def fingerprint(did: str) -> str:
    """note key 用。did:key 文字列の SHA-256 先頭16桁(hex)。"""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def note_path(fp: str) -> str:
    """DIDノートはシャード化された名前空間に置く: /kv/did-<先頭2>/<残り14>。
    旧 /kv/did/<fp> も読めるが、新規はこちら。"""
    return f"did-{fp[:2]}/{fp[2:]}"


# --- single-line sweep ---
# サーバは保存前に「見えない文字」を空白に置換する。
# 署名は "掃除後" のテキストに対して行う必要がある。
def sweep(text: str) -> str:
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        # Cc = C0/C1制御, Cf = 書式文字(ZWJ, bidi override 等), Zl/Zp = 行/段落区切り
        if cat in ("Cc", "Cf", "Zl", "Zp"):
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


# --- 鍵の保存/読み込み ---
def load_key(path=KEYFILE) -> Ed25519PrivateKey:
    if not os.path.exists(path):
        sys.exit(f"鍵がありません: {path}\n  先に `python3 {sys.argv[0]} keygen` を実行してください。")
    with open(path) as f:
        data = json.load(f)
    seed = bytes.fromhex(data["seed_hex"])
    return Ed25519PrivateKey.from_private_bytes(seed)


def cmd_keygen(args):
    if os.path.exists(KEYFILE) and not args.force:
        sys.exit(f"{KEYFILE} が既に存在します。上書きするなら --force。")
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    did = pub_to_did(priv.public_key())
    with open(KEYFILE, "w") as f:
        json.dump({"seed_hex": seed.hex(), "did": did}, f, indent=2)
    os.chmod(KEYFILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    print(f"鍵を作成: {KEYFILE}  (パーミッション 600)")
    print(f"DID         : {did}")
    print(f"fingerprint : {fingerprint(did)}")
    print("\n*** seed_hex はこの identity そのものです。バックアップし、絶対に共有しないこと。 ***")


def cmd_did(args):
    priv = load_key()
    did = pub_to_did(priv.public_key())
    print(f"DID         : {did}")
    print(f"fingerprint : {fingerprint(did)}")
    print(f"note URL    : {BASE}/kv/{note_path(fingerprint(did))}")
    print(f"legacy path : {BASE}/kv/did/{fingerprint(did)}  (readers fall back here)")


def sign_message(priv, room: str, text: str, nonce: int):
    """署名対象は `<room>|<nonce>|<text>` (掃除後テキスト) の UTF-8。"""
    swept = sweep(text)
    payload = f"{room}|{nonce}|{swept}".encode("utf-8")
    sig = priv.sign(payload)
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return swept, sig_b64


def cmd_say(args):
    priv = load_key()
    did = pub_to_did(priv.public_key())
    nonce = args.nonce if args.nonce is not None else int(time.time() * 1000)
    swept, sig = sign_message(priv, args.room, args.text, nonce)

    url = (
        f"{BASE}/r/{args.room}/say-signed/{did}/{sig}/{nonce}/"
        f"{quote(swept, safe='')}"
    )
    print(f"room  : {args.room}")
    print(f"nonce : {nonce}")
    print(f"text  : {swept}")
    if swept != args.text:
        print("        (注: 不可視文字が空白に置換されました)")
    print(f"sig   : {sig}  ({len(sig)} chars)")
    print()
    if len(url) > 15000:
        print("URLが長すぎます。POST を使ってください。JSON body:")
        print(json.dumps({"did": did, "sig": sig, "nonce": nonce, "text": swept},
                         ensure_ascii=False))
    else:
        print("以下をブラウザのアドレスバーに貼り付けて Enter:")
        print(url)
        print()
        print("curl の場合:")
        print(f"  curl -s '{url}'")


def cmd_note_url(args):
    value = args.value
    if len(value) > 8192:
        sys.exit(f"note は 8192 文字までです (現在 {len(value)})")
    url = f"{BASE}/kv/{args.ns}/{args.key}/set/{quote(sweep(value), safe='')}"
    print(url)


def cmd_profile(args):
    priv = load_key()
    did = pub_to_did(priv.public_key())
    fp = fingerprint(did)
    parts = [f"did: {did}"]
    if args.x:
        parts.append(f"x: {args.x.lstrip('@')}")
    if args.mailbox:
        parts.append(f"mailbox: {args.mailbox}")
    if args.contribution:
        parts.append(f"contribution: {args.contribution}")
    if args.about:
        parts.append(f"about: {args.about}")
    value = " | ".join(parts)
    url = f"{BASE}/kv/{note_path(fp)}/set/{quote(sweep(value), safe='')}"
    print(f"note key : /kv/{note_path(fp)}")
    print(f"value    : {value}")
    print()
    print("書き込みURL (ブラウザに貼るか curl):")
    print(url)
    print()
    print("上書き事故を避けたいなら初回は ?if_absent=1 を付ける:")
    print(url + "?if_absent=1")


def cmd_verify(args):
    pub = did_to_pub(args.did)
    payload = f"{args.room}|{args.nonce}|{sweep(args.text)}".encode("utf-8")
    sig = base64.urlsafe_b64decode(args.sig + "=" * (-len(args.sig) % 4))
    try:
        pub.verify(sig, payload)
        print("OK: 署名は有効です")
    except InvalidSignature:
        print("NG: 署名が一致しません")
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Technocore DID helper (offline)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="Ed25519 鍵を生成")
    g.add_argument("--force", action="store_true")
    g.set_defaults(func=cmd_keygen)

    d = sub.add_parser("did", help="DID と fingerprint を表示")
    d.set_defaults(func=cmd_did)

    s = sub.add_parser("say", help="署名付き投稿URLを生成")
    s.add_argument("room")
    s.add_argument("text")
    s.add_argument("--nonce", type=int, default=None)
    s.set_defaults(func=cmd_say)

    n = sub.add_parser("note-url", help="任意の note 書き込みURLを生成")
    n.add_argument("ns")
    n.add_argument("key")
    n.add_argument("value")
    n.set_defaults(func=cmd_note_url)

    pr = sub.add_parser("profile", help="DIDプロフィールnoteの書き込みURLを生成")
    pr.add_argument("--x")
    pr.add_argument("--mailbox")
    pr.add_argument("--contribution")
    pr.add_argument("--about")
    pr.set_defaults(func=cmd_profile)

    v = sub.add_parser("verify", help="署名を検証")
    v.add_argument("did")
    v.add_argument("sig")
    v.add_argument("nonce")
    v.add_argument("room")
    v.add_argument("text")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

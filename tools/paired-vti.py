#!/usr/bin/env python3
"""Check and apply a paired VTI change to offline pfSense configuration copies."""

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import xml.etree.ElementTree as ET


def read(path, limit=2 * 1024 * 1024):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular lab file named {path.name}.")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path.name} exceeds the size limit.")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    document = data.decode("utf-8-sig")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", document, re.I):
        raise ValueError("XML doctype and entity declarations are outside the lab profile.")
    config = ET.fromstring(document)
    if config.tag != "pfsense":
        raise ValueError("Expected a pfSense configuration copy.")
    return config


def shape(node):
    if node is None:
        return None
    return (node.tag, node.attrib, node.text if node.text and node.text.strip() else None,
            tuple(shape(child) for child in node))


def site_profile(profile):
    expected = {"name", "wan", "vti", "gateway", "outer", "inner", "lan", "ikeid", "reqid"}
    if not isinstance(profile, dict) or set(profile) != expected:
        raise ValueError("Each site must specify its native WAN, VTI, gateway, addresses and identifiers.")
    for key, pattern in {"name": r"[a-z][a-z0-9-]{0,31}", "wan": r"(?:wan|opt[1-9][0-9]{0,3})",
                         "vti": r"opt[1-9][0-9]{0,3}", "gateway": r"[A-Za-z][A-Za-z0-9_]{0,31}"}.items():
        if not isinstance(profile[key], str) or not re.fullmatch(pattern, profile[key]):
            raise ValueError(f"Invalid site field {key}.")
    if profile["wan"] == profile["vti"] or any(type(profile[n]) is not int or not 1 <= profile[n] <= 65535
                                              for n in ("ikeid", "reqid")):
        raise ValueError("Use distinct interfaces and explicit positive IPsec identifiers.")
    if any(not isinstance(profile[key], str) for key in ("outer", "inner", "lan")):
        raise ValueError("Expected textual IPv4 addresses and network.")
    outer = ipaddress.IPv4Address(profile["outer"])
    inner = ipaddress.IPv4Interface(profile["inner"])
    lan = ipaddress.IPv4Network(profile["lan"])
    if (inner.network.prefixlen != 30 or inner.ip not in set(inner.network.hosts()) or
            lan.prefixlen == 0 or outer.is_multicast or outer.is_unspecified or outer.is_loopback or
            lan.overlaps(inner.network) or outer in lan or outer in inner.network):
        raise ValueError("Use a unicast WAN, two usable /30 VTI addresses and a scoped LAN prefix.")
    return {**profile, "outer": str(outer), "inner": inner, "lan": lan}


def profiles(data):
    manifest = json.loads(data)
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or len(manifest.get("sites", [])) != 2:
        raise ValueError("Expected a two-site VTI plan.")
    a, b = map(site_profile, manifest["sites"])
    if (a["name"] == b["name"] or a["outer"] == b["outer"] or a["lan"].overlaps(b["lan"]) or
            a["inner"].network != b["inner"].network or a["inner"].ip == b["inner"].ip or
            any(site["lan"].overlaps(peer["inner"].network) or ipaddress.IPv4Address(peer["outer"]) in site["lan"]
                for site, peer in ((a, b), (b, a)))):
        raise ValueError("The pair has overlapping or inconsistent transport, tunnel or LAN addressing.")
    return a, b


def remove_addition(before, after, parent, tag, match):
    block = after.find(parent)
    entries = [entry for entry in block.findall(tag) if match(entry)] if block is not None else []
    if len(entries) != 1:
        raise ValueError(f"Expected one staged {parent}/{tag} in the named tunnel scope.")
    block.remove(entries[0])
    if before.find(parent) is None and not len(block):
        after.remove(block)
    return entries[0]


def fields(entry, expected):
    for key, value in expected.items():
        node = entry
        for part in key.split("/"):
            children = node.findall(part)
            if len(children) != 1:
                return False
            node = children[0]
        if node.text != value or len(node):
            return False
    return True


def check_guard(config, site, peer):
    rule = next((entry for entry in config.findall("filter/rule")
                 if entry.find("disabled") is None and entry.findtext("floating") == "yes" and
                 entry.findtext("quick") == "yes" and entry.findtext("direction") != "in"), None)
    expected = {"floating": "yes", "direction": "out", "interface": site["wan"], "type": "block",
                "ipprotocol": "inet", "destination/address": str(peer["lan"])}
    allowed = {"floating", "direction", "interface", "type", "ipprotocol", "quick", "source", "destination",
               "protocol", "id", "tracker", "descr", "created", "updated", "log", "statetype"}
    native_empty = {"tag", "tagged", "max", "max-src-nodes", "max-src-conn", "max-src-states", "statetimeout",
                    "statepolicy", "os"}
    if (rule is None or not fields(rule, expected) or rule.attrib or
            any(child.tag not in allowed and (child.tag not in native_empty or child.text or child.attrib or len(child))
                for child in rule) or rule.findtext("protocol", "") not in ("", "any") or
            rule.findtext("statetype", "") not in ("", "keep state", "none") or
            shape(rule.find("source")) != ("source", {}, None, (("any", {}, None, ()),)) or
            shape(rule.find("destination")) != ("destination", {}, None, (("address", {}, str(peer["lan"]), ()),))):
        raise ValueError("The first enabled outbound Floating quick rule must block the private prefix on the WAN.")


def check_change(before_bytes, after_bytes, site, peer):
    before, after = parse(before_bytes), parse(after_bytes)
    ikeid, reqid = str(site["ikeid"]), str(site["reqid"])
    wan = before.find("interfaces/" + site["wan"])
    own_lan = before.findtext("interfaces/lan/ipaddr")
    if (wan is None or wan.findtext("ipaddr") != site["outer"] or own_lan is None or
            ipaddress.IPv4Interface(own_lan + "/" + before.findtext("interfaces/lan/subnet", "32")).network != site["lan"] or
            before.find("ipsec/enable") is None):
        raise ValueError("The original config must have the declared WAN, LAN and enabled IPsec.")
    check_guard(before, site, peer)
    if (before.find(f"ipsec/phase1[ikeid='{ikeid}']") is not None or
            before.find(f"ipsec/phase2[reqid='{reqid}']") is not None or
            before.find("interfaces/" + site["vti"]) is not None or
            before.find(f"gateways/gateway_item[name='{site['gateway']}']") is not None or
            before.find(f"staticroutes/route[network='{peer['lan']}']") is not None):
        raise ValueError("One of the new tunnel objects already exists.")
    p1 = remove_addition(before, after, "ipsec", "phase1", lambda e: e.findtext("ikeid") == ikeid)
    p2 = remove_addition(before, after, "ipsec", "phase2", lambda e: e.findtext("reqid") == reqid)
    iface = remove_addition(before, after, "interfaces", site["vti"], lambda _: True)
    gateway = remove_addition(before, after, "gateways", "gateway_item", lambda e: e.findtext("name") == site["gateway"])
    route = remove_addition(before, after, "staticroutes", "route", lambda e: e.findtext("network") == str(peer["lan"]))
    if (not fields(p1, {"ikeid": ikeid, "interface": site["wan"], "remote-gateway": peer["outer"], "iketype": "ikev2",
                        "protocol": "inet", "authentication_method": "pre_shared_key"}) or
            not fields(p2, {"ikeid": ikeid, "reqid": reqid, "mode": "vti", "protocol": "esp",
                            "localid/type": "address", "remoteid/type": "address",
                            "localid/address": str(site["inner"].ip), "remoteid/address": str(peer["inner"].ip)}) or
            not fields(iface, {"if": "ipsec" + reqid}) or len(iface.findall("enable")) != 1 or
            not fields(gateway, {"name": site["gateway"], "interface": site["vti"],
                                 "gateway": str(peer["inner"].ip), "ipprotocol": "inet"}) or
            not fields(route, {"network": str(peer["lan"]), "gateway": site["gateway"]}) or
            any(e.find("disabled") is not None for e in (p1, p2, gateway, route))):
        raise ValueError("The staged IPsec, VTI, gateway or private route differs from the pair plan.")
    for config in (before, after):
        for revision in config.findall("revision"):
            config.remove(revision)
    if shape(before) != shape(after):
        raise ValueError("The staged copy changes configuration outside the new VTI objects.")
    secret = p1.findtext("pre-shared-key")
    if not secret or len(p1.findall("pre-shared-key")) != 1:
        raise ValueError("Configure the IKEv2 key in both native consoles before exporting the private copies.")
    return secret.encode()


def atomic_write(path, data):
    handle, name = tempfile.mkstemp(prefix=".vti-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def transaction_lock(root):
    lock = root / ".paired-vti-lock"
    with lock.open("xb"):
        pass
    try:
        yield
    finally:
        lock.unlink()


def compensation(changes):
    ambiguous = False
    for target, before, after in reversed(changes):
        try:
            current = read(target)
            if current == before:
                continue
            if current == after:
                atomic_write(target, before)
            else:
                ambiguous = True
        except (OSError, ValueError):
            ambiguous = True
    if ambiguous:
        raise ValueError("An offline configuration needs manual recovery. Preserve the native guard and review the saved copies.")


def execute(root, plan, action):
    data = read(plan, 8192)
    a, b = profiles(data)
    with transaction_lock(root):
        receipt_file = root / ".paired-vti-receipt.json"
        receipt = json.loads(read(receipt_file, 8192)) if receipt_file.exists() else None
        identity = digest(data)
        if receipt is not None and (not isinstance(receipt, dict) or receipt.get("schema") != 1 or
                                    receipt.get("plan_sha256") != identity):
            raise ValueError("The private rollback receipt belongs to another pair plan.")
        changes = []
        preview = []
        secrets = []
        for site, peer in ((a, b), (b, a)):
            folder = root / site["name"]
            if folder.is_symlink() or not folder.is_dir():
                raise ValueError("Use regular site directories under the offline lab root.")
            live = folder / "current.xml"
            backup = folder / "before-vti.xml"
            if action == "rollback":
                if receipt is None:
                    raise ValueError("A paired apply must save its rollback receipt first.")
                expected = next((row for row in receipt["sites"] if row["site"] == site["name"]), None)
                before, current = read(backup), read(live)
                if (expected is None or digest(before) != expected["before_sha256"] or
                        digest(current) not in (expected["before_sha256"], expected["staged_sha256"])):
                    raise ValueError("An offline copy differs from both saved revisions. Review before restoring.")
                changes.append((live, before, current))
                continue
            original = read(backup if backup.exists() else live)
            staged = read(folder / "staged.xml")
            secrets.append(check_change(original, staged, site, peer))
            changes.append((live, original, staged))
            preview.append({"site": site["name"], "vti": site["vti"], "peer": peer["outer"],
                            "private_route": str(peer["lan"]), "before_sha256": digest(original),
                            "staged_sha256": digest(staged)})
        if action == "rollback":
            compensation(changes)
            return {"action": action, "sites": receipt["sites"]}
        if not hmac.compare_digest(*secrets):
            raise ValueError("The staged IKEv2 keys differ.")
        if action == "apply":
            if receipt is not None and receipt["sites"] != preview:
                raise ValueError("The offline copies differ from the saved apply receipt. Use a new lab directory.")
            if any(read(target) != before for target, before, _ in changes):
                raise ValueError("The offline copies changed after preparation. Review both sites.")
            for target, before, _ in changes:
                backup = target.with_name("before-vti.xml")
                if not backup.exists():
                    atomic_write(backup, before)
            if receipt is None:
                receipt = {"schema": 1, "plan_sha256": identity, "sites": preview}
                atomic_write(receipt_file, json.dumps(receipt).encode())
            modified = []
            try:
                for target, before, after in changes:
                    if read(target) != before:
                        raise ValueError("An offline copy changed during application.")
                    modified.append((target, before, after))
                    atomic_write(target, after)
                    if read(target) != after:
                        raise ValueError("The staged offline copy could not be verified.")
            except (OSError, ValueError):
                compensation(modified)
                raise
        return {"action": action, "sites": preview}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Offline lab directory holding copies named current.xml and staged.xml")
    parser.add_argument("plan", type=Path)
    parser.add_argument("action", choices=("preview", "apply", "rollback"))
    args = parser.parse_args()
    try:
        os.umask(0o077)
        print(json.dumps(execute(args.root, args.plan, args.action), indent=2))
    except (OSError, ValueError, ET.ParseError, TypeError, KeyError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()

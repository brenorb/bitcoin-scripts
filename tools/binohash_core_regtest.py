#!/usr/bin/env python3
"""Funded legacy FindAndDelete subset comparison against pinned Bitcoin Core."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (RELEASE, ROOT, START_TIME, Node, RPCError, core_binary,
                          transaction)
from tapscript_csv_regtest import generate as csv_generate

GENERATOR = "binohash_core_fixtures"
ZERO_TXID = "00" * 32
FUNDING_VALUE = 1_000_000
FUNDING_FEE = 10_000
POLICY_REJECTION = "mempool-script-verify-flag-failed (Signature is found in scriptCode)"
CONSENSUS_REJECTION = ("TestBlockValidity failed: block-script-verify-flag-failed "
                       "(Script evaluated without error but finished with a false/empty top "
                       "stack element), input 1 of ")


def generate(funding_txid, destination_script):
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", GENERATOR,
         "--", funding_txid, destination_script], cwd=ROOT)
    return json.loads(raw)


def decoded_matches(node, tx):
    decoded = node.rpc("decoderawtransaction", tx["hex"])
    if tx["base_bytes"] != tx["total_bytes"] or tx["weight"] != 4 * tx["base_bytes"]:
        raise RuntimeError("Expected a complete legacy transaction without witness")
    for expected, actual in (("txid", "txid"), ("weight", "weight"),
                             ("vsize", "vsize"), ("total_bytes", "size")):
        if tx[expected] != decoded[actual]:
            raise RuntimeError(f"Core and Rust disagree on {expected}")
    if decoded["hash"] != tx["txid"] or len(decoded["vin"]) != 2 or len(decoded["vout"]) != 1:
        raise RuntimeError("Decoded legacy transaction shape changed")
    for index, item in enumerate(decoded["vin"]):
        if "txinwitness" in item:
            raise RuntimeError("Legacy fixture unexpectedly gained a witness")
        if len(item["scriptSig"]["hex"]) // 2 != tx["input_script_sig_bytes"][index]:
            raise RuntimeError("Core and Rust disagree on scriptSig length")
    return {"txid": decoded["txid"], "weight": decoded["weight"],
            "vsize": decoded["vsize"], "size": decoded["size"]}


def consensus_probe(node, address, tx, expected_accept):
    height = node.rpc("getblockcount")
    try:
        result = node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        if expected_accept:
            raise RuntimeError(f"Expected a valid legacy spend: {error.message}") from error
        if node.rpc("getblockcount") != height:
            raise RuntimeError("Rejected probe changed chain height")
        return {"accepted": False, "rpc_code": error.code, "reason": error.message}
    if not expected_accept:
        raise RuntimeError("Wrong-selection legacy spend entered a block")
    block = node.rpc("getblock", result["hash"])
    if block["height"] != height + 1 or tx["txid"] not in block["tx"]:
        raise RuntimeError("Accepted block omitted the selected transaction")
    return {"accepted": True, "block_hash": result["hash"], "block_height": block["height"]}


def run(node, report):
    csv_manifest, _ = csv_generate()
    if (csv_manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
            csv_manifest["expected_bitcoin_core_commit"] != RELEASE["commit"]):
        raise RuntimeError("Pinned mining-address source changed Core version")
    address = csv_manifest["mining_address"]
    destination_script = node.rpc("validateaddress", address)["scriptPubKey"]
    if destination_script != csv_manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and mining-address generator disagree")
    report["mining_address"] = address
    report["destination_script_pubkey_hex"] = destination_script
    manifest = generate(ZERO_TXID, destination_script)
    if (manifest["experiment"] != "binohash-legacy-two-choice-core" or
            manifest["funding_txid"] != ZERO_TXID or
            manifest["input_value_sat"] != FUNDING_VALUE or
            len(manifest["results"]) != 2):
        raise RuntimeError("Binohash fixture manifest changed")

    hashes = node.rpc("generatetoaddress", 101, address)
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == destination_script)
    easy = bytes.fromhex(manifest["easy_script_pubkey_hex"])
    bino = bytes.fromhex(manifest["binohash_script_pubkey_hex"])
    outputs = [(FUNDING_VALUE, easy), (FUNDING_VALUE, bino),
               (FUNDING_VALUE, easy), (FUNDING_VALUE, bino),
               (5_000_000_000 - 4 * FUNDING_VALUE - FUNDING_FEE,
                bytes.fromhex(destination_script))]
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding transaction identity changed")
    funding_block = node.rpc("generatetoaddress", 1, address)[0]
    if funding["txid"] not in node.rpc("getblock", funding_block)["tx"]:
        raise RuntimeError("Funding transaction was not confirmed")
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_block
    funded = generate(funding["txid"], destination_script)
    for key in ("experiment", "input_value_sat", "fee_sat", "redeem_script_hex",
                "redeem_script_bytes", "binohash_script_pubkey_hex",
                "easy_script_pubkey_hex", "destination_script_pubkey_hex",
                "pool_signature_a_hex", "pool_signature_b_hex"):
        if funded[key] != manifest[key]:
            raise RuntimeError(f"Funding changed embedded fixture: {key}")
    if len(funded["results"]) != 2 or funded["funding_txid"] != funding["txid"]:
        raise RuntimeError("Funded Binohash fixture shape changed")
    report["fixture"] = funded
    report["results"] = []
    for row in funded["results"]:
        valid = row["valid"]
        wrong = row["wrong_selection"]
        if valid["txid"] == wrong["txid"]:
            raise RuntimeError("Selection mutation did not change transaction identity")
        valid_decode = decoded_matches(node, valid)
        wrong_decode = decoded_matches(node, wrong)
        wrong_policy = node.rpc("testmempoolaccept", [wrong["hex"]])[0]
        wrong_consensus = consensus_probe(node, address, wrong, False)
        valid_policy = node.rpc("testmempoolaccept", [valid["hex"]])[0]
        valid_consensus = consensus_probe(node, address, valid, True)
        if (wrong_policy.get("allowed") is not False or
                wrong_policy.get("reject-reason") != POLICY_REJECTION or
                valid_policy.get("allowed") is not False or
                valid_policy.get("reject-reason") != POLICY_REJECTION or
                wrong_consensus.get("rpc_code") != -25 or
                not wrong_consensus.get("reason", "").startswith(
                    CONSENSUS_REJECTION + wrong["txid"])):
            raise RuntimeError(f"Unexpected policy/consensus category for {row['name']}")
        report["results"].append({
            "name": row["name"], "selected_index": row["selected_index"],
            "local_digest_hex": row["local_digest_hex"],
            "valid": {"transaction": valid, "decoded": valid_decode,
                      "policy": valid_policy, "consensus": valid_consensus},
            "wrong_selection": {"transaction": wrong, "decoded": wrong_decode,
                                "policy": wrong_policy, "consensus": wrong_consensus},
        })


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1 or
            report.get("experiment") != "funded-binohash-legacy-two-choice" or
            report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"] or
            len(report.get("results", [])) != 2 or
            {row.get("name") for row in report["results"]} != {"first", "second"}):
        return False
    if report["results"][0]["local_digest_hex"] == report["results"][1]["local_digest_hex"]:
        return False
    for row in report["results"]:
        valid = row["valid"]
        wrong = row["wrong_selection"]
        if (valid["consensus"].get("accepted") is not True or
                wrong["consensus"].get("accepted") is not False or
                wrong["consensus"].get("rpc_code") != -25 or
                not wrong["consensus"].get("reason", "").startswith(
                    CONSENSUS_REJECTION + wrong["transaction"]["txid"]) or
                valid["policy"].get("allowed") is not False or
                valid["policy"].get("reject-reason") != POLICY_REJECTION or
                wrong["policy"].get("allowed") is not False or
                wrong["policy"].get("reject-reason") != POLICY_REJECTION or
                valid["decoded"]["txid"] != valid["transaction"]["txid"] or
                wrong["decoded"]["txid"] != wrong["transaction"]["txid"] or
                valid["transaction"]["txid"] == wrong["transaction"]["txid"] or
                valid["policy"].get("txid") != valid["transaction"]["txid"] or
                wrong["policy"].get("txid") != wrong["transaction"]["txid"]):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/binohash-core-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-binohash-legacy-two-choice",
              "initial_mocktime": START_TIME, "results": [],
              "scope": "Two-choice, no-grinding legacy P2SH FindAndDelete fixture. Core consensus/policy validates complete funded transactions; local digest generation is separate. No full Binohash protocol or security bound is claimed."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        report["bitcoin_core"] = provenance
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-binohash-") as directory:
            node = Node(binary, Path(directory))
            try:
                node.ready()
                report["node_options"] = node.options
                run(node, report)
            finally:
                node.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    report["run_passed"] = report_passed(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Report: {args.output}", file=sys.stderr)
    return 0 if report["run_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Compare absolute nLockTime boundaries with pinned Core on funded Taproot spends."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core_regtest import (FEE, FUNDING_VALUE, RELEASE, ROOT, START_TIME, Node,
                          RPCError, core_binary, interpreter_provenance, transaction)
from tapscript_csv_regtest import (csv_transaction, generate, validate_funded_manifest,
                                   validate_witness)
from tapscript_maturity_regtest import SECONDS_PER_UNIT, tick_512

NAMES = ("csv-zero-control", "csv-high-zero", "csv-operand-disabled")
BLOCK_REJECTION = "TestBlockValidity failed: bad-txns-nonfinal, non-final transaction"
POLICY_REJECTION = "non-final"


def local_probe(tx, candidate_height=None, candidate_parent_mtp=None):
    request = {"tx_hex": tx["hex"], "candidate_height": candidate_height,
               "candidate_parent_mtp": candidate_parent_mtp}
    raw = subprocess.check_output(
        ["cargo", "run", "--locked", "--quiet", "--example", "absolute_finality_probe"],
        input=json.dumps(request).encode(), cwd=ROOT)
    result = json.loads(raw)
    if result.get("txid") != tx["txid"]:
        raise RuntimeError("Local finality probe used a different transaction")
    return result


def context(node):
    tip = node.rpc("getblockheader", node.rpc("getbestblockhash"))
    return {"tip_hash": tip["hash"], "tip_height": tip["height"],
            "candidate_height": tip["height"] + 1,
            "candidate_parent_mtp": tip["mediantime"]}


def rejected_consensus_probe(node, address, tx):
    height = node.rpc("getblockcount")
    try:
        node.rpc("generateblock", address, [tx["hex"]])
    except RPCError as error:
        result = {"accepted": False, "rpc_code": error.code, "reason": error.message}
        if error.code != -25 or error.message != BLOCK_REJECTION:
            raise RuntimeError(f"Unexpected nonfinal block rejection: {result}") from error
        if node.rpc("getblockcount") != height:
            raise RuntimeError("Rejected finality probe changed chain height")
        return result
    raise RuntimeError("Nonfinal spend entered a block")


def rejected_policy_probe(node, tx):
    result = node.rpc("testmempoolaccept", [tx["hex"]])[0]
    if (result.get("allowed") is not False or result.get("txid") != tx["txid"] or
            result.get("reject-reason") != POLICY_REJECTION):
        raise RuntimeError(f"Unexpected nonfinal policy result: {result}")
    return result


def accepted_policy_probe(node, tx):
    result = node.rpc("testmempoolaccept", [tx["hex"]])[0]
    if (result.get("allowed") is not True or result.get("txid") != tx["txid"] or
            result.get("wtxid") != tx["wtxid"]):
        raise RuntimeError(f"Expected accepted policy result: {result}")
    return result


def selected_fixture(funded, name, funding_txid, mining_script, lock_time):
    fixture = next((row for row in funded["fixtures"] if row["name"] == name), None)
    if fixture is None:
        raise RuntimeError(f"Missing fixture {name}")
    witness = [bytes.fromhex(item) for item in fixture["data_witness_hex"]]
    witness.extend([bytes.fromhex(fixture["script_hex"]),
                    bytes.fromhex(fixture["control_block_hex"])])
    tx = csv_transaction(funding_txid, fixture["funding_vout"], witness,
                         [(FUNDING_VALUE - FEE, mining_script)],
                         fixture["transaction_version"], fixture["input_sequence"], lock_time)
    validate_witness(fixture, witness, tx["witness_bytes"])
    # The source local leaf was run with nLockTime=0. This exact CSV-only leaf
    # reads the unchanged input sequence, not the changed transaction locktime.
    if (fixture["script_hex"] != "b27551" or
            fixture["local_consensus"].get("accepted") is not True or
            fixture["local_policy"].get("accepted") is not True):
        raise RuntimeError(f"Leaf is not locally accepted: {name}")
    if name == "csv-operand-disabled":
        if fixture["input_sequence"] != 0xffffffff:
            raise RuntimeError("All-final sequence control changed")
    elif fixture["input_sequence"] != 0:
        raise RuntimeError(f"Active zero sequence changed: {name}")
    return {"name": name, "transaction": tx, "metrics": fixture["metrics"],
            "local_leaf_consensus": fixture["local_consensus"],
            "local_leaf_policy": fixture["local_policy"]}


def run(node, manifest, report):
    address = manifest["mining_address"]
    mining_script = bytes.fromhex(node.rpc("validateaddress", address)["scriptPubKey"])
    if mining_script.hex() != manifest["destination_script_pubkey_hex"]:
        raise RuntimeError("Core and Rust disagree on destination script")
    hashes = []
    for _ in range(101):
        tick_512(node)
        hashes.extend(node.rpc("generatetoaddress", 1, address))
    coinbase = node.rpc("getblock", hashes[0], 2)["tx"][0]
    coin = next(output for output in coinbase["vout"]
                if output["scriptPubKey"]["hex"] == mining_script.hex())
    outputs = [(FUNDING_VALUE, bytes.fromhex(row["script_pubkey_hex"]))
               for row in manifest["fixtures"]]
    outputs.append((5_000_000_000 - len(outputs) * FUNDING_VALUE - FEE, mining_script))
    funding = transaction(coinbase["txid"], coin["n"], [b"\x51"], outputs)
    if node.rpc("sendrawtransaction", funding["hex"]) != funding["txid"]:
        raise RuntimeError("Funding txid mismatch")
    tick_512(node)
    funding_hash = node.rpc("generatetoaddress", 1, address)[0]
    report["funding_transaction"] = funding
    report["funding_block_hash"] = funding_hash
    report["funding_height"] = node.rpc("getblockheader", funding_hash)["height"]
    funded, digest = generate(funding["txid"])
    validate_funded_manifest(manifest, funded, funding["txid"])
    report["funded_fixture_sha256"] = digest
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
    report["resolved_interpreter"] = interpreter_provenance(funded, metadata)

    before = context(node)
    if before["candidate_height"] != report["funding_height"] + 1:
        raise RuntimeError("Height equality stage is not immediately after funding")
    height_lock = before["candidate_height"]
    time_lock = before["candidate_parent_mtp"]
    rows = [selected_fixture(funded, NAMES[0], funding["txid"], mining_script, height_lock),
            selected_fixture(funded, NAMES[1], funding["txid"], mining_script, time_lock),
            selected_fixture(funded, NAMES[2], funding["txid"], mining_script,
                             time_lock + 100_000)]
    report["equality_context"] = before
    for row in rows[:2]:
        tx = row["transaction"]
        row["equality"] = {
            "local_absolute_finality": local_probe(tx, before["candidate_height"],
                                                      before["candidate_parent_mtp"]),
            "local_without_chain_context": local_probe(tx),
            "core": {"policy": rejected_policy_probe(node, tx),
                     "consensus": rejected_consensus_probe(node, address, tx)}}
    bypass = rows[2]
    bypass_tx = bypass["transaction"]
    bypass["equality"] = {
        "local_absolute_finality": local_probe(bypass_tx, before["candidate_height"],
                                                  before["candidate_parent_mtp"]),
        "local_without_chain_context": local_probe(bypass_tx),
        "core": {"policy": accepted_policy_probe(node, bypass_tx)}}
    tick_512(node)
    bypass_block = node.rpc("generateblock", address, [bypass_tx["hex"]])["hash"]
    bypass_header = node.rpc("getblockheader", bypass_block)
    if (bypass_header["height"] != before["candidate_height"] or
            bypass_tx["txid"] not in node.rpc("getblock", bypass_block)["tx"]):
        raise RuntimeError("All-final sequence control was not mined")
    bypass["equality"]["core"]["consensus"] = {
        "accepted": True, "block_hash": bypass_block, "block_height": bypass_header["height"]}

    after = context(node)
    if (after["candidate_height"] != height_lock + 1 or
            after["candidate_parent_mtp"] <= time_lock):
        raise RuntimeError("First eligible height/MTP stage did not advance")
    report["first_eligible_context"] = after
    for row in rows[:2]:
        tx = row["transaction"]
        row["first_eligible"] = {
            "local_absolute_finality": local_probe(tx, after["candidate_height"],
                                                      after["candidate_parent_mtp"]),
            "core": {"policy": accepted_policy_probe(node, tx)}}
    tick_512(node)
    accepted_block = node.rpc("generateblock", address,
                              [row["transaction"]["hex"] for row in rows[:2]])["hash"]
    block = node.rpc("getblock", accepted_block)
    if (block["height"] != after["candidate_height"] or
            not all(row["transaction"]["txid"] in block["tx"] for row in rows[:2])):
        raise RuntimeError("Eligible block omitted a fixture or used the wrong height")
    for row in rows[:2]:
        row["first_eligible"]["core"]["consensus"] = {
            "accepted": True, "block_hash": accepted_block, "block_height": block["height"]}
    report["results"] = rows


def report_passed(report):
    if ("infrastructure_error" in report or report.get("schema_version") != 1
            or report.get("experiment") != "funded-absolute-finality"
            or report.get("source_manifest_experiment") != "funded-tapscript-csv-five-byte"
            or report.get("source_manifest_fixture_count") != 19
            or report.get("bitcoin_core", {}).get("commit") != RELEASE["commit"]
            or report.get("fixture_count") != len(NAMES)
            or {row.get("name") for row in report.get("results", [])} != set(NAMES)):
        return False
    equality_context = report["equality_context"]
    eligible_context = report["first_eligible_context"]
    if (equality_context["candidate_height"] != report["funding_height"] + 1 or
            eligible_context["candidate_height"] != equality_context["candidate_height"] + 1 or
            eligible_context["candidate_parent_mtp"] <= equality_context["candidate_parent_mtp"]):
        return False
    for row in report["results"]:
        equality = row["equality"]
        txid = row["transaction"]["txid"]
        local = equality["local_absolute_finality"]
        no_context = equality["local_without_chain_context"]
        if (row["local_leaf_consensus"].get("accepted") is not True or
                row["local_leaf_policy"].get("accepted") is not True or
                local.get("txid") != txid or no_context.get("txid") != txid or
                equality["core"]["policy"].get("txid") != txid or
                equality["core"]["consensus"].get("accepted") is not
                (row["name"] == NAMES[2]) or
                equality["core"]["policy"].get("allowed") is not
                (row["name"] == NAMES[2])):
            return False
        if row["name"] == NAMES[2]:
            if (local.get("verdict") != "final" or no_context.get("verdict") != "final" or
                    local.get("input_sequences") != [0xffffffff] or
                    local.get("lock_time", 0) <= equality_context["candidate_parent_mtp"] or
                    equality["core"]["consensus"].get("block_height") !=
                    equality_context["candidate_height"]):
                return False
        elif (local.get("verdict") != "nonfinal" or
              local.get("input_sequences") != [0] or
              no_context.get("verdict") != "unsupported" or
              equality["core"]["policy"].get("reject-reason") != POLICY_REJECTION or
              equality["core"]["consensus"].get("reason") != BLOCK_REJECTION or
              equality["core"]["consensus"].get("rpc_code") != -25 or
              row["first_eligible"]["local_absolute_finality"].get("verdict") != "final" or
              row["first_eligible"]["local_absolute_finality"].get("txid") != txid or
              row["first_eligible"]["core"]["policy"].get("allowed") is not True or
              row["first_eligible"]["core"]["policy"].get("txid") != txid or
              row["first_eligible"]["core"]["consensus"].get("accepted") is not True or
              row["first_eligible"]["core"]["consensus"].get("block_height") !=
              eligible_context["candidate_height"]):
            return False
        if (row["name"] == NAMES[0] and
                local.get("lock_time") != equality_context["candidate_height"] or
                row["name"] == NAMES[1] and
                local.get("lock_time") != equality_context["candidate_parent_mtp"]):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-core", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "target/core-regtest")
    parser.add_argument("--output", type=Path, default=ROOT / "target/tapscript-finality-v30.3.json")
    args = parser.parse_args()
    report = {"schema_version": 1, "experiment": "funded-absolute-finality",
              "fixture_count": len(NAMES), "results": [],
              "initial_mocktime": START_TIME, "block_spacing_seconds": SECONDS_PER_UNIT,
              "consensus_method": "generateblock with funded raw transactions",
              "policy_method": "testmempoolaccept with -acceptnonstdtxn=0; Core v30.3 defaults",
              "scope": "Confirmed single-input Taproot spends at exact height and parent-MTP nLockTime equality and first-eligible boundaries, plus an all-final-sequence bypass. Local leaf and absolute-finality results are distinct; Core validates complete transactions."}
    try:
        binary, provenance = core_binary(args.cache_dir.resolve(), args.download_core)
        manifest, digest = generate()
        if (manifest["expected_bitcoin_core_version"] != RELEASE["version"] or
                manifest["expected_bitcoin_core_commit"] != RELEASE["commit"] or
                manifest["funding_value_sat"] != FUNDING_VALUE or manifest["fee_sat"] != FEE):
            raise RuntimeError("Generator oracle or funding configuration differs")
        report.update({"bitcoin_core": provenance, "manifest_sha256": digest,
                       "source_manifest_experiment": manifest["experiment"],
                       "source_manifest_fixture_count": manifest["fixture_count"]})
        with tempfile.TemporaryDirectory(prefix="bitcoin-lab-finality-") as directory:
            node = Node(binary, Path(directory))
            try:
                node.ready()
                report["node_options"] = node.options
                deployments = node.rpc("getdeploymentinfo")["deployments"]
                if not all(deployments[name]["active"] for name in ("segwit", "taproot", "csv")):
                    raise RuntimeError("Required consensus deployments inactive")
                report["active_consensus_deployments"] = ["segwit", "taproot", "csv"]
                run(node, manifest, report)
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

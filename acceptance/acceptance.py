"""One-shot acceptance service (docker-compose service ``verify``).

Drives the public HTTP API of two independent API instances that share one
persistent volume, then downloads an evidence pack and verifies it offline.
Exits 0 only when every acceptance check passes.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.canonical import dumps, sha256_hex  # noqa: E402
from acceptance.pki_fixtures import (  # noqa: E402
    artifact_algorithm_for,
    make_ca,
    make_crl,
    make_key,
    make_leaf,
    make_ocsp,
    sign_data,
)

UTC = timezone.utc
T = lambda s: datetime.fromisoformat(s + "T00:00:00+00:00")

API_A = os.environ.get("API_A_URL", "http://api-a:8080")
API_B = os.environ.get("API_B_URL", "http://api-b:8080")

# request ids are namespaced per run: the persistent store legitimately
# remembers ids from earlier runs
RUN = os.environ.get("ACCEPTANCE_RUN_ID") or hashlib.sha256(
    f"{time.time()}-{os.getpid()}".encode()).hexdigest()[:12]

SIGNED_AT = "2024-06-01T00:00:00Z"
CUTOFF = "2025-01-01T00:00:00Z"
EARLY = "2024-01-01T00:00:00Z"

# policy OIDs for the continuous policy-mapping scenario
POLICY_P1 = "1.3.6.1.4.1.58181.1"
POLICY_P2 = "1.3.6.1.4.1.58181.2"
POLICY_P3 = "1.3.6.1.4.1.58181.3"
POLICY_P4 = "1.3.6.1.4.1.58181.4"

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail and not cond else ""), flush=True)
    if not cond:
        _failures.append(name)


def wait_healthy(url, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/healthz", timeout=3)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False


def post(url, path, obj, expect=None):
    r = requests.post(f"{url}{path}", data=dumps(obj),
                      headers={"Content-Type": "application/json"}, timeout=120)
    if expect is not None and r.status_code != expect:
        raise AssertionError(f"POST {path} -> {r.status_code}: {r.text[:500]}")
    return r


def build_dataset():
    """A rich dataset: cross-signing, a cycle, revocation flavors, noise."""
    d = {}
    objects = []  # (name, der, otype, received_at)

    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter X", "ec", issuer=root_a, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    inter_b = make_ca("Inter X", "ec", issuer=root_b, key=inter.key,
                      subject_name=inter.cert.subject,
                      not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf_ok = make_leaf(inter, "Leaf OK", "ed", not_before=T("2022-01-01"),
                        not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_rev = make_leaf(inter, "Leaf Revoked", "rsa", not_before=T("2022-01-01"),
                         not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_ocsp = make_leaf(inter, "Leaf OCSP", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_delta = make_leaf(inter, "Leaf Delta", "ed", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_unsup = make_leaf(root_a, "Leaf Unsupported", "ed", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                           pkcs1v15=True)
    # a CA whose only revocation evidence is stale at signed_at
    stale_ca = make_ca("Stale CA", "ec", issuer=root_a, not_before=T("2021-01-01"),
                       not_after=T("2035-01-01"))
    leaf_stale = make_leaf(stale_ca, "Leaf Stale", "ec", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    # cycle: two CAs cross-signing each other, anchored nowhere
    cyc_x = make_ca("Cycle X", "ec", not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    cyc_y = make_ca("Cycle Y", "ec", issuer=cyc_x, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    cyc_x2 = make_ca("Cycle X", "ec", issuer=cyc_y, key=cyc_x.key,
                     subject_name=cyc_x.cert.subject,
                     not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf_cycle = make_leaf(cyc_x2, "Leaf Cycle", "ed", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])

    certs = [root_a, root_b, inter, inter_b, leaf_ok, leaf_rev, leaf_stale,
             leaf_ocsp, leaf_delta, leaf_unsup, stale_ca, cyc_x, cyc_y, cyc_x2,
             leaf_cycle]
    d.update(root_a=root_a, root_b=root_b, inter=inter, inter_b=inter_b,
             leaf_ok=leaf_ok, leaf_rev=leaf_rev, leaf_stale=leaf_stale,
             leaf_ocsp=leaf_ocsp, leaf_delta=leaf_delta, leaf_unsup=leaf_unsup,
             stale_ca=stale_ca, cyc_x=cyc_x, cyc_y=cyc_y, cyc_x2=cyc_x2,
             leaf_cycle=leaf_cycle)

    # noise: unrelated certs (cross-signed ring + junk) that must not disturb
    rng = random.Random(20240919)
    noise = []
    noise_keys = []
    for i in range(60):
        kind = ("rsa", "ec", "ed")[i % 3]
        noise_keys.append((f"noise-{i}", make_key(kind)))
    noise_cas = []
    for i in range(12):
        name, key = noise_keys[i]
        ca = make_ca(f"Noise CA {i}", "ec", key=key, not_before=T("2020-01-01"),
                     not_after=T("2040-01-01"))
        noise_cas.append(ca)
        noise.append(ca)
    # cross-signed noise ring
    for i in range(12):
        ca = noise_cas[i]
        issuer = noise_cas[(i + 1) % 12]
        cross = make_ca(f"Noise CA {i}", "ec", issuer=issuer, key=ca.key,
                        subject_name=ca.cert.subject, not_before=T("2020-01-01"),
                        not_after=T("2040-01-01"))
        noise.append(cross)
    for i in range(36):
        issuer = noise_cas[i % 12]
        leaf = make_leaf(issuer, f"Noise Leaf {i}", ("rsa", "ec", "ed")[i % 3],
                         not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                         eku=["1.3.6.1.5.5.7.3.3"])
        noise.append(leaf)
    for e in noise:
        certs.append(e)

    for e in certs:
        objects.append((f"cert:{e.cn}:{sha256_hex(e.der)[:8]}", e.der, "certificate", EARLY))

    # revocation evidence
    inter_crl = make_crl(
        inter,
        entries=[(leaf_rev.cert.serial_number, T("2024-03-01"), "keyCompromise")],
        crl_number=5, this_update=T("2024-05-01"), next_update=T("2024-07-01"))
    objects.append(("crl:inter", inter_crl, "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:stale", make_crl(
        inter, entries=[], crl_number=4, this_update=T("2024-01-01"),
        next_update=T("2024-02-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:root-a", make_crl(
        root_a, entries=[], crl_number=3, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:root-b", make_crl(
        root_b, entries=[], crl_number=3, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:stale-ca", make_crl(
        stale_ca, entries=[], crl_number=1, this_update=T("2024-01-01"),
        next_update=T("2024-02-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:cycle-x", make_crl(
        cyc_x, entries=[], crl_number=1, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:cycle-y", make_crl(
        cyc_y, entries=[], crl_number=1, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    # delta CRL chain: base carries leaf_rev forward, delta adds leaf_delta
    objects.append(("crl:delta-base", make_crl(
        inter, entries=[(leaf_rev.cert.serial_number, T("2024-03-01"),
                         "keyCompromise")],
        crl_number=8, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:delta", make_crl(
        inter, entries=[(leaf_delta.cert.serial_number, T("2024-03-01"),
                         "keyCompromise")],
        crl_number=9, this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        delta_base_number=8), "crl", "2024-06-15T00:00:00Z"))
    # OCSP: direct for leaf_ocsp (good), delegated responder for a second case
    objects.append(("ocsp:leaf-ocsp", make_ocsp(
        inter, serial=leaf_ocsp.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-06-20")), "ocsp",
        "2024-06-15T00:00:00Z"))
    responder = make_leaf(inter, "OCSP Responder", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.9"])
    objects.append(("cert:responder", responder.der, "certificate", EARLY))
    d["responder"] = responder
    objects.append(("ocsp:leaf-ok-delegated", make_ocsp(
        inter, serial=leaf_ok.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-06-20"),
        responder=responder), "ocsp", "2024-06-15T00:00:00Z"))
    # a late-archived CRL revoking leaf_ok (must be inadmissible)
    objects.append(("crl:late", make_crl(
        inter, entries=[(leaf_ok.cert.serial_number, T("2024-03-01"),
                         "keyCompromise")],
        crl_number=10, this_update=T("2024-05-25"), next_update=T("2024-07-01")),
        "crl", "2025-06-01T00:00:00Z"))
    return d, objects


def adjudication_input(leaf, anchors, artifact=b"acceptance artifact",
                       initial_policy_set=None):
    digest = hashlib.sha256(artifact).hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    inp = {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": SIGNED_AT,
        "knowledge_cutoff": CUTOFF,
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(a.der) for a in anchors],
    }
    if initial_policy_set is not None:
        inp["initial_policy_set"] = initial_policy_set
    return inp


def build_policy_dataset():
    """Continuous policy-mapping chains and their boundary scenarios.

    The headline chain is root <- I1 (P1, maps P1->P2) <- I2 (P2, maps
    P2->P3) <- leaf (P3); with initial policy set [P1] it must validate.
    Companion leaves exercise single mapping, anyPolicy, the empty policy
    tree, mapping inhibition and requireExplicitPolicy boundaries.
    """
    objects = []
    root = make_ca("Policy Root", "rsa", not_before=T("2020-01-01"),
                   not_after=T("2040-01-01"))
    i1 = make_ca("Policy I1", "ec", issuer=root, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[POLICY_P1],
                 policy_mappings=[(POLICY_P1, POLICY_P2)])
    i2 = make_ca("Policy I2", "ec", issuer=i1, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[POLICY_P2],
                 policy_mappings=[(POLICY_P2, POLICY_P3)])
    # three-level extension chain for a second fixture set
    j1 = make_ca("Policy J1", "ec", issuer=root, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[POLICY_P1],
                 policy_mappings=[(POLICY_P1, POLICY_P2)])
    j2 = make_ca("Policy J2", "ec", issuer=j1, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[POLICY_P2],
                 policy_mappings=[(POLICY_P2, POLICY_P3)])
    j3 = make_ca("Policy J3", "ec", issuer=j2, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[POLICY_P3],
                 policy_mappings=[(POLICY_P3, POLICY_P4)])

    def _leaf(issuer, cn, **kw):
        return make_leaf(issuer, cn, "ed", not_before=T("2022-01-01"),
                         not_after=T("2030-01-01"),
                         eku=["1.3.6.1.5.5.7.3.3"], **kw)

    leaf_chain = _leaf(i2, "Policy Leaf P1P2P3", policies=[POLICY_P3])
    leaf_three = _leaf(j3, "Policy Leaf P1P2P3P4", policies=[POLICY_P4])
    leaf_any = _leaf(i2, "Policy Leaf Any", policies=["2.5.29.32.0"])
    leaf_nopol = _leaf(i2, "Policy Leaf NoPol")

    # mapping inhibition: the CA's own inhibitPolicyMapping=0 blocks its
    # P1->P2 mapping, so a leaf asserting P2 cannot satisfy [P1]
    root_inh = make_ca("Policy Root Inh", "rsa", not_before=T("2020-01-01"),
                       not_after=T("2040-01-01"))
    i_inh = make_ca("Policy I Inh", "ec", issuer=root_inh,
                    not_before=T("2021-01-01"), not_after=T("2035-01-01"),
                    policies=[POLICY_P1], policy_mappings=[(POLICY_P1, POLICY_P2)],
                    policy_constraints={"inhibit_mapping": 0})
    leaf_inh = _leaf(i_inh, "Policy Leaf Inh", policies=[POLICY_P2])

    # requireExplicitPolicy=0 on the CA directly above the leaf
    root_req = make_ca("Policy Root Req", "rsa", not_before=T("2020-01-01"),
                       not_after=T("2040-01-01"))
    i_req = make_ca("Policy I Req", "ec", issuer=root_req,
                    not_before=T("2021-01-01"), not_after=T("2035-01-01"),
                    policies=[POLICY_P1],
                    policy_constraints={"require_explicit": 0})
    leaf_req_ok = _leaf(i_req, "Policy Leaf ReqOK", policies=[POLICY_P1])
    leaf_req_empty = _leaf(i_req, "Policy Leaf ReqEmpty")

    certs = [root, i1, i2, j1, j2, j3, leaf_chain, leaf_three, leaf_any,
             leaf_nopol, root_inh, i_inh, leaf_inh, root_req, i_req,
             leaf_req_ok, leaf_req_empty]
    for e in certs:
        objects.append((f"cert:{e.cn}:{sha256_hex(e.der)[:8]}", e.der,
                        "certificate", EARLY))
    for ca in (root, i1, i2, j1, j2, j3, root_inh, i_inh, root_req, i_req):
        objects.append((f"crl:{ca.cn}", make_crl(
            ca, entries=[], crl_number=1, this_update=T("2024-05-01"),
            next_update=T("2024-07-01")), "crl", EARLY))
    d = {"root": root, "i1": i1, "i2": i2, "leaf_chain": leaf_chain,
         "leaf_three": leaf_three, "leaf_any": leaf_any,
         "leaf_nopol": leaf_nopol, "root_inh": root_inh, "leaf_inh": leaf_inh,
         "root_req": root_req, "leaf_req_ok": leaf_req_ok,
         "leaf_req_empty": leaf_req_empty}
    return d, objects


def main():
    print(f"acceptance: API_A={API_A} API_B={API_B}", flush=True)
    check("api-a healthy", wait_healthy(API_A))
    check("api-b healthy", wait_healthy(API_B))
    if _failures:
        return 1

    d, objects = build_dataset()
    by_fp = {}
    for name, der, otype, rcv in objects:
        by_fp[sha256_hex(der)] = (name, der, otype, rcv)

    # -- create evidence set -------------------------------------------------
    create = post(API_A, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-1",
                                               "label": "acceptance"}, 201)
    set_id = json.loads(create.content)["evidence_set_id"]
    # idempotent replay + conflict
    replay = post(API_B, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-1",
                                               "label": "acceptance"})
    check("create idempotent replay", replay.content == create.content)
    conflict = post(API_A, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-1",
                                                 "label": "different"})
    check("create idempotency conflict", conflict.status_code == 409)

    # -- upload in shuffled batches across both instances --------------------
    rng = random.Random(7)
    order = list(objects)
    rng.shuffle(order)
    batches = [order[i : i + 17] for i in range(0, len(order), 17)]
    apis = [API_A, API_B]
    total_added = 0
    for i, batch in enumerate(batches):
        body = {
            "request_id": f"acc-{RUN}-add-{i}",
            "objects": [
                {"type": otype, "der": base64.b64encode(der).decode(),
                 "received_at": rcv}
                for (_name, der, otype, rcv) in batch
            ],
        }
        r = post(apis[i % 2], f"/v1/evidence-sets/{set_id}/objects", body, 200)
        parsed = json.loads(r.content)
        check(f"batch {i} accepted", not parsed["rejected"],
              json.dumps(parsed["rejected"])[:300])
        total_added += len(parsed["added"])
        if i == 0:
            # identical replay returns the original response
            r2 = post(apis[1], f"/v1/evidence-sets/{set_id}/objects", body)
            check("batch replay identical", r2.content == r.content)
            # same request id, different content -> conflict
            body2 = dict(body)
            body2["objects"] = body["objects"][:1]
            r3 = post(API_A, f"/v1/evidence-sets/{set_id}/objects", body2)
            check("batch id conflict", r3.status_code == 409)
    check("all objects uploaded", total_added == len(objects),
          f"{total_added} != {len(objects)}")

    # -- concurrent seal from both instances ---------------------------------
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_a = pool.submit(post, API_A, f"/v1/evidence-sets/{set_id}/seal",
                          {"request_id": f"acc-{RUN}-seal-a"})
        f_b = pool.submit(post, API_B, f"/v1/evidence-sets/{set_id}/seal",
                          {"request_id": f"acc-{RUN}-seal-b"})
        seal_a, seal_b = f_a.result(), f_b.result()
    check("concurrent seal ok", seal_a.status_code == 200 and seal_b.status_code == 200)
    digest_a = json.loads(seal_a.content)["content_digest"]
    digest_b = json.loads(seal_b.content)["content_digest"]
    check("single immutable manifest", digest_a == digest_b)
    content_digest = digest_a

    # uploads after seal are rejected
    late = post(API_A, f"/v1/evidence-sets/{set_id}/objects", {
        "request_id": f"acc-{RUN}-after-seal",
        "objects": [{"type": "certificate",
                     "der": base64.b64encode(d["root_a"].der).decode(),
                     "received_at": EARLY}]})
    check("sealed set immutable", late.status_code == 409)

    # -- upload-order independence: a second set with the same objects in a
    #    different order must seal to the identical manifest digest ----------
    create2 = post(API_B, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-2"}, 201)
    set_id2 = json.loads(create2.content)["evidence_set_id"]
    order2 = list(objects)
    rng.shuffle(order2)
    for i in range(0, len(order2), 29):
        batch = order2[i : i + 29]
        body = {
            "request_id": f"acc-{RUN}-add2-{i}",
            "objects": [
                {"type": otype, "der": base64.b64encode(der).decode(),
                 "received_at": rcv}
                for (_name, der, otype, rcv) in batch
            ],
        }
        post(apis[i % 2], f"/v1/evidence-sets/{set_id2}/objects", body, 200)
    seal2 = post(API_A, f"/v1/evidence-sets/{set_id2}/seal",
                 {"request_id": f"acc-{RUN}-seal-2"}, 200)
    digest2 = json.loads(seal2.content)["content_digest"]
    check("upload order does not affect manifest", digest2 == content_digest)

    # -- adjudications ---------------------------------------------------------
    cases = [
        ("valid-cross-signed", d["leaf_ok"], [d["root_a"], d["root_b"]], "VALID"),
        ("valid-single-anchor", d["leaf_ok"], [d["root_b"]], "VALID"),
        ("revoked-leaf", d["leaf_rev"], [d["root_a"]], "INVALID"),
        ("stale-evidence", d["leaf_stale"], [d["root_a"]], "INVALID"),
        ("ocsp-good", d["leaf_ocsp"], [d["root_a"]], "VALID"),
        ("delta-revoked", d["leaf_delta"], [d["root_a"]], "INVALID"),
        ("cycle-leaf", d["leaf_cycle"], [d["root_a"]], "INVALID"),
        ("unsupported-leaf", d["leaf_unsup"], [d["root_a"]], "UNSUPPORTED"),
    ]
    results = {}
    for idx, (name, leaf, anchors, expected) in enumerate(cases):
        inp = adjudication_input(leaf, anchors)
        r_a = post(API_A, "/v1/adjudications",
                   {"request_id": f"acc-{RUN}-adj-{idx}", "evidence_set_id": set_id,
                    "input": inp})
        check(f"{name}: adjudicated", r_a.status_code == 201, r_a.text[:300])
        body = json.loads(r_a.content)
        check(f"{name}: verdict {expected}", body["verdict"] == expected,
              f"got {body['verdict']}")
        results[name] = body
        # same adjudication via the other instance must be byte-identical
        r_b = post(API_B, "/v1/adjudications",
                   {"request_id": f"acc-{RUN}-adj-b-{idx}", "evidence_set_id": set_id,
                    "input": inp})
        check(f"{name}: cross-instance determinism", r_b.content == r_a.content)
        # idempotent replay
        r_re = post(API_A, "/v1/adjudications",
                    {"request_id": f"acc-{RUN}-adj-{idx}", "evidence_set_id": set_id,
                     "input": inp})
        check(f"{name}: idempotent replay", r_re.content == r_a.content)

    # late CRL must have been excluded for the valid leaf
    acct = {r["fingerprint"]: r for r in results["valid-cross-signed"]["evidence_accounting"]}
    late_fp = sha256_hex([o for o in objects if o[0] == "crl:late"][0][1])
    check("late evidence excluded", acct.get(late_fp, {}).get("reason") == "RECEIVED_AFTER_CUTOFF")
    check("late evidence did not change verdict",
          results["valid-cross-signed"]["verdict"] == "VALID")

    # -- continuous policy mappings ----------------------------------------
    pd, pol_objects = build_policy_dataset()
    pcreate = post(API_A, "/v1/evidence-sets",
                   {"request_id": f"acc-{RUN}-pol-create", "label": "policies"}, 201)
    pset_id = json.loads(pcreate.content)["evidence_set_id"]
    post(API_B, f"/v1/evidence-sets/{pset_id}/objects", {
        "request_id": f"acc-{RUN}-pol-add",
        "objects": [
            {"type": otype, "der": base64.b64encode(der).decode(),
             "received_at": rcv}
            for (_name, der, otype, rcv) in pol_objects
        ],
    }, 200)
    post(API_A, f"/v1/evidence-sets/{pset_id}/seal",
         {"request_id": f"acc-{RUN}-pol-seal"}, 200)

    def adjudicate_policy(name, leaf, initial, expect, anchors=None):
        inp = adjudication_input(leaf, anchors or proot,
                                 initial_policy_set=initial)
        r = post(API_A, "/v1/adjudications",
                 {"request_id": f"acc-{RUN}-pol-{name}",
                  "evidence_set_id": pset_id, "input": inp}, 201)
        body = json.loads(r.content)
        check(f"policy {name}: verdict {expect}", body["verdict"] == expect,
              f"got {body['verdict']}")
        return body

    def policy_rule(body):
        return {r["rule"]: r for r in body["decision"]["path_rules"]}["POLICIES"]

    def first_policy_failure(body):
        for branch in body["decision"]["rejection_proof"]["branches"]:
            if branch["failure"]["rule"] == "POLICIES":
                return branch["failure"]
        return None

    proot = [pd["root"]]
    body = adjudicate_policy("continuous-p1", pd["leaf_chain"], [POLICY_P1],
                             "VALID")
    if body["verdict"] == "VALID":
        rule = policy_rule(body)
        check("continuous mapping final valid set [P1]",
              rule["valid_policies"] == [POLICY_P1], str(rule.get("valid_policies")))
        layers = rule["policy_trace"]["certificates"]
        # each CA keeps asserting its own policy; its mapping instead rewrites
        # the policy expected one layer down (visible in the next layer)
        check("continuous mapping per-layer trace",
              [e["valid_policies_after_certificate"] for e in layers] == [
                  [POLICY_P1], [POLICY_P2], [POLICY_P3]] and
              layers[0]["policy_mappings"] == [[POLICY_P1, POLICY_P2]] and
              layers[1]["policy_mappings"] == [[POLICY_P2, POLICY_P3]] and
              all(e["mapping_permitted"] for e in layers[:-1]),
              json.dumps(layers)[:400])
        check("continuous mapping wrap-up", rule["policy_trace"]["wrap_up"][
            "valid_policies"] == [POLICY_P1])

    body_bad = adjudicate_policy("continuous-p4", pd["leaf_chain"],
                                 [POLICY_P4], "INVALID")
    if body_bad["verdict"] != "VALID":
        failure = first_policy_failure(body_bad)
        check("continuous mapping mismatch first rule",
              failure is not None and failure["code"] == "POLICY_INITIAL_SET_MISMATCH",
              str(failure)[:300])
        check("rejected branch carries policy trace",
              failure is not None and len(
                  failure["policy_trace"]["certificates"]) == 3)

    body3 = adjudicate_policy("three-level-p1", pd["leaf_three"],
                              [POLICY_P1], "VALID")
    if body3["verdict"] == "VALID":
        check("three-level mapping final valid set [P1]",
              policy_rule(body3)["valid_policies"] == [POLICY_P1])

    body_any = adjudicate_policy("leaf-any", pd["leaf_any"], [POLICY_P1],
                                 "VALID")
    if body_any["verdict"] == "VALID":
        check("anyPolicy leaf satisfies [P1]",
              policy_rule(body_any)["valid_policies"] == [POLICY_P1])

    body_empty = adjudicate_policy("empty-tree-default", pd["leaf_nopol"],
                                   None, "VALID")
    if body_empty["verdict"] == "VALID":
        check("empty policy tree valid set is []",
              policy_rule(body_empty)["valid_policies"] == [])
    body_empty_bad = adjudicate_policy("empty-tree-specific",
                                       pd["leaf_nopol"], [POLICY_P1], "INVALID")
    if body_empty_bad["verdict"] != "VALID":
        failure = first_policy_failure(body_empty_bad)
        check("empty tree + specific initial set first rule",
              failure is not None and
              failure["code"] == "POLICY_INITIAL_SET_MISMATCH")

    body_inh = adjudicate_policy("mapping-inhibited", pd["leaf_inh"],
                                 [POLICY_P1], "INVALID", anchors=[pd["root_inh"]])
    if body_inh["verdict"] != "VALID":
        failure = first_policy_failure(body_inh)
        check("inhibited mapping first rule",
              failure is not None and
              failure["code"] == "POLICY_INITIAL_SET_MISMATCH", str(failure)[:300])

    body_req_ok = adjudicate_policy("explicit-required-asserted",
                                    pd["leaf_req_ok"], [POLICY_P1], "VALID",
                                    anchors=[pd["root_req"]])
    if body_req_ok["verdict"] == "VALID":
        check("explicit required with asserted policy set",
              policy_rule(body_req_ok)["valid_policies"] == [POLICY_P1])
    body_req_empty = adjudicate_policy("explicit-required-empty",
                                       pd["leaf_req_empty"], [POLICY_P1],
                                       "INVALID", anchors=[pd["root_req"]])
    if body_req_empty["verdict"] != "VALID":
        failure = first_policy_failure(body_req_empty)
        check("explicit required + empty tree first rule",
              failure is not None and failure["code"] == "POLICY_TREE_EMPTY",
              str(failure)[:300])

    # the continuous-mapping pack must recompute offline to the same result
    pol_adj = body["adjudication_id"]
    pol_pack = requests.get(f"{API_A}/v1/adjudications/{pol_adj}/evidence-pack",
                            timeout=120)
    check("policy pack download", pol_pack.status_code == 200)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(pol_pack.content)
        ppath = fh.name
    proc = subprocess.run([sys.executable, "-m", "app.verify", ppath],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check("policy pack offline recomputation", proc.returncode == 0,
          proc.stdout[-500:] + proc.stderr[-500:])
    pack_obj = json.loads(pol_pack.content)
    check("policy pack records per-layer state",
          all("policy_trace" in r for r in pack_obj["result"]["decision"]["path_rules"]
              if r["rule"] == "POLICIES"))

    # -- evidence pack + offline verification --------------------------------
    adj_id = results["valid-cross-signed"]["adjudication_id"]
    pack = requests.get(f"{API_B}/v1/adjudications/{adj_id}/evidence-pack",
                        timeout=120)
    check("pack download", pack.status_code == 200)
    pack_digest = hashlib.sha256(pack.content).hexdigest()
    check("pack digest header",
          pack.headers.get("X-Evidence-Pack-SHA256") == pack_digest)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(pack.content)
        pack_path = fh.name
    proc = subprocess.run([sys.executable, "-m", "app.verify", pack_path],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print(proc.stdout, flush=True)
    check("offline pack verification", proc.returncode == 0,
          proc.stdout[-500:] + proc.stderr[-500:])

    # tampered packs must fail
    pack_obj = json.loads(pack.content)
    for tname, mutate in [
        ("verdict", lambda p: p["result"].__setitem__("verdict", "INVALID")),
        ("input", lambda p: p["input"].__setitem__("signed_at", "2024-06-02T00:00:00Z")),
        ("manifest", lambda p: p["evidence_set"].__setitem__("content_digest", "0" * 64)),
    ]:
        tampered = json.loads(dumps(pack_obj))
        mutate(tampered)
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(dumps(tampered))
            tpath = fh.name
        proc = subprocess.run([sys.executable, "-m", "app.verify", tpath],
                              capture_output=True, text=True,
                              cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        check(f"tamper-{tname} detected", proc.returncode != 0)

    # rejection-proof case also produces a verifiable pack
    adj_bad = results["revoked-leaf"]["adjudication_id"]
    pack_bad = requests.get(f"{API_A}/v1/adjudications/{adj_bad}/evidence-pack",
                            timeout=120)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(pack_bad.content)
        bad_path = fh.name
    proc = subprocess.run([sys.executable, "-m", "app.verify", bad_path],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check("rejection pack verification", proc.returncode == 0)

    if _failures:
        print(f"\nACCEPTANCE FAILED ({len(_failures)} checks): {_failures}", flush=True)
        return 1
    print("\nACCEPTANCE PASSED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

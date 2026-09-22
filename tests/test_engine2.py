"""Engine tests, part 2: path selection, PSS-OCSP, URI constraints, more."""
from __future__ import annotations

from datetime import datetime, timezone

from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import make_ca, make_crl, make_leaf, make_ocsp
from tests.conftest import Bag, EARLY, T, adjudicate

UTC = timezone.utc


def test_shorter_path_revoked_longer_path_valid():
    """The engine must not lock onto the shortest chain before revocation."""
    bag = Bag()
    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    bridge = make_ca("Bridge", "ec", issuer=root_b, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"))
    inter = make_ca("Inter", "ec", issuer=root_a, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    # same key+subject also issued by bridge (longer path)
    inter2 = make_ca("Inter", "ec", issuer=bridge, key=inter.key,
                     subject_name=inter.cert.subject,
                     not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root_a, root_b, bridge, inter, inter2, leaf):
        bag.cert(e)
    # root A revokes inter (the short path's intermediate)
    bag.add(make_crl(root_a, entries=[(inter.cert.serial_number, T("2024-03-01"),
                                       "keyCompromise")],
                     crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root_b, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(bridge, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    anchors = [sha256_hex(root_a.der), sha256_hex(root_b.der)]
    res = adjudicate(bag, sha256_hex(leaf.der), anchors, leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    path = res["decision"]["path"]
    assert len(path) == 4  # the longer, still-valid path wins
    assert path[1] == sha256_hex(inter2.der)
    assert path[2] == sha256_hex(bridge.der)


def test_pss_ocsp_response():
    """OCSP response signed with RSA-PSS (fixture DER surgery)."""
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"


def test_ocsp_unknown_status():
    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="unknown",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "UNKNOWN"


def test_stale_crl_with_old_revocation_still_revokes():
    """A stale CRL that recorded a revocation before signed_at still proves it."""
    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    # stale CRL (nextUpdate < signed_at) but lists the leaf revoked long ago
    bag.add(make_crl(inter, entries=[(leaf.cert.serial_number, T("2024-01-15"),
                                      "keyCompromise")],
                     crl_number=1, this_update=T("2024-01-20"),
                     next_update=T("2024-02-20")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "REVOKED"


def test_uri_name_constraints():
    from cryptography import x509

    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.UniformResourceIdentifier(".example.com")],
        excluded_subtrees=[x509.UniformResourceIdentifier("bad.example.com")],
    )
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), name_constraints=nc)
    leaf_ok = make_leaf(inter, "LeafOK", "ed", not_before=T("2022-01-01"),
                        not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                        san_uri=["https://www.example.com/app"])
    leaf_excl = make_leaf(inter, "LeafExcl", "ed", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                          san_uri=["https://bad.example.com/app"])
    leaf_apex = make_leaf(inter, "LeafApex", "ed", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                          san_uri=["https://example.com/app"])
    for e in (root, inter, leaf_ok, leaf_excl, leaf_apex):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    anchor = sha256_hex(root.der)
    res_ok = adjudicate(bag, sha256_hex(leaf_ok.der), [anchor], leaf_key=leaf_ok.key)
    assert res_ok["verdict"] == "VALID", dumps(res_ok["decision"]).decode()
    res_excl = adjudicate(bag, sha256_hex(leaf_excl.der), [anchor], leaf_key=leaf_excl.key)
    assert res_excl["verdict"] == "INVALID"
    assert "NAME_CONSTRAINT_EXCLUDED" in res_excl["summary"]["failure_codes"]
    # ".example.com" permits subdomains only, not the apex host
    res_apex = adjudicate(bag, sha256_hex(leaf_apex.der), [anchor], leaf_key=leaf_apex.key)
    assert res_apex["verdict"] == "INVALID"
    assert "NAME_CONSTRAINT_NOT_PERMITTED" in res_apex["summary"]["failure_codes"]


def test_require_explicit_policy():
    P1 = "1.3.6.1.4.1.99999.1"
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1],
                    policy_constraints={"require_explicit": 0})
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=[P1])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    anchor = sha256_hex(root.der)
    res = adjudicate(bag, sha256_hex(leaf.der), [anchor], leaf_key=leaf.key,
                     initial_policy_set=[P1])
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    # with a leaf that asserts nothing, explicit policy required -> fail
    bag2 = Bag()
    root2 = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter2 = make_ca("Inter", "ec", issuer=root2, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"), policies=[P1],
                     policy_constraints={"require_explicit": 0})
    leaf2 = make_leaf(inter2, "Leaf", "ed", not_before=T("2022-01-01"),
                      not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root2, inter2, leaf2):
        bag2.cert(e)
    bag2.add(make_crl(inter2, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl", EARLY)
    bag2.add(make_crl(root2, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl", EARLY)
    res2 = adjudicate(bag2, sha256_hex(leaf2.der), [sha256_hex(root2.der)],
                      leaf_key=leaf2.key, initial_policy_set=[P1])
    assert res2["verdict"] == "INVALID"
    assert "POLICY" in ",".join(res2["summary"]["failure_codes"])


def test_policy_two_level_continuous_mapping():
    """P1 ->(CA1)-> P2 ->(CA2)-> P3 must compose: leaf P3 satisfies [P1]."""
    P1, P2, P3 = ("1.3.6.1.4.1.99999.1", "1.3.6.1.4.1.99999.2",
                  "1.3.6.1.4.1.99999.3")
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    ca1 = make_ca("CA1", "ec", issuer=root, not_before=T("2021-01-01"),
                  not_after=T("2035-01-01"), policies=[P1],
                  policy_mappings=[(P1, P2)])
    ca2 = make_ca("CA2", "ec", issuer=ca1, not_before=T("2021-06-01"),
                  not_after=T("2034-01-01"), policies=[P2],
                  policy_mappings=[(P2, P3)])
    leaf = make_leaf(ca2, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=[P3])
    for e in (root, ca1, ca2, leaf):
        bag.cert(e)
    for issuer in (root, ca1, ca2):
        bag.add(make_crl(issuer, entries=[], crl_number=1, this_update=T("2024-05-01"),
                         next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    pol = [r for r in res["decision"]["path_rules"] if r["rule"] == "POLICIES"][0]
    assert pol["result"] == "pass"
    assert pol["valid_policies"] == [P3]
    trace = pol["policy_trace"]
    assert [layer["certificate"] for layer in trace] == [
        sha256_hex(ca1.der), sha256_hex(ca2.der), sha256_hex(leaf.der)]
    assert trace[0]["valid_policies"] == [P1]
    assert trace[1]["valid_policies"] == [P2]
    assert trace[2]["valid_policies"] == [P3]
    # an unrelated initial policy still fails
    res2 = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                      leaf_key=leaf.key,
                      initial_policy_set=["1.3.6.1.4.1.99999.9"])
    assert res2["verdict"] == "INVALID"
    assert "POLICY_INITIAL_SET_MISMATCH" in res2["summary"]["failure_codes"]


def _mapping_chain(policy_constraints_ca1=None):
    P1, P2, P3 = ("1.3.6.1.4.1.99999.1", "1.3.6.1.4.1.99999.2",
                  "1.3.6.1.4.1.99999.3")
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    ca1 = make_ca("CA1", "ec", issuer=root, not_before=T("2021-01-01"),
                  not_after=T("2035-01-01"), policies=[P1],
                  policy_mappings=[(P1, P2)],
                  policy_constraints=policy_constraints_ca1)
    ca2 = make_ca("CA2", "ec", issuer=ca1, not_before=T("2021-06-01"),
                  not_after=T("2034-01-01"), policies=[P2],
                  policy_mappings=[(P2, P3)])
    leaf = make_leaf(ca2, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=[P3])
    for e in (root, ca1, ca2, leaf):
        bag.cert(e)
    for issuer in (root, ca1, ca2):
        bag.add(make_crl(issuer, entries=[], crl_number=1, this_update=T("2024-05-01"),
                         next_update=T("2024-07-01")), "crl", EARLY)
    return bag, root, leaf


def test_policy_mapping_inhibit_count_boundaries():
    # inhibitPolicyMapping=1 exempts exactly CA2; the leaf-layer mapping is
    # inhibited, so P3 cannot chain back to P1
    bag, root, leaf = _mapping_chain({"inhibit_mapping": 1})
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key,
                     initial_policy_set=["1.3.6.1.4.1.99999.1"])
    assert res["verdict"] == "INVALID"
    assert "POLICY_INITIAL_SET_MISMATCH" in res["summary"]["failure_codes"]
    # inhibitPolicyMapping=2 exempts both intermediates: chain stays valid
    bag2, root2, leaf2 = _mapping_chain({"inhibit_mapping": 2})
    res2 = adjudicate(bag2, sha256_hex(leaf2.der), [sha256_hex(root2.der)],
                      leaf_key=leaf2.key,
                      initial_policy_set=["1.3.6.1.4.1.99999.1"])
    assert res2["verdict"] == "VALID", dumps(res2["decision"]).decode()
    pol = [r for r in res2["decision"]["path_rules"] if r["rule"] == "POLICIES"][0]
    assert pol["valid_policies"] == ["1.3.6.1.4.1.99999.3"]


def test_require_explicit_policy_skip_boundary():
    ANY = "2.5.29.32.0"
    # requireExplicitPolicy=1 with one intermediate exempts the leaf: the
    # leaf's anyPolicy-only tree is accepted
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[ANY],
                    policy_constraints={"require_explicit": 1})
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=[ANY])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    # value 0 over the same leaf enforces explicit policy -> anyPolicy fails
    bag2 = Bag()
    root2 = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter2 = make_ca("Inter", "ec", issuer=root2, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"), policies=[ANY],
                     policy_constraints={"require_explicit": 0})
    leaf2 = make_leaf(inter2, "Leaf", "ed", not_before=T("2022-01-01"),
                      not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                      policies=[ANY])
    for e in (root2, inter2, leaf2):
        bag2.cert(e)
    bag2.add(make_crl(inter2, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl", EARLY)
    bag2.add(make_crl(root2, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl", EARLY)
    res2 = adjudicate(bag2, sha256_hex(leaf2.der), [sha256_hex(root2.der)],
                      leaf_key=leaf2.key)
    assert res2["verdict"] == "INVALID"
    assert "POLICY_EXPLICIT_REQUIRED" in res2["summary"]["failure_codes"]


def test_rejection_proof_policy_trace():
    """A policy failure in the rejection proof carries the per-layer trace."""
    P1, P2, P3 = ("1.3.6.1.4.1.99999.1", "1.3.6.1.4.1.99999.2",
                  "1.3.6.1.4.1.99999.3")
    bag, root, leaf = _mapping_chain()
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key,
                     initial_policy_set=["1.3.6.1.4.1.99999.9"])
    assert res["verdict"] == "INVALID"
    proof = res["decision"]["rejection_proof"]
    pf = next(b["failure"] for b in proof["branches"]
              if b["failure"]["rule"] == "POLICIES")
    trace = pf["details"]["policy_trace"]
    assert len(trace) == 3
    assert trace[2]["valid_policies"] == [P3]


def test_cross_signed_different_keys_aki_selects_parent():
    """Same subject name, different keys: AKI/SKI pins the right parent."""
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter_k1 = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                       not_after=T("2035-01-01"))
    # same subject name, DIFFERENT key, same issuer
    inter_k2 = make_ca("Inter", "ec", issuer=root, subject_name=inter_k1.cert.subject,
                       not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter_k1, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter_k1, inter_k2, leaf):
        bag.cert(e)
    # CRL signed by inter_k1's key (the real issuer of leaf)
    bag.add(make_crl(inter_k1, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["decision"]["path"][1] == sha256_hex(inter_k1.der)


def test_rejection_proof_covers_all_branches():
    """With two candidate issuers both failing, the proof lists both branches."""
    bag = Bag()
    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root_a, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    inter_b = make_ca("Inter", "ec", issuer=root_b, key=inter.key,
                      subject_name=inter.cert.subject,
                      not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root_a, root_b, inter, inter_b, leaf):
        bag.cert(e)
    # no CRLs at all -> every branch fails with revocation UNKNOWN
    res = adjudicate(bag, sha256_hex(leaf.der),
                     [sha256_hex(root_a.der), sha256_hex(root_b.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    proof = res["decision"]["rejection_proof"]
    assert proof is not None
    paths = [tuple(b["path"]) for b in proof["branches"]]
    assert len(paths) >= 2, proof
    inters = {p[1] for p in paths}
    assert sha256_hex(inter.der) in inters
    assert sha256_hex(inter_b.der) in inters
    for b in proof["branches"]:
        assert "failure" in b and "rule" in b["failure"]


def test_ocsp_sha256_certid():
    from cryptography.hazmat.primitives import hashes

    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"),
                     hash_alg=hashes.SHA256())
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()


def test_duplicate_cert_objects_do_not_duplicate_paths():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
        bag.cert(e)  # duplicate upload -> same fingerprint, deduped
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    assert len(res["decision"]["path"]) == 3

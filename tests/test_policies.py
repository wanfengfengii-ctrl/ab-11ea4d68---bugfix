"""Policy processing: continuous mappings, anyPolicy, the NULL tree,
mapping inhibition and explicit-policy count boundaries.

These tests pin both the final valid policy set / first failing rule and the
deterministic per-layer policy_trace that evidence packs carry for offline
recomputation.
"""
from __future__ import annotations

from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import make_ca, make_crl, make_leaf
from tests.conftest import Bag, EARLY, T, adjudicate

P1 = "1.3.6.1.4.1.99999.1"
P2 = "1.3.6.1.4.1.99999.2"
P3 = "1.3.6.1.4.1.99999.3"
P4 = "1.3.6.1.4.1.99999.4"
ANY = "2.5.29.32.0"


def _build(cas, leaf):
    bag = Bag()
    for e in cas + [leaf]:
        bag.cert(e)
    for ca in cas:
        bag.add(make_crl(ca, entries=[], crl_number=1, this_update=T("2024-05-01"),
                         next_update=T("2024-07-01")), "crl", EARLY)
    return bag


def _root():
    return make_ca("Root", "rsa", not_before=T("2020-01-01"),
                   not_after=T("2040-01-01"))


def _policy_result(res):
    rules = {r["rule"]: r for r in res["decision"]["path_rules"]}
    return rules["POLICIES"]


def _first_failure(res):
    branches = res["decision"]["rejection_proof"]["branches"]
    policy_branches = [b for b in branches if b["failure"]["rule"] == "POLICIES"]
    return policy_branches[0]["failure"]


def _two_level_chain():
    root = _root()
    inter1 = make_ca("Inter1", "ec", issuer=root, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"), policies=[P1],
                     policy_mappings=[(P1, P2)])
    inter2 = make_ca("Inter2", "ec", issuer=inter1, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"), policies=[P2],
                     policy_mappings=[(P2, P3)])
    leaf = make_leaf(inter2, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"], policies=[P3])
    return root, _build([root, inter1, inter2], leaf), leaf


def test_continuous_two_level_mapping_satisfies_initial_p1():
    root, bag, leaf = _two_level_chain()
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    pr = _policy_result(res)
    assert pr["valid_policies"] == [P1]
    layers = pr["policy_trace"]["certificates"]
    assert [e["depth"] for e in layers] == [1, 2, 3]
    assert layers[0]["valid_policies_after_mappings"] == [P1]
    assert layers[1]["valid_policies_after_mappings"] == [P2]
    assert layers[2]["valid_policies_after_certificate"] == [P3]
    assert pr["policy_trace"]["wrap_up"]["valid_policies"] == [P1]
    assert pr["policy_trace"]["wrap_up"]["valid_policies_before_intersection"] == [P3]


def test_continuous_mapping_foreign_initial_policy_mismatch():
    from app.canonical import sha256_hex
    root, bag, leaf = _two_level_chain()
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P4])
    assert res["verdict"] == "INVALID"
    failure = _first_failure(res)
    assert failure["code"] == "POLICY_INITIAL_SET_MISMATCH"
    # rejected branches carry the same per-layer trace for offline recompute
    assert failure["policy_trace"]["wrap_up"]["valid_policies"] == []


def test_single_level_mapping_regression():
    from app.canonical import sha256_hex
    root = _root()
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1],
                    policy_mappings=[(P1, P2)])
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"], policies=[P2])
    bag = _build([root, inter], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID"
    assert _policy_result(res)["valid_policies"] == [P1]


def test_any_policy_leaf_satisfies_specific_initial_set():
    from app.canonical import sha256_hex
    root = _root()
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1])
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"], policies=[ANY])
    bag = _build([root, inter], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID"
    assert _policy_result(res)["valid_policies"] == [P1]


def test_any_policy_intermediate_carries_specific_leaf_policy():
    from app.canonical import sha256_hex
    root = _root()
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[ANY])
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"], policies=[P2])
    bag = _build([root, inter], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P2])
    assert res["verdict"] == "VALID"
    assert _policy_result(res)["valid_policies"] == [P2]
    res_bad = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                         leaf_key=leaf.key, initial_policy_set=[P3])
    assert res_bad["verdict"] == "INVALID"
    assert _first_failure(res_bad)["code"] == "POLICY_INITIAL_SET_MISMATCH"


def test_empty_policy_tree_accepts_any_policy_initial_set_only():
    from app.canonical import sha256_hex
    root = _root()
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1])
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"])  # no certificatePolicies
    bag = _build([root, inter], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    assert _policy_result(res)["valid_policies"] == []
    res_bad = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                         leaf_key=leaf.key, initial_policy_set=[P1])
    assert res_bad["verdict"] == "INVALID"
    assert _first_failure(res_bad)["code"] == "POLICY_INITIAL_SET_MISMATCH"


def test_inhibit_policy_mapping_boundaries():
    from app.canonical import sha256_hex

    def chain(skip):
        root = _root()
        inter1 = make_ca("Inter1", "ec", issuer=root, not_before=T("2021-01-01"),
                         not_after=T("2035-01-01"), policies=[P1],
                         policy_mappings=[(P1, P2)],
                         policy_constraints={"inhibit_mapping": skip})
        inter2 = make_ca("Inter2", "ec", issuer=inter1, not_before=T("2021-01-01"),
                         not_after=T("2035-01-01"), policies=[P2],
                         policy_mappings=[(P2, P3)])
        leaf = make_leaf(inter2, "Leaf", "ed", not_before=T("2022-01-01"),
                         not_after=T("2030-01-01"),
                         eku=["1.3.6.1.5.5.7.3.3"], policies=[P3])
        return root, _build([root, inter1, inter2], leaf), leaf

    # skip=2 exempts both certificates below inter1: both mappings compose
    root, bag, leaf = chain(2)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID"

    # skip=1 exempts inter2 only; the leaf is past the exemption, so the
    # P2->P3 mapping does not apply and P3 cannot satisfy P1
    root, bag, leaf = chain(1)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "INVALID"
    assert _first_failure(res)["code"] == "POLICY_INITIAL_SET_MISMATCH"


def test_inhibit_policy_mapping_zero_blocks_the_mapping_ca_itself():
    from app.canonical import sha256_hex
    root = _root()
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1],
                    policy_mappings=[(P1, P2)],
                    policy_constraints={"inhibit_mapping": 0})
    leaf_mapped = make_leaf(inter, "LeafMapped", "ed", not_before=T("2022-01-01"),
                            not_after=T("2030-01-01"),
                            eku=["1.3.6.1.5.5.7.3.3"], policies=[P2])
    leaf_direct = make_leaf(inter, "LeafDirect", "ed", not_before=T("2022-01-01"),
                            not_after=T("2030-01-01"),
                            eku=["1.3.6.1.5.5.7.3.3"], policies=[P1])
    bag = _build([root, inter], leaf_mapped)
    bag.cert(leaf_direct)
    res = adjudicate(bag, sha256_hex(leaf_mapped.der), [sha256_hex(root.der)],
                     leaf_key=leaf_mapped.key, initial_policy_set=[P1])
    assert res["verdict"] == "INVALID"
    assert _first_failure(res)["code"] == "POLICY_INITIAL_SET_MISMATCH"
    res2 = adjudicate(bag, sha256_hex(leaf_direct.der), [sha256_hex(root.der)],
                      leaf_key=leaf_direct.key, initial_policy_set=[P1])
    assert res2["verdict"] == "VALID"


def test_require_explicit_policy_count_boundaries():
    from app.canonical import sha256_hex
    root = _root()
    # skip=1 on the top CA exempts inter2; the NULL leaf is one cert further
    # down and therefore requires an explicit policy -> POLICY_TREE_EMPTY
    inter1 = make_ca("Inter1", "ec", issuer=root, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"), policies=[P1],
                     policy_constraints={"require_explicit": 1})
    inter2 = make_ca("Inter2", "ec", issuer=inter1, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"))
    leaf = make_leaf(inter2, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"])
    bag = _build([root, inter1, inter2], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "INVALID"
    assert _first_failure(res)["code"] == "POLICY_TREE_EMPTY"

    # skip=1 on the CA directly above a NULL leaf: that leaf is the single
    # exempted certificate, so no explicit policy is required
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1],
                    policy_constraints={"require_explicit": 1})
    leaf_exempt = make_leaf(inter, "LeafExempt", "ed", not_before=T("2022-01-01"),
                            not_after=T("2030-01-01"),
                            eku=["1.3.6.1.5.5.7.3.3"])
    bag2 = _build([root, inter], leaf_exempt)
    res2 = adjudicate(bag2, sha256_hex(leaf_exempt.der),
                      [sha256_hex(root.der)], leaf_key=leaf_exempt.key)
    assert res2["verdict"] == "VALID"


def test_inhibit_any_policy_boundary():
    from app.canonical import sha256_hex
    root = _root()
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1], inhibit_any=0)
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"], policies=[ANY])
    bag = _build([root, inter], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "INVALID"
    assert _first_failure(res)["code"] == "POLICY_INITIAL_SET_MISMATCH"


def test_three_level_mapping_chains():
    from app.canonical import sha256_hex
    root = _root()
    c1 = make_ca("C1", "ec", issuer=root, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[P1],
                 policy_mappings=[(P1, P2)])
    c2 = make_ca("C2", "ec", issuer=c1, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[P2],
                 policy_mappings=[(P2, P3)])
    c3 = make_ca("C3", "ec", issuer=c2, not_before=T("2021-01-01"),
                 not_after=T("2035-01-01"), policies=[P3],
                 policy_mappings=[(P3, P4)])
    leaf = make_leaf(c3, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"),
                     eku=["1.3.6.1.5.5.7.3.3"], policies=[P4])
    bag = _build([root, c1, c2, c3], leaf)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID"
    assert _policy_result(res)["valid_policies"] == [P1]


def test_policy_trace_is_deterministic():
    root, bag, leaf = _two_level_chain()
    from app.canonical import sha256_hex
    kw = dict(leaf_fp=sha256_hex(leaf.der), anchors=[sha256_hex(root.der)],
              leaf_key=leaf.key, initial_policy_set=[P1])
    r1 = adjudicate(bag, **kw)
    r2 = adjudicate(bag, **kw)
    assert dumps(r1) == dumps(r2)

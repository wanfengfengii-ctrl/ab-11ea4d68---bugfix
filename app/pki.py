"""Certificate parsing and the supported RFC 5280 profile.

A certificate that parses as DER is always *stored*; profile violations are
recorded on the object as structured ``unsupported`` findings.  During
adjudication, any path that would rely on an unsupported object fails with a
structured UNSUPPORTED rule outcome - the object is never silently accepted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from . import profile
from .canonical import canon_time, sha256_hex
from .errors import ParseError

# ---------------------------------------------------------------------------
# Supported extension OIDs
# ---------------------------------------------------------------------------
SUPPORTED_EXTENSION_OIDS = {
    ExtensionOID.BASIC_CONSTRAINTS.dotted_string,
    ExtensionOID.KEY_USAGE.dotted_string,
    ExtensionOID.EXTENDED_KEY_USAGE.dotted_string,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string,
    ExtensionOID.NAME_CONSTRAINTS.dotted_string,
    ExtensionOID.CERTIFICATE_POLICIES.dotted_string,
    ExtensionOID.POLICY_MAPPINGS.dotted_string,
    ExtensionOID.POLICY_CONSTRAINTS.dotted_string,
    ExtensionOID.INHIBIT_ANY_POLICY.dotted_string,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string,
}

EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
EKU_ANY = "2.5.29.37.0"
ANY_POLICY_OID = "2.5.29.32.0"
ANY_POLICY = "anyPolicy"


def _unsupported(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


def _rdns_of(name: x509.Name) -> tuple:
    """Canonical RDN structure: tuple of RDNs, each a tuple of (oid, value)."""
    return tuple(
        tuple((a.oid.dotted_string, a.value) for a in rdn) for rdn in name.rdns
    )


@dataclass
class CertInfo:
    fingerprint: str
    der: bytes
    cert: x509.Certificate
    subject_der: bytes
    issuer_der: bytes
    subject_rdns: tuple
    serial_hex: str
    not_before: datetime
    not_after: datetime
    is_ca: bool
    path_len: int | None
    key_usage: frozenset | None
    eku: frozenset | None
    san_dns: tuple
    san_uri: tuple
    san_dir: tuple  # RDN structures of directoryName SANs
    nc: dict | None  # {"permitted": {...}, "excluded": {...}} with dns/uri/dir lists
    policies: tuple | None  # tuple of policy OID strings, None when extension absent
    policy_mappings: tuple  # ((issuer_oid, subject_oid), ...)
    policy_constraints: dict | None  # {"require_explicit": n|None, "inhibit_mapping": n|None}
    inhibit_any_policy: int | None
    ski: str | None
    aki_keyid: str | None
    key_alg: dict | None
    sig_alg: dict | None
    key_fp: str
    unsupported: list = field(default_factory=list)

    # -- convenience -------------------------------------------------------
    @property
    def subject_hex(self) -> str:
        return self.subject_der.hex()

    @property
    def issuer_hex(self) -> str:
        return self.issuer_der.hex()

    @property
    def self_issued(self) -> bool:
        return self.subject_der == self.issuer_der

    @property
    def profile_ok(self) -> bool:
        return not self.unsupported

    def public_key(self):
        return self.cert.public_key()


def _name_cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def parse_certificate(der: bytes, fingerprint: str | None = None) -> CertInfo:
    """Parse a DER certificate into a CertInfo, collecting profile findings."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        raise ParseError("CERT_PARSE_ERROR", f"not a DER X.509 certificate: {exc}")
    fp = fingerprint or sha256_hex(der)
    unsupported: list = []

    # --- signature algorithm ---------------------------------------------
    sig_oid = cert.signature_algorithm_oid.dotted_string
    try:
        hash_alg = cert.signature_hash_algorithm
    except Exception:
        hash_alg = None
    try:
        sig_params = cert.signature_algorithm_parameters
    except Exception:
        sig_params = None
    sig_alg = profile.signature_algorithm_descriptor(sig_oid, sig_params, hash_alg)
    if sig_alg is None:
        unsupported.append(
            _unsupported("UNSUPPORTED_SIGNATURE_ALGORITHM", f"signature algorithm OID {sig_oid}")
        )

    # --- public key -------------------------------------------------------
    try:
        pub = cert.public_key()
        key_alg = profile.public_key_descriptor(pub)
        key_fp = sha256_hex(
            pub.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    except Exception as exc:
        pub = None
        key_alg = None
        key_fp = ""
        unsupported.append(_unsupported("UNSUPPORTED_KEY_ALGORITHM", f"unreadable public key: {exc}"))
    if pub is not None and key_alg is None:
        if isinstance(pub, rsa.RSAPublicKey):
            unsupported.append(
                _unsupported("UNSUPPORTED_KEY_SIZE", f"RSA key {pub.key_size} bits out of profile")
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            unsupported.append(
                _unsupported("UNSUPPORTED_KEY_ALGORITHM", f"EC curve {pub.curve.name} out of profile")
            )
        else:
            unsupported.append(_unsupported("UNSUPPORTED_KEY_ALGORITHM", type(pub).__name__))

    # --- extensions -------------------------------------------------------
    is_ca, path_len = False, None
    key_usage = None
    eku = None
    san_dns: list = []
    san_uri: list = []
    san_dir: list = []
    nc = None
    policies = None
    policy_mappings: tuple = ()
    policy_constraints = None
    inhibit_any = None
    ski = None
    aki_keyid = None

    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid not in SUPPORTED_EXTENSION_OIDS:
            if ext.critical:
                unsupported.append(
                    _unsupported("UNSUPPORTED_CRITICAL_EXTENSION", f"extension OID {oid}")
                )
            continue
        val = ext.value
        if oid == ExtensionOID.BASIC_CONSTRAINTS.dotted_string:
            is_ca = bool(val.ca)
            path_len = val.path_length
        elif oid == ExtensionOID.KEY_USAGE.dotted_string:
            usages = set()
            if val.digital_signature:
                usages.add("digitalSignature")
            if val.content_commitment:
                usages.add("nonRepudiation")
            if val.key_encipherment:
                usages.add("keyEncipherment")
            if val.data_encipherment:
                usages.add("dataEncipherment")
            if val.key_agreement:
                usages.add("keyAgreement")
            if val.key_cert_sign:
                usages.add("keyCertSign")
            if val.crl_sign:
                usages.add("cRLSign")
            key_usage = frozenset(usages)
        elif oid == ExtensionOID.EXTENDED_KEY_USAGE.dotted_string:
            eku = frozenset(o.dotted_string for o in val)
        elif oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string:
            for gn in val:
                if isinstance(gn, x509.DNSName):
                    san_dns.append(gn.value)
                elif isinstance(gn, x509.UniformResourceIdentifier):
                    san_uri.append(gn.value)
                elif isinstance(gn, x509.DirectoryName):
                    san_dir.append(_rdns_of(gn.value))
                else:
                    unsupported.append(
                        _unsupported(
                            "UNSUPPORTED_SAN_TYPE", f"general name {type(gn).__name__} in SAN"
                        )
                    )
        elif oid == ExtensionOID.NAME_CONSTRAINTS.dotted_string:
            nc = {"permitted": {"dns": [], "uri": [], "dir": []},
                  "excluded": {"dns": [], "uri": [], "dir": []}}
            for label, subtrees in (("permitted", val.permitted_subtrees),
                                    ("excluded", val.excluded_subtrees)):
                for gn in (subtrees or []):
                    if isinstance(gn, x509.DNSName):
                        nc[label]["dns"].append(gn.value)
                    elif isinstance(gn, x509.UniformResourceIdentifier):
                        nc[label]["uri"].append(gn.value)
                    elif isinstance(gn, x509.DirectoryName):
                        nc[label]["dir"].append(_rdns_of(gn.value))
                    else:
                        unsupported.append(
                            _unsupported(
                                "UNSUPPORTED_NAME_CONSTRAINT_TYPE",
                                f"{type(gn).__name__} in {label} subtrees",
                            )
                        )
        elif oid == ExtensionOID.CERTIFICATE_POLICIES.dotted_string:
            pols = []
            for info in val:
                pols.append(info.policy_identifier.dotted_string)
                if info.policy_qualifiers:
                    unsupported.append(
                        _unsupported(
                            "UNSUPPORTED_POLICY_QUALIFIERS",
                            f"qualifiers on policy {info.policy_identifier.dotted_string}",
                        )
                    )
            policies = tuple(pols)
        elif oid == ExtensionOID.POLICY_MAPPINGS.dotted_string:
            # cryptography does not model policyMappings; parse the DER.
            from .derutil import parse_policy_mappings

            raw = val.value if isinstance(val, x509.UnrecognizedExtension) else None
            if raw is None:
                # future cryptography versions may model it natively
                policy_mappings = tuple(
                    (m.issuer_domain_policy.dotted_string,
                     m.subject_domain_policy.dotted_string)
                    for m in val
                )
            else:
                try:
                    policy_mappings = parse_policy_mappings(raw)
                except ValueError as exc:
                    unsupported.append(
                        _unsupported("MALFORMED_POLICY_MAPPINGS", str(exc))
                    )
                    policy_mappings = ()
        elif oid == ExtensionOID.POLICY_CONSTRAINTS.dotted_string:
            policy_constraints = {
                "require_explicit": val.require_explicit_policy,
                "inhibit_mapping": val.inhibit_policy_mapping,
            }
        elif oid == ExtensionOID.INHIBIT_ANY_POLICY.dotted_string:
            inhibit_any = val.skip_certs
        elif oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string:
            ski = val.digest.hex()
        elif oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string:
            if val.authority_cert_issuer is not None or val.authority_cert_serial_number is not None:
                unsupported.append(
                    _unsupported(
                        "UNSUPPORTED_AKI_FORM",
                        "authorityCertIssuer/authorityCertSerialNumber in AKI",
                    )
                )
            aki_keyid = val.key_identifier.hex() if val.key_identifier is not None else None

    return CertInfo(
        fingerprint=fp,
        der=der,
        cert=cert,
        subject_der=cert.subject.public_bytes(),
        issuer_der=cert.issuer.public_bytes(),
        subject_rdns=_rdns_of(cert.subject),
        serial_hex=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        is_ca=is_ca,
        path_len=path_len,
        key_usage=key_usage,
        eku=eku,
        san_dns=tuple(san_dns),
        san_uri=tuple(san_uri),
        san_dir=tuple(san_dir),
        nc=nc,
        policies=policies,
        policy_mappings=policy_mappings,
        policy_constraints=policy_constraints,
        inhibit_any_policy=inhibit_any,
        ski=ski,
        aki_keyid=aki_keyid,
        key_alg=key_alg,
        sig_alg=sig_alg,
        key_fp=key_fp,
        unsupported=unsupported,
    )


# ---------------------------------------------------------------------------
# Name constraints (RFC 5280 section 4.2.1.10), profile: DNS, URI, directoryName
# ---------------------------------------------------------------------------

def dns_name_matches(name: str, constraint: str) -> bool:
    """DNS constraint: matches the host itself or any subdomain to the left."""
    name = name.rstrip(".").lower()
    constraint = constraint.rstrip(".").lower()
    return name == constraint or name.endswith("." + constraint)


def _uri_host(uri: str) -> str | None:
    try:
        parts = urlsplit(uri)
    except Exception:
        return None
    host = parts.hostname
    return host.lower() if host else None


def uri_name_matches(uri: str, constraint: str) -> bool:
    """URI constraint per RFC 5280: a leading dot denotes a domain (subdomains
    only); without a leading dot it is an exact host name."""
    host = _uri_host(uri)
    if host is None:
        return False
    constraint = constraint.lower()
    if constraint.startswith("."):
        return host.endswith(constraint) and host != constraint[1:]
    return host == constraint


def dir_name_matches(name_rdns: tuple, constraint_rdns: tuple) -> bool:
    """directoryName constraint: the name must be inside the constraint subtree,
    i.e. the constraint RDN sequence is a prefix of the name's RDN sequence."""
    if len(constraint_rdns) > len(name_rdns):
        return False
    return name_rdns[: len(constraint_rdns)] == constraint_rdns


def check_name_constraints(path: list) -> dict:
    """Evaluate accumulated name constraints for a candidate path.

    *path* is ordered leaf-first.  Constraints of CA certificates apply to all
    certificates below them.  The trust anchor's own constraints are not
    evaluated (a trust anchor is a trusted name+key).  Returns a rule result.
    """
    # accumulate constraints from the anchor-1 down to each cert's issuers
    acc_p = {"dns": [], "uri": [], "dir": []}
    acc_e = {"dns": [], "uri": [], "dir": []}
    # walk from the cert just below the anchor down to the leaf; a CA's own
    # constraints apply to the certificates below it
    per_cert: dict = {}
    n = len(path) - 1  # anchor index
    for idx in range(n - 1, -1, -1):
        per_cert[idx] = (
            {k: list(v) for k, v in acc_p.items()},
            {k: list(v) for k, v in acc_e.items()},
        )
        issuer = path[idx]
        if issuer.nc:
            for k in ("dns", "uri", "dir"):
                acc_p[k].extend(issuer.nc["permitted"][k])
                acc_e[k].extend(issuer.nc["excluded"][k])
    for idx, (perm, excl) in per_cert.items():
        cert = path[idx]
        names = {
            "dns": list(cert.san_dns),
            "uri": list(cert.san_uri),
            "dir": [cert.subject_rdns] + list(cert.san_dir),
        }
        matchers = {"dns": dns_name_matches, "uri": uri_name_matches, "dir": dir_name_matches}
        for kind in ("dns", "uri", "dir"):
            for n in names[kind]:
                for c in excl[kind]:
                    if matchers[kind](n, c):
                        return {
                            "result": "fail",
                            "code": "NAME_CONSTRAINT_EXCLUDED",
                            "certificate": cert.fingerprint,
                            "detail": f"{kind} name {n!r} in excluded subtree {c!r} "
                            f"(certificate {cert.fingerprint})",
                        }
            if perm[kind]:
                for n in names[kind]:
                    if not any(matchers[kind](n, c) for c in perm[kind]):
                        return {
                            "result": "fail",
                            "code": "NAME_CONSTRAINT_NOT_PERMITTED",
                            "certificate": cert.fingerprint,
                            "detail": f"{kind} name {n!r} not within permitted subtrees "
                            f"(certificate {cert.fingerprint})",
                        }
    return {"result": "pass"}


# ---------------------------------------------------------------------------
# Certification path policy processing (RFC 5280 section 6.1)
# ---------------------------------------------------------------------------

class _PolicyNode:
    """A node of the RFC 5280 valid_policy_tree.

    ``valid_policy`` is the policy asserted at this depth (the sentinel
    ``anyPolicy`` denotes the special OID 2.5.29.32.0); ``expected`` is the
    node's expected_policy_set for the next certificate.  The tree keeps
    expected_policy_set explicitly: a policyMappings extension on a CA
    rewrites the expected sets of its nodes, so a mapping chain P1->P2 on one
    CA and P2->P3 on the next composes exactly as RFC 5280 prescribes.
    """

    __slots__ = ("valid_policy", "expected", "children")

    def __init__(self, valid_policy: str, expected=None, children=None):
        self.valid_policy = valid_policy
        self.expected = expected if expected is not None else {valid_policy}
        self.children = children if children is not None else []


def _nodes_at_depth(root: _PolicyNode, depth: int) -> list:
    level = [root]
    for _ in range(depth):
        level = [child for node in level for child in node.children]
    return level


def _level_policy_set(root: _PolicyNode | None, depth: int):
    """Sorted valid policies present at *depth* (None when the tree is NULL)."""
    if root is None:
        return None
    return sorted({node.valid_policy for node in _nodes_at_depth(root, depth)})


def _prune_dead_branches(node: _PolicyNode, depth: int, leaf_depth: int) -> bool:
    """RFC 5280 6.1.3 (d)(3): drop parent nodes left without children.

    Returns whether *node* survives.
    """
    if depth >= leaf_depth:
        return True
    node.children = [
        child for child in node.children
        if _prune_dead_branches(child, depth + 1, leaf_depth)
    ]
    return bool(node.children)


def evaluate_policies(path: list, initial_policy_set: list) -> dict:
    """Evaluate certificate policies for a candidate path (leaf-first order).

    Implements the RFC 5280 section 6.1 valid_policy_tree state machine with
    the skip-counter semantics documented for this profile:
      * The trust anchor contributes only the initial tree root (anyPolicy);
        its own extensions are not processed.
      * Certificates are processed from the CA directly below the anchor down
        to the leaf.  Every node carries an expected_policy_set, so a
        policyMappings extension rewrites the policies that satisfy the node
        one level down and mappings compose continuously across multiple CA
        levels (P1->P2 then P2->P3 leaves P3 satisfying P1).
      * Skip counters are position based.  For a constraint value ``k`` on a
        CA at depth ``j`` and the certificate at depth ``i`` below it, the
        effective value is ``k - (i - j)``; constraints from multiple CAs
        combine with MIN.  Mapping is permitted and anyPolicy is processed
        while the effective value is non-negative (an effective 0 still
        permits, i.e. a skip of ``k`` exempts the ``k`` certificates
        immediately below); requireExplicitPolicy binds once the effective
        value becomes negative.
      * When policy mapping is inhibited for a child, the issuer's mappings
        simply do not rewrite that child's expected policies; the policies
        the CA itself asserts are retained.  A policyMappings extension
        naming anyPolicy always fails the path (POLICY_MAPPING_ANY).
      * Profile tightening (documented in README): requireExplicitPolicy
        effective at the leaf rejects a NULL tree or a tree whose only leaf
        is anyPolicy.

    Returns a rule result dict; on success it includes ``valid_policies`` and
    a deterministic ``policy_trace`` recording the per-certificate tree state
    so the outcome can be recomputed offline from the evidence pack alone.
    """
    n = len(path) - 1  # anchor index in the leaf-first path

    # top-down order of the non-anchor certificates (RFC certificates 1..n)
    certs = [path[i] for i in range(n - 1, -1, -1)]

    def counter_value(kind: str, target_depth: int, max_source_depth: int):
        """Effective skip value at *target_depth* from constraints on certs
        at depths 1..max_source_depth; None when no constraint applies."""
        best = None
        for j in range(1, max_source_depth + 1):
            cert = certs[j - 1]
            if kind == "require_explicit":
                k = cert.policy_constraints.get("require_explicit") \
                    if cert.policy_constraints else None
            elif kind == "inhibit_mapping":
                k = cert.policy_constraints.get("inhibit_mapping") \
                    if cert.policy_constraints else None
            else:
                k = cert.inhibit_any_policy
            if k is None:
                continue
            v = k - (target_depth - j)
            best = v if best is None else min(best, v)
        return best

    root = _PolicyNode(ANY_POLICY, {ANY_POLICY})
    trace_entries = []

    def fail(code, cert, detail):
        return {
            "result": "fail",
            "code": code,
            "certificate": cert.fingerprint,
            "detail": detail,
            "policy_trace": {"certificates": trace_entries, "wrap_up": None},
        }

    for i, cert in enumerate(certs, start=1):
        is_leaf = i == n
        policies = cert.policies
        any_v = counter_value("inhibit_any", i, i - 1)
        # effective 0 still permits: a skip of k exempts the k certs below
        any_permitted = any_v is None or any_v >= 0
        explicit_v = counter_value("require_explicit", i, i - 1)
        explicit_required_here = explicit_v is not None and explicit_v < 0

        # -- RFC 6.1.3 (d): basic policy processing -----------------------
        post_basic = None
        if root is not None and policies is not None:
            parents = _nodes_at_depth(root, i - 1)
            any_parents = [node for node in parents if node.valid_policy == ANY_POLICY]
            specific = [p for p in policies if p != ANY_POLICY_OID]
            for p_oid in specific:
                # (d)(1)(i): exact match against parent expected_policy_set
                matched = [node for node in parents if p_oid in node.expected]
                if matched:
                    for node in matched:
                        node.children.append(_PolicyNode(p_oid, {p_oid}))
                elif any_parents:
                    # (d)(1)(ii): unmatched policy under an anyPolicy node
                    for node in any_parents:
                        node.children.append(_PolicyNode(p_oid, {p_oid}))
            if ANY_POLICY_OID in policies and any_permitted:
                # (d)(2): anyPolicy carries every still-expected value over
                for node in parents:
                    present = {child.valid_policy for child in node.children}
                    for expected in sorted(node.expected):
                        if expected not in present:
                            node.children.append(
                                _PolicyNode(expected, {expected})
                            )
                            present.add(expected)
            # (d)(3): prune parent nodes left without children
            if not _prune_dead_branches(root, 0, i):
                root = None
            else:
                post_basic = _level_policy_set(root, i)
        elif policies is None:
            # (e): absent certificatePolicies extension -> NULL tree (sticky)
            root = None

        post_mapping = post_basic
        mapping_permitted = None
        if not is_leaf:
            # -- this CA's policy mappings rewrite the next certificate.
            #    The gate is evaluated at the child position, so a
            #    constraint on this CA also governs its own mappings.
            map_v = counter_value("inhibit_mapping", i + 1, i)
            mapping_permitted = map_v is None or map_v >= 0
            # once the tree is NULL policy processing ceases (RFC 6.1.2);
            # the mappings are recorded in the trace but not applied
            if cert.policy_mappings and root is not None and mapping_permitted:
                # RFC 6.1.4 (a): anyPolicy in an applicable mapping fails;
                # a mapping that is inhibited is ignored wholesale
                if any(ip == ANY_POLICY_OID or sp == ANY_POLICY_OID
                       for ip, sp in cert.policy_mappings):
                    trace_entries.append(_trace_entry(
                        cert, i, policies,
                        sorted((ip, sp) for ip, sp in cert.policy_mappings),
                        any_permitted, mapping_permitted, post_basic,
                        explicit_required=explicit_required_here))
                    return fail("POLICY_MAPPING_ANY", cert,
                                f"policyMappings with anyPolicy at {cert.fingerprint}")
                # RFC 6.1.4 (b)(1): rewrite expected_policy_set values
                grouped: dict = {}
                for ip, sp in cert.policy_mappings:
                    grouped.setdefault(ip, set()).add(sp)
                level_nodes = _nodes_at_depth(root, i)
                for ip in sorted(grouped):
                    targets = [nd for nd in level_nodes if nd.valid_policy == ip]
                    for nd in targets:
                        nd.expected = set(grouped[ip])
                    if not targets:
                        # an absent issuer policy under an anyPolicy node
                        # becomes an equivalent branch
                        for parent in _nodes_at_depth(root, i - 1):
                            if parent.valid_policy != ANY_POLICY:
                                continue
                            if any(c.valid_policy == ANY_POLICY
                                   for c in parent.children) and not any(
                                c.valid_policy == ip for c in parent.children
                            ):
                                parent.children.append(
                                    _PolicyNode(ip, set(grouped[ip])))
                post_mapping = _level_policy_set(root, i)
            # when mapping is inhibited (or the tree is NULL) the mappings
            # are recorded in the trace but not applied

        trace_entries.append(_trace_entry(
            cert, i, policies,
            sorted((ip, sp) for ip, sp in cert.policy_mappings),
            any_permitted, mapping_permitted, post_basic, post_mapping,
            explicit_required_here))

    # -- wrap-up: explicit policy gate at the leaf -------------------------
    leaf_cert = certs[-1]
    explicit_v = counter_value("require_explicit", n, n - 1)
    explicit_required = explicit_v is not None and explicit_v < 0

    initial = list(initial_policy_set) if initial_policy_set else [ANY_POLICY]
    initial_is_any_policy = ANY_POLICY in initial or ANY_POLICY_OID in initial
    initial_set = {p for p in initial if p != ANY_POLICY and p != ANY_POLICY_OID}

    wrap_up = {
        "explicit_policy_required": explicit_required,
        "initial_policy_set": sorted(set(initial)),
        "valid_policies": None,
    }
    trace = {"certificates": trace_entries, "wrap_up": wrap_up}

    def terminal_fail(code, detail):
        return {"result": "fail", "code": code,
                "certificate": leaf_cert.fingerprint, "detail": detail,
                "policy_trace": trace}

    if root is None:
        if explicit_required:
            return terminal_fail(
                "POLICY_TREE_EMPTY",
                "explicit policy required but the valid policy tree is null")
        if not initial_is_any_policy:
            return terminal_fail(
                "POLICY_INITIAL_SET_MISMATCH",
                "no policies are asserted but the initial policy set is specific")
        wrap_up["valid_policies"] = []
        return {"result": "pass", "valid_policies": [], "policy_trace": trace}

    leaf_policies = {nd.valid_policy for nd in _nodes_at_depth(root, n)}
    if explicit_required and leaf_policies == {ANY_POLICY}:
        return terminal_fail(
            "POLICY_EXPLICIT_REQUIRED",
            "explicit policy required but only anyPolicy remains")

    if not initial_is_any_policy:
        # RFC 6.1.5 (g)(iii): intersect the tree with the user initial set.
        # A branch starts wherever a specific policy appears beneath an
        # anyPolicy node (at any depth); such a branch survives only when its
        # entry policy is in the initial set.  anyPolicy branch nodes are
        # retained, and an anyPolicy leaf satisfies every requested policy
        # (step 3 synthesizes one leaf per requested OID).
        def prune_for_initial_set(node: _PolicyNode, depth: int) -> bool:
            kept = []
            for child in node.children:
                dropped = (
                    node.valid_policy == ANY_POLICY
                    and child.valid_policy != ANY_POLICY
                    and child.valid_policy not in initial_set
                )
                if not dropped and prune_for_initial_set(child, depth + 1):
                    kept.append(child)
            node.children = kept
            return depth == n or bool(kept)

        tree_survives = prune_for_initial_set(root, 0)
        surviving_leaf_policies = (
            {nd.valid_policy for nd in _nodes_at_depth(root, n)}
            if tree_survives else set()
        )
        # RFC 6.1.5(g)(iii)3: an anyPolicy node still present at leaf depth
        # after branch pruning synthesizes one leaf per requested OID
        any_policy_leaf = ANY_POLICY in surviving_leaf_policies
        final = set()
        if any_policy_leaf:
            final |= initial_set

        def collect_entries(node: _PolicyNode):
            for child in node.children:
                if node.valid_policy == ANY_POLICY and child.valid_policy != ANY_POLICY:
                    final.add(child.valid_policy)
                collect_entries(child)

        if tree_survives:
            collect_entries(root)
        wrap_up["valid_policies_before_intersection"] = sorted(leaf_policies)
        wrap_up["valid_policies"] = sorted(final)
        if not final or not tree_survives:
            return terminal_fail(
                "POLICY_INITIAL_SET_MISMATCH",
                f"valid policies {sorted(leaf_policies)} do not intersect "
                f"initial policy set")
        return {"result": "pass", "valid_policies": sorted(final),
                "policy_trace": trace}

    # RFC 6.1.5 (g)(ii): an any-policy initial set accepts the whole tree.
    final = sorted(leaf_policies)
    wrap_up["valid_policies_before_intersection"] = final
    wrap_up["valid_policies"] = final
    return {"result": "pass", "valid_policies": final, "policy_trace": trace}


def _trace_entry(cert, depth, policies, mappings, any_permitted,
                 mapping_permitted, valid_after_certificate,
                 valid_after_mappings=None, explicit_required=False) -> dict:
    """A deterministic per-layer policy state record for offline recomputation."""
    if valid_after_mappings is None:
        valid_after_mappings = valid_after_certificate
    entry = {
        "certificate": cert.fingerprint,
        "depth": depth,
        "policies": list(policies) if policies is not None else None,
        "policy_mappings": [list(m) for m in mappings] if mappings else [],
        "any_policy_processed": bool(any_permitted and policies is not None
                                     and ANY_POLICY_OID in policies),
        "mapping_permitted": mapping_permitted,
        "explicit_policy_required": explicit_required,
        "valid_policies_after_certificate": valid_after_certificate,
        "valid_policies_after_mappings": valid_after_mappings,
    }
    return entry

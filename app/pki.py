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
# Certification path policy processing (RFC 5280 section 6.1), profile subset
# ---------------------------------------------------------------------------

def evaluate_policies(path: list, initial_policy_set: list) -> dict:
    """Evaluate certificate policies for a candidate path (leaf-first order).

    Returns a rule result dict; on success includes ``valid_policies`` and a
    per-layer ``policy_trace`` (ordered from the certificate below the anchor
    down to the leaf) recording, for every certificate:

      * ``certificate_policies`` - the asserted policies (``null`` when the
        certificatePolicies extension is absent);
      * ``mappings`` - the issuer's policyMappings applied at that layer;
      * ``mappings_inhibited`` / ``any_policy_inhibited`` /
        ``explicit_policy_required`` - the effective controls at that
        certificate, derived from skip counters;
      * ``valid_policies`` - the surviving policy set expressed in *that
        certificate's own terms* (``[]`` is the NULL valid policy tree).

    The trace is a deterministic function of the path and is what the offline
    evidence-pack verifier independently recomputes.

    Semantics (RFC 5280 section 6.1, profile subset documented in README):
      * The trust anchor is treated as ``anyPolicy``; its own extensions are
        not processed.
      * The valid policy set is maintained in each certificate's *own* terms.
        A mapping P_issuer <- P_subject lets a child policy satisfy the
        issuer-domain policy, and mappings compose continuously across any
        number of CAs: an issuer-domain policy at one layer (e.g. P2) that is
        itself a subject-domain policy at the next layer keeps chaining.
      * A certificate without certificatePolicies prunes the tree to NULL
        (sticky).
      * ``anyPolicy`` keeps the set open unless inhibited by
        inhibitAnyPolicy.
      * Skip-count semantics (RFC 5280 4.2.1.11 / 4.2.1.14): a constraint
        value ``k`` on the certificate at position ``p`` exempts the ``k``
        certificates immediately below it and takes effect at the
        ``(k+1)``-th certificate below; multiple constraints combine with
        MIN.  Trust-anchor extensions are ignored.
      * A policyMapping to or from anyPolicy is prohibited on every path,
        independent of inhibitPolicyMapping.
      * Final acceptance (user-initial-policy set phase, RFC 6.1.5): the
        initial set is composed through the whole chain of mappings, and the
        surviving set must intersect it.  An initial set of [anyPolicy]
        accepts anything the tree asserts, including a NULL tree when
        explicit policy is not required.
    """
    n = len(path) - 1  # anchor index

    def pending_at(kind: str, idx: int):
        """Effective skip-counter value at *idx*; None when unconstrained."""
        best = None
        for p in range(idx + 1, n):
            cert = path[p]
            if kind == "require_explicit":
                k = cert.policy_constraints.get("require_explicit") if cert.policy_constraints else None
            elif kind == "inhibit_mapping":
                k = cert.policy_constraints.get("inhibit_mapping") if cert.policy_constraints else None
            else:  # inhibit_any
                k = cert.inhibit_any_policy
            if k is None:
                continue
            v = k - (p - idx)
            best = v if best is None else min(best, v)
        return best

    def fail(code: str, cert_idx: int, detail: str, trace: list) -> dict:
        return {
            "result": "fail",
            "code": code,
            "certificate": path[cert_idx].fingerprint,
            "detail": detail,
            "policy_trace": trace,
        }

    trace: list = []
    layers: list = []  # processing order: certificate below the anchor -> leaf
    valid = {ANY_POLICY}  # own-terms set at the current cert; None = NULL tree
    for idx in range(n - 1, -1, -1):
        cert = path[idx]
        mapping_counter = pending_at("inhibit_mapping", idx)
        any_counter = pending_at("inhibit_any", idx)
        explicit_counter = pending_at("require_explicit", idx)
        # Skip-count boundary (RFC 5280 4.2.1.11/14, README): a counter value
        # k exempts exactly the k certificates immediately below; the control
        # takes effect when the counter has run below zero (at the (k+1)-th
        # certificate below).  A value of exactly zero still exempts that
        # last certificate.
        mapping_inhibited = mapping_counter is not None and mapping_counter < 0
        any_inhibited = any_counter is not None and any_counter < 0
        explicit_required = explicit_counter is not None and explicit_counter < 0

        parent_mappings = tuple(path[idx + 1].policy_mappings) if idx + 1 <= n - 1 else ()
        # anyPolicy may never appear in a policy mapping, whether or not
        # mapping is otherwise inhibited (RFC 5280 4.2.1.5)
        for (ip, sp) in parent_mappings:
            if ip == ANY_POLICY_OID or sp == ANY_POLICY_OID:
                return fail(
                    "POLICY_MAPPING_ANY", idx + 1,
                    f"policyMappings with anyPolicy at {path[idx + 1].fingerprint}",
                    trace,
                )

        map_subject_to_issuers: dict = {}
        if not mapping_inhibited:
            for (ip, sp) in parent_mappings:
                map_subject_to_issuers.setdefault(sp, []).append(ip)

        if cert.policies is None:
            valid = None
        elif valid is not None:
            cert_policies = list(cert.policies)
            has_any = ANY_POLICY_OID in cert_policies
            explicit_oids = [p for p in cert_policies if p != ANY_POLICY_OID]
            new_valid = set()
            if ANY_POLICY in valid:
                # an anyPolicy parent node matches every asserted policy
                if has_any and not any_inhibited:
                    new_valid.add(ANY_POLICY)
                new_valid.update(explicit_oids)
            else:
                # this certificate's anyPolicy stands in (as one node
                # labeled anyPolicy) for every parent policy node
                if has_any and not any_inhibited:
                    new_valid.add(ANY_POLICY)
                for p in explicit_oids:
                    # direct match or a link through an uninhibited mapping
                    if (p in valid
                            or any(ip in valid for ip in map_subject_to_issuers.get(p, ()))):
                        new_valid.add(p)
            valid = new_valid if new_valid else None

        asserted = None if cert.policies is None else sorted(
            ANY_POLICY if p == ANY_POLICY_OID else p for p in cert.policies
        )
        layers.append({
            "valid": valid,
            "map_s2i": map_subject_to_issuers,
        })
        trace.append({
            "certificate": cert.fingerprint,
            "certificate_policies": asserted,
            "mappings": sorted(
                ({"issuer_domain_policy": ip, "subject_domain_policy": sp}
                 for (ip, sp) in parent_mappings),
                key=lambda m: (m["issuer_domain_policy"], m["subject_domain_policy"]),
            ),
            "mappings_inhibited": mapping_inhibited,
            "any_policy_inhibited": any_inhibited,
            "explicit_policy_required": explicit_required,
            "valid_policies": [] if valid is None else sorted(valid),
        })

    explicit_at_leaf = (
        (v := pending_at("require_explicit", 0)) is not None and v < 0
    )
    initial = list(initial_policy_set) if initial_policy_set else [ANY_POLICY]
    initial_specific = ANY_POLICY not in initial and ANY_POLICY_OID not in initial
    initial_set = set(initial)

    if valid is None:
        if explicit_at_leaf:
            return fail(
                "POLICY_TREE_EMPTY", 0,
                "explicit policy required but the valid policy tree is null",
                trace,
            )
        if initial_specific:
            return fail(
                "POLICY_INITIAL_SET_MISMATCH", 0,
                "no policies are asserted but the initial policy set is specific",
                trace,
            )
        return {"result": "pass", "valid_policies": [], "policy_trace": trace}
    if valid == {ANY_POLICY}:
        if explicit_at_leaf:
            return fail(
                "POLICY_EXPLICIT_REQUIRED", 0,
                "explicit policy required but only anyPolicy remains",
                trace,
            )
        return {
            "result": "pass",
            "valid_policies": sorted(initial) if initial_specific else [ANY_POLICY],
            "policy_trace": trace,
        }

    # User-initial-policy-set phase (RFC 5280 6.1.5(g)): descend the initial
    # policies through the *full* chain of mappings and anyPolicy stand-in
    # nodes, keeping the set at each layer in that certificate's own terms.
    if initial_specific:
        current = set(initial_set)
        for layer in layers:
            layer_valid = layer["valid"]
            map_s2i = layer["map_s2i"]
            nxt = set()
            for p in current:
                if p == ANY_POLICY:
                    # Under this engine's tree rules every surviving node at
                    # the layer below an anyPolicy node was created as one of
                    # its children, so the wildcard expands to all of them.
                    nxt.update(layer_valid)
                elif p in layer_valid:
                    nxt.add(p)
                elif ANY_POLICY in layer_valid:
                    # a surviving anyPolicy node wildcard-matches any policy;
                    # continue the descent on the wildcard node itself
                    nxt.add(ANY_POLICY)
                for sp, ips in map_s2i.items():
                    if p in ips:
                        nxt.add(sp)
            current = nxt & layer_valid if layer_valid is not None else set()
            if not current:
                break
        if not current:
            return fail(
                "POLICY_INITIAL_SET_MISMATCH", 0,
                f"valid policies {sorted(valid)} do not intersect initial policy set",
                trace,
            )
        return {"result": "pass", "valid_policies": sorted(current),
                "policy_trace": trace}
    return {"result": "pass", "valid_policies": sorted(valid), "policy_trace": trace}

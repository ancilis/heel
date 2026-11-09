"""C4 P01: closed managed-authority contracts and route codecs (inert; no listener or admission).

Every byte bound below is the literal Q section 6 witness, recomputed here from objects this test
builds itself from the pinned grammars; the module's own constants are never the oracle.
"""
import ast
import copy
import hashlib
import inspect
import json
import unittest
from pathlib import Path
from unittest import mock

from heel.saas import managed_authority_contracts as mac
from heel.saas.managed_authority_contracts import ManagedContractError

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/canary/contracts/managed-authority-v1.json"
# cdd3576a... was the fixture before C4-P01-PHASE-R2 changed only observation_offered.runner_key_id
# from null to a synthetic reserved key (S 14.2: key nonnull at reservation).
FIXTURE_SHA256 = "44df3c4f78d59e23403f219df6644b91850415c8f278f599b1212cf53cca5eee"

WINDOW_ROUTE, ATTEMPT_ROUTE, CEREMONY_ROUTE = (
    "/host/v3/managed-operation", "/host/v1/managed-attempt", "/host/v3/managed-ceremony")


def _c(value) -> bytes:
    """Independent canonical encoder: sorted keys, compact separators, ASCII escapes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _h(value) -> str:
    return hashlib.sha256(_c(value)).hexdigest()


def _fixture() -> dict:
    return json.loads(FIXTURE.read_bytes())


# ------------------------------------------------------------------------------------------------
# Independent maximal construction from the pinned grammars (Q section 6, EA section 4, S 14.2).
MS, NS, SEQ, REV = 2 ** 53 - 1, 2 ** 63 - 1, 2 ** 20, 2147483647
HEX32, HEX64, LONG = "a" * 32, "a" * 64, "a" * 128
B64_32 = "/" * 42 + "8="  # canonical base64 of 32 bytes, 44 characters


def _maximal() -> dict:
    tuple_fields = {"workspace_id": "ws_" + "a" * 16, "project_id": "prj_" + HEX32, "environment_id": "env_" + HEX32,
                    "verification_record_digest": HEX64, "runner_id": LONG, "runner_key_id": LONG,
                    "binding_id": "rcb_" + HEX32, "binding_digest": HEX64, "run_id": "crun_" + HEX32,
                    "grant_id": LONG, "grant_digest": HEX64}
    window = {**tuple_fields, "schema_version": "heel.managed-operation-request.v3", "kind": "execute_window",
              "restore_epoch": HEX64, "managed_executor_id": "mex_" + HEX32, "pairing_epoch": "epoch_" + HEX32,
              "pairing_id": "pending_" + HEX32, "host_boot_epoch": "a" * 64, "slot_id": "a" * 32,
              "generation_id": HEX32, "bootstrap_fence": HEX32, "kill_switch_generation": MS, "sequence": SEQ,
              "request_nonce": HEX32, "monotonic_ms": MS, "operation_digest": HEX64}
    attempt = {**window, "schema_version": "heel.managed-attempt-request.v1", "kind": "execute_attempt",
               "manifest_digest": HEX64, "window_operation_digest": HEX64, "action_ordinal": 19, "method": "HEAD",
               "route_template_digest": HEX64, "route_digest": HEX64, "semantic_role": "higher_privilege",
               "attempt": 2, "previous_failure_code": "connect_error", "attempt_deadline_ns": NS}
    active = {**tuple_fields, "public_key_digest": HEX64, "run_status": "claimed", "stop_reason": "none",
              "egress_hostname": ("a" * 63 + ".") * 3 + "a" * 61, "proof_expires_at_ms": MS,
              "binding_expires_at_ms": MS, "grant_expires_at_ms": MS, "egress_port": 443}
    window_response = {**active, "schema_version": "heel.managed-operation-response.v3", "decision": "admitted",
                       "reason": "none", "request_digest": HEX64, "operation_digest": HEX64, "sequence": SEQ,
                       "authority_revision": REV, "server_time_ms": MS, "kill_switch_generation": MS,
                       "bootstrap_fence": HEX32}
    attempt_response = {**window_response, "schema_version": "heel.managed-attempt-response.v1",
                        "attempt_digest": HEX64, "window_operation_digest": HEX64, "attempt_deadline_ns": NS}
    window_descriptor = {"schema_version": "heel.managed-prepared-operation.v2", "request_identity_digest": HEX64,
                         "handle_nonce": HEX32, "handle_mark": 2 ** 32 - 1, "namespace_dev": 2 ** 64 - 1,
                         "namespace_ino": 2 ** 64 - 1, "process_instance": HEX32, "src": "255.255.255.255",
                         "dst": "255.255.255.255", "prepared_ns": NS, "prepare_return_ns": NS,
                         "request_start_ns": NS, "tick_ns": NS, "lease_ms": 3000, "exchange_deadline_ns": NS,
                         "scope_digest": HEX64, "bootstrap_fence": HEX32}
    attempt_descriptor = {"schema_version": "heel.managed-prepared-attempt.v1", "request_identity_digest": HEX64,
                          "window_operation_digest": HEX64, "bootstrap_fence": HEX32, "process_instance": HEX32,
                          "manifest_digest": HEX64, "action_digest": HEX64, "route_digest": HEX64,
                          "credential_binding_digest": HEX64, "action_ordinal": 19, "method": "HEAD",
                          "semantic_role": "higher_privilege", "attempt": 2, "attempt_deadline_ns": NS,
                          "request_start_ns": NS}
    window_note = {"schema_version": "heel.managed-window-complete.v2", "operation_digest": HEX64,
                   "request_digest": HEX64, "generation_id": HEX32, "run_id": "crun_" + HEX32, "sequence": SEQ,
                   "deadline_ns": NS, "bootstrap_fence": HEX32}
    attempt_note = {"schema_version": "heel.managed-attempt-complete.v1", "request_digest": HEX64,
                    "attempt_digest": HEX64, "window_operation_digest": HEX64, "bootstrap_fence": HEX32,
                    "generation_id": HEX32, "run_id": "crun_" + HEX32, "sequence": SEQ, "deadline_ns": NS}
    t = {"slot_id": "a" * 32, "epoch_id": "epoch_" + HEX32, "managed_executor_id": "mex_" + HEX32,
         "workspace_id": "ws_" + "a" * 16, "pairing_id": "pending_" + HEX32}
    gens = {"retry_generation": REV, "cleanup_generation": REV, "previous_ack_generation": REV,
            "original_pairing_expires_at_ms": MS}
    request_env = {"schema_version": "heel.managed-ceremony-request.v3", "restore_epoch": HEX64, "slot_id": "a" * 32,
                   "managed_executor_id": "mex_" + HEX32, "pairing_epoch": "epoch_" + HEX32,
                   "delivery_generation": REV, "bootstrap_fence": HEX32}
    response_env = {"schema_version": "heel.managed-ceremony-response.v3", "restore_epoch": HEX64,
                    "managed_executor_id": "mex_" + HEX32, "pairing_epoch": "epoch_" + HEX32,
                    "delivery_generation": REV, "bootstrap_fence": HEX32}
    offer = {**request_env, "kind": "public_key", "payload": {
        "schema_version": "heel.managed-key-offer.v1", "slot_id": "a" * 32, "epoch_id": "epoch_" + HEX32,
        "previous_managed_executor_id": "mex_" + "b" * 32, "previous_epoch_id": "epoch_" + "b" * 32,
        "previous_terminal_pairing_id": "pending_" + "b" * 32, "public_key_b64": B64_32, "fingerprint": HEX64,
        "runner_key_id": "k_" + "a" * 16, "offered_at_ms": MS}}
    challenge = {**response_env, "kind": "challenge", "payload": {
        **t, **gens, "schema_version": "heel.managed-pending.v1", "runner_id": "runr_" + HEX32,
        "runner_key_id": "k_" + "a" * 16, "fingerprint": HEX64, "pairing_exchange_digest": HEX64,
        "activation_challenge": B64_32, "challenge_expires_at_ms": MS}}
    terminal = {**response_env, "kind": "terminal", "payload": {
        **t, **gens, "schema_version": "heel.managed-aborted.v1", "runner_id": "runr_" + HEX32,
        "runner_key_id": "k_" + "a" * 16, "terminal_at_ms": MS, "reason_code": "local_identity_unavailable"}}
    retired = {**request_env, "kind": "retired", "payload": {
        **t, "schema_version": "heel.managed-host-ack.v1", "state": "capacity_unavailable", "updated_at_ms": MS,
        "retry_generation": REV, "cleanup_generation": REV}}
    identity = {**response_env, "kind": "identity_observed", "payload": {
        "schema_version": "heel.managed-identity-observation.v1", "workspace_id": "ws_" + "a" * 16,
        "pairing_id": "pending_" + HEX32, "runner_id": "runr_" + HEX32, "runner_key_id": "k_" + "a" * 16,
        "public_key_digest": HEX64, "observed_at_ms": MS}}
    record = {"restore_epoch": HEX64, "tuple_digest": HEX64, "run_id": "crun_" + HEX32, "generation_id": HEX32,
              "ordinal": 19, "method": "HEAD", "semantic_role": "higher_privilege", "attempt": 2,
              "manifest_digest": HEX64, "route_template_digest": HEX64, "route_digest": HEX64,
              "window_operation_digest": HEX64, "operation_digest": HEX64, "request_digest": HEX64,
              "bootstrap_fence": HEX32, "exchange_sequence": SEQ, "authority_revision": REV, "admitted_at_ms": MS,
              "attempt_deadline_ns": NS, "previous_failure_code": "connect_error"}
    return {"window_request": window, "attempt_request": attempt, "window_response": window_response,
            "attempt_response": attempt_response, "window_descriptor": window_descriptor,
            "attempt_descriptor": attempt_descriptor, "window_notification": window_note,
            "attempt_notification": attempt_note, "ceremony_offer": offer, "ceremony_challenge": challenge,
            "ceremony_terminal": terminal, "ceremony_retired": retired, "ceremony_identity": identity,
            "ceremony_poll": {**request_env, "kind": "poll", "payload": {}},
            "ceremony_none": {**response_env, "kind": "none", "payload": {}}, "attempt_record": record}


# Q section 6 table (plus the logical attempt row witness 1092/2048 from the Q review).
Q_BYTES = {"window_request": (1739, 2048), "attempt_request": (2254, 2560), "window_response": (1925, 4096),
           "attempt_response": (2142, 4096), "window_descriptor": (736, 2048), "attempt_descriptor": (855, 2048),
           "window_notification": (428, 1024), "attempt_notification": (520, 1024),
           "ceremony_offer": (979, 4096), "ceremony_challenge": (1191, 4096), "ceremony_terminal": (980, 4096),
           "ceremony_retired": (835, 4096), "ceremony_identity": (739, 4096), "ceremony_poll": (412, 4096),
           "ceremony_none": (368, 4096), "attempt_record": (1092, 2048)}
MESSAGE_OF = {"ceremony_offer": "ceremony_request", "ceremony_retired": "ceremony_request",
              "ceremony_poll": "ceremony_request", "ceremony_challenge": "ceremony_response",
              "ceremony_terminal": "ceremony_response", "ceremony_identity": "ceremony_response",
              "ceremony_none": "ceremony_response"}


def _message(name: str) -> str:
    return MESSAGE_OF.get(name, name)


class ManagedAuthorityContractTests(unittest.TestCase):
    def assertRefused(self, code, function, *args):
        with self.assertRaises(ManagedContractError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    # -------------------------------------------------------------------------------------------
    def test_fixture_is_literal_hashed_canonical_with_one_newline(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FIXTURE_SHA256)
        self.assertTrue(raw.endswith(b"\n") and not raw.endswith(b"\n\n"))
        self.assertEqual(raw, _c(json.loads(raw)) + b"\n")

    def test_maximal_window_1739_attempt_2254_and_response_bounds(self):
        maximal, fixture = _maximal(), _fixture()
        for name, (size, cap) in Q_BYTES.items():
            with self.subTest(name=name):
                body = _c(maximal[name])
                self.assertEqual(len(body), size)
                self.assertEqual(maximal[name], fixture["maximal"][name])
                self.assertEqual(fixture["bounds"][name], {"bytes": size, "cap": cap})
                self.assertEqual(mac.decode(_message(name), body), maximal[name])
                self.assertEqual(mac.encode(_message(name), maximal[name]), body)
        # Payload sum per pending Q (request + response + descriptor + notification caps).
        self.assertEqual(2560 + 4096 + 2048 + 1024, 9728)
        # The attempt body needs more than the window cap, and the window route never stretches to it.
        attempt_body = _c(maximal["attempt_request"])
        self.assertGreater(len(attempt_body), 2048)
        self.assertRefused("oversize", mac.decode_route_request, WINDOW_ROUTE, attempt_body)
        self.assertEqual(mac.decode_route_request(ATTEMPT_ROUTE, attempt_body), maximal["attempt_request"])
        # Without the CP-verifiable template digest the attempt would measure 2163 bytes; it is required.
        without_template = {k: v for k, v in maximal["attempt_request"].items() if k != "route_template_digest"}
        self.assertEqual(len(_c(without_template)), 2163)
        self.assertRefused("missing_key", mac.decode_route_request, ATTEMPT_ROUTE, _c(without_template))

    def test_route_caps_are_checked_before_any_parse(self):
        cases = [(WINDOW_ROUTE, 2048, 4096), (ATTEMPT_ROUTE, 2560, 4096), (CEREMONY_ROUTE, 4096, 4096)]
        for route, request_cap, response_cap in cases:
            with self.subTest(route=route):
                # At the cap the bytes are parsed (and fail as JSON); one byte more is refused unparsed.
                self.assertRefused("malformed_json", mac.decode_route_request, route, b"{" * request_cap)
                with mock.patch.object(mac.json, "loads", side_effect=AssertionError("parsed")):
                    self.assertRefused("oversize", mac.decode_route_request, route, b"{" * (request_cap + 1))
                    self.assertRefused("oversize", mac.decode_route_response, route, b"{" * (response_cap + 1))
                    self.assertRefused("oversize", mac.decode_route_request, route, b"x" * (64 * 1024 * 1024))
        for message, cap in (("window_descriptor", 2048), ("attempt_descriptor", 2048), ("window_notification", 1024),
                             ("attempt_notification", 1024), ("attempt_forward", 2560), ("observation", 4096)):
            with self.subTest(message=message), mock.patch.object(mac.json, "loads", side_effect=AssertionError):
                self.assertRefused("oversize", mac.decode, message, b" " * (cap + 1))

    def test_duplicate_extra_bool_noncanonical_oversize_rejected_per_route(self):
        maximal = _maximal()
        samples = {WINDOW_ROUTE: maximal["window_request"], ATTEMPT_ROUTE: maximal["attempt_request"],
                   CEREMONY_ROUTE: maximal["ceremony_offer"]}
        for route, good in samples.items():
            body = _c(good)
            mutations = {
                "duplicate_key": body[:-1] + b',"schema_version":' + _c(good["schema_version"]) + b"}",
                "extra_key": _c({**good, "managed": True}),
                "noncanonical/space": body.replace(b",", b", ", 1),
                "noncanonical/order": b'{"schema_version":' + _c(good["schema_version"]) + b"," + body[1:].replace(
                    b'"schema_version":' + _c(good["schema_version"]) + b",", b"", 1),
                "noncanonical/newline": body + b"\n",
                "noncanonical/escape": body.replace(b'"slot_id":"a', b'"slot_id":"\\u0061', 1),
                "non_ascii": body.replace(b'"slot_id":"a', b'"slot_id":"\xc3\xa9', 1),
                "malformed_json": body[:-1],
                "float_forbidden": _c({**good, "delivery_generation" if route == CEREMONY_ROUTE else "sequence": 1})
                .replace(b'":1,', b'":1.0,', 1),
                "invalid_field/bool": _c({**good, "delivery_generation" if route == CEREMONY_ROUTE else "sequence": True}),
                "null_forbidden": _c({**good, "restore_epoch": None}),
            }
            for label, mutated in mutations.items():
                with self.subTest(route=route, mutation=label):
                    self.assertNotEqual(mutated, body)
                    code = label.split("/")[0]
                    self.assertRefused(code, mac.decode_route_request, route, mutated)
        # Duplicates nested inside the ceremony payload are refused too.
        offer = _c(maximal["ceremony_offer"])
        nested = offer.replace(b'"payload":{', b'"payload":{"epoch_id":"epoch_' + b"a" * 32 + b'",', 1)
        self.assertRefused("duplicate_key", mac.decode_route_request, CEREMONY_ROUTE, nested)
        # bool-as-int in every integer slot of the attempt request.
        for name in ("action_ordinal", "attempt", "attempt_deadline_ns", "monotonic_ms", "kill_switch_generation"):
            with self.subTest(bool_field=name):
                self.assertRefused("invalid_field", mac.decode_route_request, ATTEMPT_ROUTE,
                                   _c({**maximal["attempt_request"], name: True}))
        # Out-of-range integers at each documented edge.
        edges = {"sequence": [0, SEQ + 1], "monotonic_ms": [-1, MS + 1], "action_ordinal": [-1, 20],
                 "attempt": [0, 3], "attempt_deadline_ns": [-1, NS + 1]}
        for name, values in edges.items():
            for value in values:
                with self.subTest(edge=name, value=value):
                    self.assertRefused("invalid_field", mac.decode_route_request, ATTEMPT_ROUTE,
                                       _c({**maximal["attempt_request"], name: value}))
        # Unknown and legacy routes have no managed codec.
        for route in ("/host/v1/authority-snapshot", "/host/v2/managed-operation", "/host/v2/managed-ceremony",
                      "/host/v3/managed-operation/", "/HOST/V3/MANAGED-OPERATION"):
            with self.subTest(route=route):
                self.assertRefused("unknown_route", mac.decode_route_request, route, _c(maximal["window_request"]))

    def test_route_specific_codecs_do_not_cross_accept(self):
        maximal = _maximal()
        window, ceremony = _c(maximal["window_request"]), _c(maximal["ceremony_poll"])
        self.assertRefused("missing_key", mac.decode_route_request, ATTEMPT_ROUTE, window)
        self.assertRefused("extra_key", mac.decode_route_request, CEREMONY_ROUTE, window)
        self.assertRefused("extra_key", mac.decode_route_request, WINDOW_ROUTE, ceremony)
        # A window-schema body with attempt fields cannot pass as either.
        hybrid = {**maximal["attempt_request"], "schema_version": "heel.managed-operation-request.v3"}
        self.assertRefused("invalid_field", mac.decode_route_request, ATTEMPT_ROUTE, _c(hybrid))
        # Previous v2 schema spellings are not accepted on the v3 routes.
        legacy = {**maximal["window_request"], "schema_version": "heel.managed-operation-request.v2"}
        self.assertRefused("invalid_field", mac.decode_route_request, WINDOW_ROUTE, _c(legacy))

    # -------------------------------------------------------------------------------------------
    def test_rawhex32_preserved_and_hex64_rejected(self):
        useful = _fixture()["useful_scan"]
        fence = useful["window_request"]["bootstrap_fence"]
        self.assertRegex(fence, r"\A[0-9a-f]{32}\Z")
        carriers = ("window_request", "window_descriptor", "window_response", "window_notification",
                    "attempt_request", "attempt_descriptor", "attempt_response_admitted",
                    "attempt_response_refused", "attempt_notification", "attempt_record")
        for name in carriers:
            self.assertEqual(useful[name]["bootstrap_fence"], fence, name)  # unchanged, not hashed/padded
        mac.verify_window_binding(useful["window_request"], useful["window_descriptor"])
        mac.verify_window_response(useful["window_response"], useful["window_request"])
        mac.verify_window_notification(useful["window_notification"], useful["window_request"])
        mac.verify_attempt_binding(useful["attempt_request"], useful["attempt_descriptor"])
        mac.verify_attempt_response(useful["attempt_response_admitted"], useful["attempt_request"])
        mac.verify_attempt_notification(useful["attempt_notification"], useful["attempt_request"])
        maximal = _maximal()
        wrong = {"hex64": "a" * 64, "upper": "A" * 32, "short": "a" * 31, "long": "a" * 33, "hashed": _h(fence),
                 "padded": fence + "0" * 32, "truncated": _h(fence)[:32][:-1] + "g"}
        for name, document in maximal.items():
            for label, value in wrong.items():
                with self.subTest(message=name, fence=label):
                    mutated = copy.deepcopy(document)
                    mutated["bootstrap_fence"] = value
                    self.assertRefused("invalid_field", mac.decode, _message(name), _c(mutated))
        # A different (well-formed) fence anywhere downstream is a binding failure, never a substitute.
        other = "0" * 32
        checks = [(mac.verify_window_binding, "window_request", "window_descriptor", 1),
                  (mac.verify_window_response, "window_response", "window_request", 0),
                  (mac.verify_window_notification, "window_notification", "window_request", 0),
                  (mac.verify_attempt_binding, "attempt_request", "attempt_descriptor", 1),
                  (mac.verify_attempt_response, "attempt_response_admitted", "attempt_request", 0),
                  (mac.verify_attempt_notification, "attempt_notification", "attempt_request", 0)]
        for function, first, second, mutate_second in checks:
            with self.subTest(check=function.__name__):
                a, b = copy.deepcopy(useful[first]), copy.deepcopy(useful[second])
                (b if mutate_second else a)["bootstrap_fence"] = other
                self.assertRefused("binding_mismatch", function, a, b)

    def test_signed_projection_template_is_distinct_from_prepared_private_route(self):
        useful = _fixture()["useful_scan"]
        template, route = useful["route_template"], useful["prepared_route"]
        request, descriptor = useful["attempt_request"], useful["attempt_descriptor"]
        # CP recomputes the template commitment from the signed projection alone.
        expected_template = _h({"method": "GET", "route_template": template})
        self.assertEqual(mac.route_template_digest("GET", template), expected_template)
        self.assertEqual(request["route_template_digest"], expected_template)
        # The executor commits the whole prepared route after fixture substitution.
        expected_route = _h({"method": "GET", "route": route})
        self.assertEqual(mac.route_digest("GET", route), expected_route)
        self.assertEqual(request["route_digest"], expected_route)
        self.assertEqual(descriptor["route_digest"], expected_route)
        self.assertNotEqual(expected_template, expected_route)
        # Domain separation: the same string as template and as route never collide; method is bound.
        self.assertNotEqual(mac.route_template_digest("GET", "/same"), mac.route_digest("GET", "/same"))
        self.assertNotEqual(mac.route_digest("GET", route), mac.route_digest("HEAD", route))
        self.assertNotEqual(mac.route_template_digest("GET", template), mac.route_template_digest("HEAD", template))
        # Neither private route nor fixture binding values travel on the CP wire.
        wire = _c(request) + _c(useful["attempt_response_admitted"]) + _c(useful["attempt_notification"])
        for private in (route.encode(), b"proj-fixture-7", b"owner_project", b"ident-owner"):
            self.assertNotIn(private, wire)
        # Prepared route bound (ASCII <= 2048) and template bound (<= 1024 UTF-8 bytes) are the existing ones.
        self.assertEqual(len(mac.route_digest("GET", "/" + "a" * 2047)), 64)
        self.assertRefused("invalid_field", mac.route_digest, "GET", "/" + "a" * 2048)
        self.assertRefused("invalid_field", mac.route_digest, "GET", "/é")
        self.assertRefused("invalid_field", mac.route_template_digest, "GET", "/" + "a" * 1024)
        self.assertRefused("invalid_field", mac.route_digest, "POST", route)

    def test_template_digest_refuses_unencodable_text_with_a_fixed_unchained_error(self):
        marker = "DO_NOT_ECHO"
        # Lone high/low surrogates anywhere, a reversed pair, and two lone surrogates whose ASCII JSON
        # escapes are byte-identical to a real astral character (the commitment must stay injective).
        unencodable = ("/\ud800" + marker, "/\udfff" + marker, "\udc00/" + marker, "/" + marker + "\udbff",
                       "/\udc00\ud800" + marker, "/\ud83d\ude00", "/" + "a" * 900 + "\ud800" + marker,
                       "/" + "a" * 2000 + "\udfff" + marker)
        for template in unencodable:
            for method in ("GET", "HEAD"):
                with self.subTest(template=template[:24], method=method):
                    error = self.assertRefused("invalid_field", mac.route_template_digest, method, template)
                    self.assertEqual(error.field, "route_template")
                    self.assertEqual(type(error), ManagedContractError)
                    self.assertNotIsInstance(error, UnicodeError)
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)
                    self.assertFalse(hasattr(error, "object"))
                    self.assertFalse(hasattr(error, "__notes__"))
                    self.assertEqual(error.args, ("invalid_field:route_template",))
                    self.assertEqual(vars(error), {"code": "invalid_field", "field": "route_template"})
                    for surface in (str(error), repr(error)):
                        self.assertNotIn(marker, surface)
                        self.assertNotIn("\\ud", surface.lower())
        # The method is still checked first and is equally fixed.
        self.assertEqual(self.assertRefused("invalid_field", mac.route_template_digest, "POST", "/\ud800").field,
                         "method")
        # Legal non-ASCII templates keep the Q ASCII canonical commitment; literal known digests were
        # computed outside the module from sorted compact ensure_ascii JSON.
        known = {"/\u00e9": "a752aad7a901e3c99aecc8b3a2594f9389fc01764cbb4a6ffecd14a7f3a030bc",
                 "/\u65e5\u672c/{id}": "5974a5f548ed0fc7977cf6b77cb28f4ed6d44ad09f073b43fdc40d94941d3ee5",
                 "/\U0001F600": "03566cd74bff7a17a2e1221282b20583982bbb040f6278943428253cfcbf04ce"}
        for template, digest in known.items():
            with self.subTest(known=template):
                self.assertEqual(mac.route_template_digest("GET", template), digest)
                self.assertEqual(_h({"method": "GET", "route_template": template}), digest)
        # Why the refusal is needed: two lone surrogates would otherwise commit like the real character.
        self.assertEqual(_c({"t": "/\ud83d\ude00"}), _c({"t": "/\U0001F600"}))
        # The existing bound is UTF-8 bytes (not code points), unchanged for multibyte text.
        for template, legal in (("/a" + "\u00e9" * 511, True), ("/aa" + "\u00e9" * 511, False),
                                ("/" + "\U0001F600" * 255 + "abc", True), ("/" + "\U0001F600" * 256, False),
                                ("/" + "\u65e5" * 341, True), ("/" + "\u65e5" * 342, False)):
            with self.subTest(size=len(template.encode("utf-8")), legal=legal):
                if legal:
                    self.assertEqual(mac.route_template_digest("GET", template),
                                     _h({"method": "GET", "route_template": template}))
                else:
                    error = self.assertRefused("invalid_field", mac.route_template_digest, "GET", template)
                    self.assertIsNone(error.__context__)
        for bad in ("", None, b"/bytes", 7):
            with self.subTest(bad=bad):
                self.assertIsNone(self.assertRefused("invalid_field", mac.route_template_digest, "GET", bad).__context__)

    def test_descriptor_hash_has_no_cycle(self):
        useful = _fixture()["useful_scan"]
        for request_name, descriptor_name, verify in (
                ("window_request", "window_descriptor", mac.verify_window_binding),
                ("attempt_request", "attempt_descriptor", mac.verify_attempt_binding)):
            with self.subTest(pair=request_name):
                request, descriptor = useful[request_name], useful[descriptor_name]
                self.assertNotIn("operation_digest", descriptor)
                identity = _h({k: v for k, v in request.items() if k != "operation_digest"})
                self.assertEqual(descriptor["request_identity_digest"], identity)
                self.assertEqual(request["operation_digest"], _h(descriptor))
                self.assertEqual(mac.request_identity_digest(request), identity)
                self.assertEqual(mac.operation_digest(descriptor), _h(descriptor))
                # The identity digest does not depend on operation_digest, so no fixed point is needed.
                self.assertEqual(mac.request_identity_digest({**request, "operation_digest": "0" * 64}), identity)
                verify(request, descriptor)
                # Hashing the complete request into the descriptor (the cyclic order) is rejected.
                cyclic = {**descriptor, "request_identity_digest": _h(request)}
                self.assertRefused("binding_mismatch", verify, {**request, "operation_digest": _h(cyclic)}, cyclic)
                # A stale operation_digest is rejected.
                self.assertRefused("binding_mismatch", verify, {**request, "operation_digest": "0" * 64}, descriptor)
        # The response echoes the complete-request digest, distinct from the identity digest.
        request = useful["attempt_request"]
        self.assertEqual(useful["attempt_response_admitted"]["request_digest"], _h(request))
        self.assertNotEqual(_h(request), mac.request_identity_digest(request))

    def test_independently_changed_commitment_is_detected(self):
        useful = _fixture()["useful_scan"]
        request, descriptor = useful["attempt_request"], useful["attempt_descriptor"]
        action, credential = useful["manifest_action"], useful["credential_binding"]
        self.assertEqual(descriptor["action_digest"], _h(action))
        self.assertEqual(descriptor["credential_binding_digest"], _h(credential))
        mac.verify_attempt_binding(request, descriptor)

        def rebind(new_request, new_descriptor):
            """Recompute the honest chain for changed inputs; the old counterpart must then mismatch."""
            new_request = {k: v for k, v in new_request.items() if k != "operation_digest"}
            new_descriptor = {**new_descriptor, "request_identity_digest": _h(new_request)}
            return {**new_request, "operation_digest": _h(new_descriptor)}, new_descriptor

        changes = {
            "template": ({**request, "route_template_digest": _h({"method": "GET", "route_template": "/v1/other"})},
                         descriptor),
            "route": (request, {**descriptor, "route_digest": _h({"method": "GET", "route": "/v1/projects/other"})}),
            "action": (request, {**descriptor, "action_digest": _h({**action, "scenario_id": "other"})}),
            "role": ({**request, "semantic_role": "non_owner"}, descriptor),
            "credential": (request, {**descriptor, "credential_binding_digest": _h({**credential, "identity_id": "x"})}),
        }
        for label, (changed_request, changed_descriptor) in changes.items():
            with self.subTest(change=label):
                honest_request, honest_descriptor = rebind(changed_request, changed_descriptor)
                self.assertNotEqual(honest_request["operation_digest"], request["operation_digest"])
                # Pairing either changed side with the original other side fails closed.
                self.assertRefused("binding_mismatch", mac.verify_attempt_binding, request, honest_descriptor)
                self.assertRefused("binding_mismatch", mac.verify_attempt_binding, honest_request, descriptor)
        # Template and role live only on the request side; route/action/credential only in the descriptor
        # (route also on the request, and they must agree).
        route_only = {**descriptor, "route_digest": "0" * 64}
        route_only_request = {**request, "operation_digest": _h(route_only)}
        self.assertRefused("binding_mismatch", mac.verify_attempt_binding, route_only_request, route_only)
        role_only = {**descriptor, "semantic_role": "non_owner"}
        role_only_request = {**request, "operation_digest": _h(role_only)}
        self.assertRefused("binding_mismatch", mac.verify_attempt_binding, role_only_request, role_only)

    def test_anonymous_credential_binding_is_canonical_null(self):
        self.assertEqual(mac.credential_binding_digest(None), hashlib.sha256(b"null").hexdigest())
        self.assertEqual(_fixture()["anonymous_credential_binding_digest"], hashlib.sha256(b"null").hexdigest())
        for not_anonymous in ({"identity_id": "a"},):
            self.assertNotEqual(mac.credential_binding_digest(not_anonymous), mac.credential_binding_digest(None))
        for ambiguous in ({}, "null", "", 0, False, []):
            with self.subTest(value=repr(ambiguous)):
                self.assertRefused("invalid_field", mac.credential_binding_digest, ambiguous)

    def test_attempt_failure_progression_codec(self):
        attempt = _maximal()["attempt_request"]
        accepted = [(1, "none"), (2, "connect_error"), (2, "timeout")]
        refused = [(1, "connect_error"), (1, "timeout"), (2, "none")]
        for number, failure in accepted:
            with self.subTest(attempt=number, failure=failure):
                mac.decode_route_request(ATTEMPT_ROUTE, _c({**attempt, "attempt": number,
                                                            "previous_failure_code": failure}))
        for number, failure in refused:
            with self.subTest(attempt=number, failure=failure):
                self.assertRefused("attempt_failure_mismatch", mac.decode_route_request, ATTEMPT_ROUTE,
                                   _c({**attempt, "attempt": number, "previous_failure_code": failure}))
        self.assertRefused("null_forbidden", mac.decode_route_request, ATTEMPT_ROUTE,
                           _c({**attempt, "previous_failure_code": None}))
        for value in ("dns_error", "TIMEOUT", ""):
            self.assertRefused("invalid_field", mac.decode_route_request, ATTEMPT_ROUTE,
                               _c({**attempt, "previous_failure_code": value}))
        for role in ("admin", "owner", "Anonymous"):
            self.assertRefused("invalid_field", mac.decode_route_request, ATTEMPT_ROUTE,
                               _c({**attempt, "semantic_role": role}))
        for method in ("POST", "get", "OPTIONS"):
            self.assertRefused("invalid_field", mac.decode_route_request, ATTEMPT_ROUTE,
                               _c({**attempt, "method": method}))

    def test_responses_and_notifications_bind_only_the_exact_pending_attempt(self):
        useful = _fixture()["useful_scan"]
        request = useful["attempt_request"]
        admitted, refused = useful["attempt_response_admitted"], useful["attempt_response_refused"]
        mac.verify_attempt_response(refused, request)
        # Refusal carries no active field; admitted carries all of them; reason none iff admitted.
        self.assertRefused("extra_key", mac.validate, "attempt_response", {**refused, "attempt_deadline_ns": 1})
        self.assertRefused("extra_key", mac.validate, "attempt_response",
                           {**refused, "egress_hostname": "staging.example.test"})
        self.assertRefused("missing_key", mac.validate, "attempt_response",
                           {k: v for k, v in admitted.items() if k != "attempt_deadline_ns"})
        self.assertRefused("reason_decision_mismatch", mac.validate, "attempt_response", {**refused, "reason": "none"})
        self.assertRefused("reason_decision_mismatch", mac.validate, "attempt_response",
                           {**admitted, "reason": "resource_exhausted"})
        self.assertRefused("invalid_field", mac.validate, "attempt_response", {**refused, "reason": "quota"})
        self.assertRefused("invalid_field", mac.validate, "attempt_response", {**refused, "decision": "active"})
        self.assertRefused("extra_key", mac.validate, "attempt_response", {**admitted, "decision": "active"})
        mismatches = {"attempt_digest": "0" * 64, "window_operation_digest": "0" * 64, "request_digest": "0" * 64,
                      "operation_digest": "0" * 64, "sequence": 2, "run_id": "crun_" + "0" * 32}
        for name, value in mismatches.items():
            with self.subTest(response_field=name):
                self.assertRefused("binding_mismatch", mac.verify_attempt_response, {**admitted, name: value}, request)
        self.assertRefused("deadline_extension", mac.verify_attempt_response,
                           {**admitted, "attempt_deadline_ns": request["attempt_deadline_ns"] + 1}, request)
        mac.verify_attempt_response({**admitted, "attempt_deadline_ns": request["attempt_deadline_ns"] - 1}, request)
        note = useful["attempt_notification"]
        for name, value in {"deadline_ns": note["deadline_ns"] + 1, "sequence": 2, "generation_id": "0" * 32,
                            "attempt_digest": "0" * 64, "request_digest": "0" * 64}.items():
            with self.subTest(notification_field=name):
                self.assertRefused("binding_mismatch", mac.verify_attempt_notification, {**note, name: value}, request)
        # A notification for the pending window is not an attempt notification, and vice versa.
        self.assertRefused("extra_key", mac.verify_attempt_notification, useful["window_notification"], request)

    # -------------------------------------------------------------------------------------------
    def test_ceremony_phase_nullability_and_maximal_coexistence(self):
        phases = _fixture()["ceremony_phases"]
        decode = {"first_offer": "ceremony_request", "successor_offer": "ceremony_request",
                  "pre_pair_retired": "ceremony_request", "poll": "ceremony_request"}
        for name, document in phases.items():
            with self.subTest(phase=name):
                message = decode.get(name, "ceremony_response")
                self.assertEqual(mac.decode(message, _c(document)), document)
                self.assertEqual(mac.decode_route_request(CEREMONY_ROUTE, _c(document)) if message ==
                                 "ceremony_request" else mac.decode_route_response(CEREMONY_ROUTE, _c(document)),
                                 document)
        # Maximal coexistence: every nullable predecessor/generation/expiry field populated at its maximum
        # simultaneously, with the actual fence, still fits the 4096 ceremony cap.
        maximal = _maximal()
        for name in ("ceremony_offer", "ceremony_challenge", "ceremony_terminal", "ceremony_retired"):
            payload = maximal[name]["payload"]
            self.assertFalse([k for k, v in payload.items() if v is None], name)
            self.assertLessEqual(len(_c(maximal[name])), 4096)

        def refused(code, message, document):
            self.assertRefused(code, mac.decode, message, _c(document))

        pending, aborted = phases["pending"], phases["post_invite_aborted"]
        pre_invite, revoked = phases["pre_invite_aborted"], phases["revoked"]
        first, successor = phases["first_offer"], phases["successor_offer"]

        def with_payload(document, **changes):
            return {**document, "payload": {**document["payload"], **changes}}

        # Matched pending: pairing, runner and the immutable original expiry are mandatory; challenge
        # expiry equals the original pairing expiry (never a receipt horizon).
        refused("phase_nullability", "ceremony_response", with_payload(pending, pairing_id=None))
        refused("null_forbidden", "ceremony_response", with_payload(pending, runner_id=None))
        refused("phase_nullability", "ceremony_response", with_payload(pending, original_pairing_expires_at_ms=None))
        refused("expiry_mismatch", "ceremony_response",
                with_payload(pending, challenge_expires_at_ms=pending["payload"]["challenge_expires_at_ms"] + 1))
        # Reserved pre-invite failure: pairing, runner and expiry null together.
        self.assertIsNone(pre_invite["payload"]["pairing_id"])
        refused("phase_nullability", "ceremony_response",
                with_payload(pre_invite, original_pairing_expires_at_ms=1_793_000_900_000))
        refused("phase_nullability", "ceremony_response", with_payload(pre_invite, runner_id="runr_" + "f" * 32))
        # Post-invite pre-exchange failure: pairing and expiry nonnull, runner null; expiry cannot be dropped.
        self.assertIsNone(aborted["payload"]["runner_id"])
        refused("phase_nullability", "ceremony_response", with_payload(aborted, original_pairing_expires_at_ms=None))
        # Revocation always names its pairing; its reason is fixed.
        refused("phase_nullability", "ceremony_response",
                with_payload(revoked, pairing_id=None, original_pairing_expires_at_ms=None))
        refused("invalid_field", "ceremony_response", with_payload(revoked, reason_code="service_failed"))
        refused("invalid_field", "ceremony_response", with_payload(aborted, reason_code="human_revocation"))
        # Nonnull T members and key never become null.
        for name in ("slot_id", "epoch_id", "managed_executor_id", "workspace_id", "runner_key_id"):
            with self.subTest(nonnull=name):
                refused("null_forbidden", "ceremony_response", with_payload(aborted, **{name: None}))
        # There is no activated payload or active acknowledgement.
        activated = with_payload(aborted, schema_version="heel.managed-activated.v1")
        refused("payload_mismatch", "ceremony_response", activated)
        refused("invalid_field", "ceremony_response", {**aborted, "kind": "activated"})
        retired = phases["pre_pair_retired"]
        refused("invalid_field", "ceremony_request", with_payload(retired, state="active"))
        refused("extra_key", "ceremony_request", with_payload(retired, previous_ack_generation=0))
        # Predecessor linkage: all-null first use, or managed+epoch together; pairing only with a predecessor.
        refused("predecessor_nullability", "ceremony_request", with_payload(first, previous_epoch_id="epoch_" + "0" * 32))
        refused("predecessor_nullability", "ceremony_request",
                with_payload(first, previous_terminal_pairing_id="pending_" + "0" * 32))
        refused("predecessor_nullability", "ceremony_request",
                with_payload(successor, previous_managed_executor_id=None))
        refused("predecessor_reuse", "ceremony_request",
                with_payload(successor, previous_epoch_id=successor["payload"]["epoch_id"]))
        # Envelope and payload must name the same slot/epoch/managed identity.
        refused("envelope_mismatch", "ceremony_request", {**first, "pairing_epoch": "epoch_" + "9" * 32})
        refused("envelope_mismatch", "ceremony_response", {**pending, "managed_executor_id": "mex_" + "9" * 32})
        refused("envelope_mismatch", "ceremony_request", {**retired, "managed_executor_id": "mex_" + "9" * 32})
        # Null managed identity is only for association-free poll/offer/none, never a retired ack or challenge.
        refused("envelope_mismatch", "ceremony_request", {**retired, "managed_executor_id": None})
        refused("null_forbidden", "ceremony_response", {**pending, "managed_executor_id": None})
        refused("payload_mismatch", "ceremony_request", {**phases["poll"], "payload": {"x": 1}})
        # S slot ids outside the stricter host grammar are refused, not normalised.
        for slot in ("slot_1", "slot-", "Slot-1", "a" * 33):
            with self.subTest(slot=slot):
                refused("invalid_field", "ceremony_request", {**phases["poll"], "slot_id": slot})
        # Canonical base64 key only.
        for key in ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=",
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg=="):
            with self.subTest(key=key):
                refused("invalid_field", "ceremony_request", with_payload(first, public_key_b64=key))

    def test_observation_is_historical_and_closed(self):
        offered = _fixture()["observation_offered"]
        self.assertEqual(mac.decode("observation", _c(offered)), offered)
        self.assertEqual(offered["observation_kind"], "historical_not_authorization")
        mac.validate_status_request(b"{}")
        for body in (b"{ }", b'{"managed":true}', b"", b"null", b"{}\n"):
            self.assertRefused("invalid_status_request", mac.validate_status_request, body)
        refused = lambda code, doc: self.assertRefused(code, mac.decode, "observation", _c(doc))
        refused("invalid_field", {**offered, "observation_kind": "current"})
        refused("invalid_field", {**offered, "authority_revision": REV + 1})
        refused("invalid_field", {**offered, "authority_revision": -1})
        refused("invalid_field", {**offered, "observed_at_ms": 0})
        refused("phase_nullability", {**offered, "cancellation_phase": "completed"})
        refused("phase_nullability", {**offered, "observed_state": "pending"})
        refused("phase_nullability", {**offered, "original_pairing_expires_at_ms": 1})
        # S 14.2: the managed offered row is a reservation, so its key is nonnull (no keyless phase).
        self.assertEqual(offered["runner_key_id"], "k_1111111111111111")
        refused("phase_nullability", {**offered, "runner_key_id": None})
        refused("extra_key", {**offered, "active": True})
        maximal = _fixture()["maximal"]["observation"]
        self.assertLessEqual(len(_c(maximal)), 4096)
        self.assertEqual(mac.decode("observation", _c(maximal)), maximal)

    def test_observation_phase_matrix_follows_s_14_2(self):
        """S 14.2 identity/cancellation matrix, as retained by Observation ed901650 section 7.

        Identity phases: pre-invite (no pairing/runner/expiry), post-invite/pre-exchange (pairing +
        original expiry, no runner), matched (pairing + runner + expiry). CP ``pending`` follows
        exchange+approve, so pending/active are matched with a nonnull key; a terminal row preserves
        its adopted phase and keeps the reservation's nonnull key; revoked always has a pairing.
        cancellation_phase is null exactly for nonterminal rows; ``completed`` claims a matching
        retired ack, so any other ack state contradicts it. A historical active ack stays legal on a
        terminal row that has not claimed completion only WITH its pairing (host_ack.v1: active
        requires nonnull pairing; terminal identity preserves the adopted pairing). The managed
        offered row is a reservation, so its key is nonnull too. Structural only: no durable ack or
        reconciliation is proven here.
        """
        base = {"schema_version": "heel.managed-executor-observation.v1", "managed_executor_id": "mex_" + "b" * 32,
                "observation_kind": "historical_not_authorization", "authority_revision": 3,
                "observed_at_ms": 1793000000123, "delivery_status": "delivered", "recovery_code": None,
                "retry_after_ms": None, "host_ack_state": None, "cancellation_phase": None}
        pre = {"pairing_id": None, "runner_id": None, "original_pairing_expires_at_ms": None,
               "runner_key_id": "k_" + "c" * 16}
        invited = {**pre, "pairing_id": "pending_" + "d" * 32, "original_pairing_expires_at_ms": 1793000900000}
        matched = {**invited, "runner_id": "runr_" + "e" * 32}
        phases = {"pre": pre, "invited": invited, "matched": matched}
        terminal_phases = {"revoked": ("invited", "matched"), "aborted": ("pre", "invited", "matched"),
                           "expired": ("pre", "invited", "matched")}
        acks = (None, "active", "retired", "cleanup_pending", "cleanup_failed", "capacity_unavailable")

        def body(state, phase, **changes):
            return {**base, **phases[phase], "observed_state": state, **changes}

        def accepted(document):
            self.assertEqual(mac.decode("observation", _c(document)), document)
            self.assertEqual(mac.validate("observation", copy.deepcopy(document)), document)

        def refused(field, document):
            for function, argument in ((mac.decode, _c(document)), (mac.validate, copy.deepcopy(document))):
                error = self.assertRefused("phase_nullability", function, "observation", argument)
                self.assertEqual(error.field, field)
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)

        valid, invalid = [], []
        # Nonterminal rows: offered may be at any identity phase but always has its reservation key
        # (S 14.2 governs over the S 4.3 / EA 8 nullable shorthand); pending/active only matched with
        # a key; never a cancellation phase.
        for phase in phases:
            valid.append(body("offered", phase))
            for cancellation in ("authority_revoked", "cleanup_pending", "completed"):
                invalid.append(("cancellation_phase", body("offered", phase, cancellation_phase=cancellation)))
        invalid.append(("runner_key_id", body("offered", "pre", runner_key_id=None)))
        for state in ("pending", "active"):
            for ack in (None, "active"):
                valid.append(body(state, "matched", host_ack_state=ack))
            invalid.append(("pairing_id", body(state, "pre")))
            invalid.append(("runner_id", body(state, "invited")))
            invalid.append(("runner_key_id", body(state, "matched", runner_key_id=None)))
            for cancellation in ("authority_revoked", "cleanup_pending", "completed"):
                invalid.append(("cancellation_phase", body(state, "matched", cancellation_phase=cancellation)))
        # Terminal rows at every adopted phase.
        for state, allowed in terminal_phases.items():
            for phase in allowed:
                for cancellation in ("authority_revoked", "cleanup_pending"):
                    for ack in acks:
                        document = body(state, phase, cancellation_phase=cancellation, host_ack_state=ack)
                        if ack == "active" and phase == "pre":  # active ack requires a pairing
                            invalid.append(("pairing_id", document))
                        else:
                            valid.append(document)
                valid.append(body(state, phase, cancellation_phase="completed", host_ack_state="retired"))
                for ack in acks:
                    if ack != "retired":
                        invalid.append(("host_ack_state",
                                        body(state, phase, cancellation_phase="completed", host_ack_state=ack)))
                invalid.append(("cancellation_phase", body(state, phase, host_ack_state="active")))
                invalid.append(("cancellation_phase", body(state, phase, host_ack_state="retired")))
                invalid.append(("runner_key_id", body(state, phase, runner_key_id=None,
                                                      cancellation_phase="authority_revoked")))
        invalid.append(("pairing_id", body("revoked", "pre", cancellation_phase="authority_revoked")))
        invalid.append(("pairing_id", body("revoked", "pre", cancellation_phase="completed", host_ack_state="retired")))
        # Existing pairing/expiry/runner implications are kept for every state.
        for state in mac.NONTERMINAL_STATES + ("revoked", "aborted", "expired"):
            terminal = state not in mac.NONTERMINAL_STATES
            extra = {"cancellation_phase": "authority_revoked"} if terminal else {}
            invalid.append(("original_pairing_expires_at_ms",
                            body(state, "matched", original_pairing_expires_at_ms=None, **extra)))
            if state not in ("pending", "active", "revoked"):
                invalid.append(("original_pairing_expires_at_ms",
                                body(state, "pre", original_pairing_expires_at_ms=1793000900000, **extra)))
            if state not in ("pending", "active", "revoked"):
                invalid.append(("runner_id", body(state, "pre", runner_id="runr_" + "e" * 32, **extra)))
        self.assertEqual(len(valid), 107)
        self.assertEqual(len(invalid), 104)
        for document in valid:
            with self.subTest(valid=(document["observed_state"], document["pairing_id"] is not None,
                                     document["runner_id"] is not None, document["cancellation_phase"],
                                     document["host_ack_state"], document["runner_key_id"] is not None)):
                accepted(document)
        for field, document in invalid:
            with self.subTest(invalid=field, state=document["observed_state"],
                              phase=document["cancellation_phase"], ack=document["host_ack_state"]):
                refused(field, document)
        # The four reviewer-shaped contradictions, rebuilt here: active without a key, revoked without a
        # cancellation phase, completed without an ack and completed over a historical active ack.
        refused("runner_key_id", body("active", "matched", runner_key_id=None, host_ack_state="active"))
        refused("cancellation_phase", body("revoked", "matched", host_ack_state="active"))
        refused("host_ack_state", body("revoked", "matched", cancellation_phase="completed"))
        refused("host_ack_state", body("revoked", "matched", cancellation_phase="completed", host_ack_state="active"))
        # The positive controls the review retained: historical active ack on an incomplete terminal,
        # and a pre-invite terminal that completed with a retired ack.
        accepted(body("revoked", "matched", cancellation_phase="cleanup_pending", host_ack_state="active"))
        accepted(body("aborted", "pre", cancellation_phase="completed", host_ack_state="retired"))
        # C4-P01-SEMANTIC-REVIEW F1a: an active ack without any pairing, on offered/aborted/expired.
        refused("pairing_id", body("offered", "pre", host_ack_state="active"))
        refused("pairing_id", body("aborted", "pre", cancellation_phase="cleanup_pending", host_ack_state="active"))
        refused("pairing_id", body("expired", "pre", cancellation_phase="cleanup_pending", host_ack_state="active"))
        # F1b: the managed offered reservation without its key; the keyed offered row stays valid.
        refused("runner_key_id", body("offered", "pre", runner_key_id=None))
        accepted(body("offered", "pre"))
        # Positive controls: pre-invite retired completion, post-invite historical active history.
        for state in ("aborted", "expired"):
            accepted(body(state, "pre", cancellation_phase="completed", host_ack_state="retired"))
            for phase in ("invited", "matched"):
                accepted(body(state, phase, cancellation_phase="cleanup_pending", host_ack_state="active"))
        # observation_kind and its meaning are unchanged; no phase makes it an authorization.
        self.assertEqual(mac.OBSERVATION_KIND, "historical_not_authorization")

    def test_observation_full_combination_matrix_maps_to_s_14_2(self):
        """Every state x identity phase x ack x cancellation x key combination, against named S rules.

        Each rule cites retained S 2a712217 14.2 (as kept by Observation ed901650 section 7). The oracle
        returns the set of violated rule fields; the codec must accept exactly the combinations with no
        violation and refuse the others with phase_nullability naming one violated field. Nothing here
        infers a database row, a durable ack, auth reconciliation or current authority.
        """
        pre = {"pairing_id": None, "runner_id": None, "original_pairing_expires_at_ms": None}
        invited = {**pre, "pairing_id": "pending_" + "d" * 32, "original_pairing_expires_at_ms": 1793000900000}
        matched = {**invited, "runner_id": "runr_" + "e" * 32}
        phases = {"pre": pre, "invited": invited, "matched": matched}
        rules = (
            # Public response "cancellation_phase is null for nonterminal rows".
            ("cancellation_phase", lambda s, p, a, c, k: s in mac.NONTERMINAL_STATES and c is not None),
            # Terminal rows carry authority_revoked/cleanup_pending/completed after terminal commit.
            ("cancellation_phase", lambda s, p, a, c, k: s not in mac.NONTERMINAL_STATES and c is None),
            # Identity table: matched pending/activating/active rows have pairing and runner.
            ("pairing_id", lambda s, p, a, c, k: s in ("pending", "active") and p == "pre"),
            ("runner_id", lambda s, p, a, c, k: s in ("pending", "active") and p != "matched"),
            # "Matched pending/activated/revoked and cancellation always require nonnull pairing id."
            ("pairing_id", lambda s, p, a, c, k: s == "revoked" and p == "pre"),
            # "IDs/slot/epoch/key/digest are nonnull at reservation" (offered is the reserved row).
            ("runner_key_id", lambda s, p, a, c, k: k is None),
            # "completed ONLY after durable matching retired ack": another ack contradicts the claim.
            ("host_ack_state", lambda s, p, a, c, k: c == "completed" and a != "retired"),
            # host_ack.v1 "active requires nonnull pairing"; terminal identity keeps the pairing.
            ("pairing_id", lambda s, p, a, c, k: a == "active" and p == "pre"),
        )
        accepted = refused = 0
        for state in mac.MANAGED_STATES:
            for phase in phases:
                for ack in (None,) + mac.HOST_ACK_STATES:
                    for cancellation in (None,) + mac.CANCELLATION_PHASES:
                        for key in ("k_" + "c" * 16, None):
                            document = {"schema_version": "heel.managed-executor-observation.v1",
                                        "managed_executor_id": "mex_" + "b" * 32,
                                        "observation_kind": "historical_not_authorization",
                                        "authority_revision": 3, "observed_at_ms": 1793000000123,
                                        "observed_state": state, **phases[phase], "runner_key_id": key,
                                        "delivery_status": "delivered", "host_ack_state": ack,
                                        "recovery_code": None, "retry_after_ms": None,
                                        "cancellation_phase": cancellation}
                            violated = {field for field, rule in rules
                                        if rule(state, phase, ack, cancellation, key)}
                            with self.subTest(state=state, phase=phase, ack=ack, cancellation=cancellation,
                                              key=key is not None):
                                if violated:
                                    error = self.assertRefused("phase_nullability", mac.decode, "observation",
                                                               _c(document))
                                    self.assertIn(error.field, violated)
                                    refused += 1
                                else:
                                    self.assertEqual(mac.decode("observation", _c(document)), document)
                                    accepted += 1
        self.assertEqual(accepted + refused, 6 * 3 * 6 * 4 * 2)
        self.assertEqual((accepted, refused), (129, 735))

    def test_unreserved_root_key_offer_stays_a_separate_ceremony_message(self):
        """The unreserved root key offer (null managed/workspace identity) is the ceremony public_key
        request, not this observation; the offered-key rule neither rejects nor alters it."""
        first = _fixture()["ceremony_phases"]["first_offer"]
        self.assertIsNone(first["managed_executor_id"])
        self.assertEqual([first["payload"][k] for k in ("previous_managed_executor_id", "previous_epoch_id",
                                                        "previous_terminal_pairing_id")], [None, None, None])
        self.assertEqual(mac.decode("ceremony_request", _c(first)), first)
        self.assertEqual(mac.decode_route_request(CEREMONY_ROUTE, _c(first)), first)

    # -------------------------------------------------------------------------------------------
    def test_domain_classification_is_server_owned(self):
        for name in mac.__all__:
            value = getattr(mac, name)
            if callable(value) and not isinstance(value, type):
                parameters = inspect.signature(value).parameters
                self.assertFalse({p for p in parameters if "managed" in p.lower() or p in {"domain", "kind"}},
                                 name)
        self.assertEqual(set(mac.ROUTES), {WINDOW_ROUTE, ATTEMPT_ROUTE, CEREMONY_ROUTE})
        window = _maximal()["window_request"]
        for flag in ({"managed": True}, {"managed": False}, {"domain": "managed"}, {"connector": True}):
            with self.subTest(flag=flag):
                self.assertRefused("extra_key", mac.decode_route_request, WINDOW_ROUTE, _c({**window, **flag}))
        self.assertRefused("unknown_message", mac.decode, "connector_request", b"{}")

    def test_errors_never_echo_untrusted_values(self):
        secret = "sk_live_DO_NOT_ECHO_" + "9" * 24
        window = _maximal()["window_request"]
        bodies = [_c({**window, secret: 1}), _c({**window, "grant_id": secret + "!"}),
                  _c({**window, "request_nonce": secret}), secret.encode() * 200,
                  b'{"' + secret.encode() + b'":1,"' + secret.encode() + b'":2}',
                  b'{"grant_id":' + secret.encode() + b"}", b'{"grant_id":"' + secret.encode() + b'",}',
                  b'{"grant_id":' + secret.encode() + b".5}"]
        codes = set()
        for body in bodies:
            with self.assertRaises(ManagedContractError) as caught:
                mac.decode_route_request(WINDOW_ROUTE, body)
            error = caught.exception
            codes.add(error.code)
            for text in (str(error), repr(error), repr(error.args), str(error.code), str(error.field)):
                self.assertNotIn("DO_NOT_ECHO", text)
            # No parser exception (JSONDecodeError.doc holds the whole body) is chained.
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertTrue(error.field is None or error.field in mac._WINDOW_REQUEST)
        self.assertLessEqual({"extra_key", "invalid_field", "oversize", "duplicate_key", "malformed_json"}, codes)

    def test_module_is_inert_standard_library_only(self):
        tree = ast.parse(Path(mac.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertLessEqual(imported, {"__future__", "base64", "binascii", "dataclasses", "hashlib", "ipaddress",
                                        "json", "re", "typing"})
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertFalse(names & {"open", "socket", "sqlite3", "subprocess", "os", "time", "secrets"})

    def test_existing_host_v1_codec_is_unchanged_and_refuses_managed_bodies(self):
        from heel.saas import host_authority
        self.assertEqual(host_authority.ROUTE, "/host/v1/authority-snapshot")
        self.assertEqual(host_authority.MAX_REQUEST_BYTES, 2048)
        self.assertNotIn(host_authority.ROUTE, mac.ROUTES)
        maximal = _maximal()
        self.assertIsNone(host_authority.validate_request(_c(maximal["window_request"])))
        self.assertIsNone(host_authority.validate_request(_c(maximal["attempt_request"])))


if __name__ == "__main__":
    unittest.main()

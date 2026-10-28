"""Production runtime-profile grading (H1A3-1, H1A3DR design section 7.1).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

The supported profile of H1DR section 3.4 as production constants: the kernel source tags whose
cited functions were pinned, the nftables release, CONFIG_HZ and the non-EXCL re-add behaviour
each tag's source implies. ``kernel_profile`` is the H1F launcher's logic unchanged (the launcher
keeps its own copy; a test pins the two over every input vector). ``grade_self_test`` applies it to
a generation self-test report, so a kernel outside the tags, an unknown HZ or a re-add semantics
that differs from the tag is ``unpinned`` and holds the generation. Grading describes the running
kernel only: it qualifies no provider, SKU or host.
"""

SUPPORTED_KERNELS = {"6.8": "v6.8", "6.17": "v6.17", "7.0": "v7.0"}
SUPPORTED_NFT = ("1.0.9",)
SUPPORTED_HZ = (100, 250, 1000)
READD_EXPECTED = {"6.8": "noop", "6.17": "refresh", "7.0": "refresh"}


def kernel_profile(fields: dict) -> tuple[str, list[str]]:
    """``pinned`` only when the captured runtime is one the pinned sources describe and behaves as
    they say; otherwise ``unpinned`` with closed reasons (the run is then held, never PASS)."""
    reasons = []
    major_minor = fields.get("kernel_major_minor")
    if major_minor not in SUPPORTED_KERNELS:
        reasons.append("kernel_outside_pinned_tags")
    if fields.get("nft_version") not in SUPPORTED_NFT:
        reasons.append("nft_outside_pinned_release")
    if fields.get("config_hz") not in SUPPORTED_HZ:
        reasons.append("config_hz_unavailable_or_unsupported")
    if fields.get("selftest") != "pass":
        reasons.append("compatibility_self_test_failed")
    if fields.get("readd_observation") != READD_EXPECTED.get(major_minor, "unknown"):
        reasons.append("readd_semantics_differ_from_source_tag")
    return ("pinned" if not reasons else "unpinned"), reasons


def profile_fields_of(report) -> dict:
    """The five grading inputs of a ``SelfTestReport`` (absent values are None)."""
    return {"kernel_major_minor": report.tokens.get("kernel_major_minor"), "nft_version": report.tokens.get("nft_version"),
            "config_hz": report.ints.get("config_hz"), "selftest": report.tokens.get("selftest"),
            "readd_observation": report.tokens.get("readd_observation")}


def grade_self_test(report) -> tuple[str, list[str]]:
    return kernel_profile(profile_fields_of(report))


def tick_ns(report) -> int:
    """One jiffy in nanoseconds, rounded up, from the report's CONFIG_HZ; ``KeyError`` when the report
    has none (the caller treats that as unpinned)."""
    hz = report.ints["config_hz"]
    if type(hz) is not int or hz <= 0:
        raise KeyError("config_hz")
    return -(-1_000_000_000 // hz)

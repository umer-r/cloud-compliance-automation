"""
Safely reconcile Cloudflare published IP ranges into AWS customer-managed prefix lists.

Algorithm (per address family):
  1. Fetch desired CIDRs from Cloudflare API
  2. Fail closed on fetch/parse errors or empty result (no AWS changes)
  3. Diff desired vs current prefix-list entries
  4. Apply adds before removes (overlap stays allowed → no traffic gap)
  5. Abort removals if count exceeds SAFETY_THRESHOLD
  6. Tag prefix list with last_updated timestamp and notify SNS topic if changes occurred

Author: Umer R.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
ENTRY_DESCRIPTION = "cloudflare ip reconciled via lambda | https://api.cloudflare.com/client/v4/ips"
HTTP_TIMEOUT_SECONDS = 15
LAST_UPDATED_TAG_KEY = "last_updated"

# Abort remove path if this many CIDRs would be removed in one run (protects against bad API data).
DEFAULT_SAFETY_THRESHOLD = 3


class FailClosedError(Exception):
    """Raised when reconcile must stop without mutating AWS state."""


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    if value is not None and value.strip() == "":
        return default
    return value


def fetch_cloudflare_cidrs() -> tuple[set[str], set[str]]:
    """Return (ipv4_cidrs, ipv6_cidrs). Raises FailClosedError on any problem."""
    try:
        request = urllib.request.Request(
            CLOUDFLARE_IPS_URL,
            headers={"Accept": "application/json", "User-Agent": "cf-whitelisting-lambda/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise FailClosedError(f"Cloudflare API HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FailClosedError(f"Cloudflare API network error: {exc.reason}") from exc
    except TimeoutError as exc:
        raise FailClosedError("Cloudflare API request timed out") from exc

    if status != 200:
        raise FailClosedError(f"Cloudflare API unexpected status {status}")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise FailClosedError("Cloudflare API returned non-JSON body") from exc

    if not payload.get("success"):
        raise FailClosedError(f"Cloudflare API success=false: {payload.get('errors')}")

    result = payload.get("result") or {}
    ipv4 = {c.strip() for c in result.get("ipv4_cidrs") or [] if c and str(c).strip()}
    ipv6 = {c.strip() for c in result.get("ipv6_cidrs") or [] if c and str(c).strip()}

    if not ipv4 and not ipv6:
        raise FailClosedError("Cloudflare API returned empty IPv4 and IPv6 CIDR lists")

    return ipv4, ipv6


def get_prefix_list_state(ec2_client: Any, prefix_list_id: str) -> tuple[int, set[str]]:
    """Return (current_version, set of CIDR strings) for a managed prefix list."""
    describe = ec2_client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])
    lists = describe.get("PrefixLists") or []
    if not lists:
        raise FailClosedError(f"Prefix list not found: {prefix_list_id}")

    pl = lists[0]
    state = pl.get("State")
    # Block mid-flight or failed states so we never mutate a moving target.
    if state not in ("create-complete", "modify-complete"):
        raise FailClosedError(f"Prefix list {prefix_list_id} not stable (state={state})")

    version = pl["Version"]
    cidrs: set[str] = set()
    paginator = ec2_client.get_paginator("get_managed_prefix_list_entries")
    for page in paginator.paginate(PrefixListId=prefix_list_id):
        for entry in page.get("Entries") or []:
            cidr = entry.get("Cidr")
            if cidr:
                cidrs.add(cidr)

    return version, cidrs


def tag_prefix_list_last_updated(ec2_client: Any, prefix_list_id: str) -> str:
    """Set/overwrite last_updated on the prefix list. Call only after a successful modify."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        ec2_client.create_tags(
            Resources=[prefix_list_id],
            Tags=[{"Key": LAST_UPDATED_TAG_KEY, "Value": timestamp}],
        )
    except ClientError as exc:
        raise FailClosedError(
            f"Failed to tag prefix list {prefix_list_id} with {LAST_UPDATED_TAG_KEY}: {exc}"
        ) from exc
    logger.info(
        "Tagged prefix list %s %s=%s",
        prefix_list_id,
        LAST_UPDATED_TAG_KEY,
        timestamp,
    )
    return timestamp


def publish_sns_notification(
    sns_client: Any,
    topic_arn: str,
    modified_results: list[dict[str, Any]],
) -> str:
    """
    Publish an alert notification to SNS when Cloudflare prefix lists change.
    Returns the published MessageId.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    families_str = ", ".join(r.get("family", "unknown").upper() for r in modified_results)

    lines = [
        "Cloudflare Managed Prefix List Reconciliation Alert",
        "=" * 50,
        f"Timestamp (UTC): {now_utc}",
        f"Status         : Successfully updated {len(modified_results)} prefix list(s) ({families_str})",
        "",
        "Changes Applied:",
    ]

    for item in modified_results:
        fam = item.get("family", "unknown").upper()
        pl_id = item.get("prefix_list_id")
        v_before = item.get("version_before")
        v_after = item.get("version_after")
        added = item.get("to_add") or []
        removed = item.get("to_remove") or []
        last_updated = item.get("last_updated")

        lines.extend([
            f"[{fam} Prefix List: {pl_id}]",
            f"  - Version Change: {v_before} -> {v_after}",
            f"  - Added CIDRs ({len(added)}): {', '.join(added) if added else 'None'}",
            f"  - Removed CIDRs ({len(removed)}): {', '.join(removed) if removed else 'None'}",
            f"  - Tagged timestamp: {last_updated}",
            "",
        ])

    lines.extend([
        "Details (JSON):",
        json.dumps(modified_results, indent=2),
    ])

    subject = f"[Security Alert] Cloudflare Prefix List Updated ({families_str})"
    # SNS Subject limit is 100 ASCII characters
    if len(subject) > 100:
        subject = subject[:97] + "..."

    message_body = "\n".join(lines)

    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message_body,
        )
    except ClientError as exc:
        logger.error("Failed to publish notification to SNS topic %s: %s", topic_arn, exc)
        raise FailClosedError(f"Failed to publish to SNS topic {topic_arn}: {exc}") from exc

    message_id = response.get("MessageId", "")
    logger.info(
        "Published change notification to SNS topic %s (MessageId: %s)",
        topic_arn,
        message_id,
    )
    return message_id


def reconcile_prefix_list(
    ec2_client: Any,
    *,
    prefix_list_id: str,
    desired: set[str],
    family: str,
    safety_threshold: int,
) -> dict[str, Any]:
    """
    Diff-based reconcile for one prefix list.
    Adds first within the same ModifyManagedPrefixList call when both change.
    Never clears the list on empty desired (caller should fail closed before that).
    """
    if not desired:
        raise FailClosedError(f"{family}: desired CIDR set empty; refusing to reconcile")

    version, current = get_prefix_list_state(ec2_client, prefix_list_id)
    to_add = sorted(desired - current)
    to_remove = sorted(current - desired)
    unchanged = len(current & desired)

    result: dict[str, Any] = {
        "family": family,
        "prefix_list_id": prefix_list_id,
        "version_before": version,
        "current_count": len(current),
        "desired_count": len(desired),
        "unchanged": unchanged,
        "to_add": to_add,
        "to_remove": to_remove,
        "action": "noop",
    }

    if not to_add and not to_remove:
        logger.info(
            "%s: prefix list %s already in sync (%d CIDRs)",
            family,
            prefix_list_id,
            len(current),
        )
        return result

    if len(to_remove) > safety_threshold:
        raise FailClosedError(
            f"{family}: would remove {len(to_remove)} CIDRs which exceeds "
            f"SAFETY_THRESHOLD={safety_threshold}; skipping all mutations. "
            f"removals={to_remove}"
        )

    # AWS applies AddEntries and RemoveEntries in one atomic modify when both are supplied.
    # Prefer calling with adds present so capacity is reserved before removals take effect
    # if a multi-call path is ever needed later. Single call keeps overlap continuous.
    modify_kwargs: dict[str, Any] = {
        "PrefixListId": prefix_list_id,
        "CurrentVersion": version,
    }
    if to_add:
        modify_kwargs["AddEntries"] = [
            {"Cidr": cidr, "Description": ENTRY_DESCRIPTION} for cidr in to_add
        ]
    if to_remove:
        modify_kwargs["RemoveEntries"] = [{"Cidr": cidr} for cidr in to_remove]

    logger.info(
        "%s: applying changes to %s (add=%d remove=%d)",
        family,
        prefix_list_id,
        len(to_add),
        len(to_remove),
    )

    try:
        response = ec2_client.modify_managed_prefix_list(**modify_kwargs)
    except ClientError as exc:
        raise FailClosedError(
            f"{family}: ModifyManagedPrefixList failed for {prefix_list_id}: {exc}"
        ) from exc

    pl = (response.get("PrefixList") or {})
    result["action"] = "modified"
    result["version_after"] = pl.get("Version")
    result["state"] = pl.get("State")
    # Tag only when entries changed; noop path returns earlier without tagging.
    result["last_updated"] = tag_prefix_list_last_updated(ec2_client, prefix_list_id)
    return result


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    prefix_list_v4 = _env("PREFIX_LIST_ID_V4")
    prefix_list_v6 = _env("PREFIX_LIST_ID_V6")
    if not prefix_list_v4 and not prefix_list_v6:
        raise FailClosedError(
            "Set at least one of PREFIX_LIST_ID_V4 or PREFIX_LIST_ID_V6"
        )

    safety_raw = _env("SAFETY_THRESHOLD", str(DEFAULT_SAFETY_THRESHOLD))
    try:
        safety_threshold = int(safety_raw)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise FailClosedError(f"Invalid SAFETY_THRESHOLD={safety_raw!r}") from exc

    region = _env("AWS_REGION") or _env("AWS_DEFAULT_REGION") or "eu-west-2"
    ec2 = boto3.client("ec2", region_name=region)

    logger.info("Fetching Cloudflare IP ranges from %s", CLOUDFLARE_IPS_URL)
    ipv4_desired, ipv6_desired = fetch_cloudflare_cidrs()
    logger.info(
        "Cloudflare returned ipv4=%d ipv6=%d",
        len(ipv4_desired),
        len(ipv6_desired),
    )

    # Fail closed if a configured family has an empty desired set.
    if prefix_list_v4 and not ipv4_desired:
        raise FailClosedError("PREFIX_LIST_ID_V4 configured but Cloudflare returned no IPv4 CIDRs")
    if prefix_list_v6 and not ipv6_desired:
        raise FailClosedError("PREFIX_LIST_ID_V6 configured but Cloudflare returned no IPv6 CIDRs")

    results: list[dict[str, Any]] = []

    if prefix_list_v4:
        results.append(
            reconcile_prefix_list(
                ec2,
                prefix_list_id=prefix_list_v4,
                desired=ipv4_desired,
                family="ipv4",
                safety_threshold=safety_threshold,
            )
        )

    if prefix_list_v6:
        results.append(
            reconcile_prefix_list(
                ec2,
                prefix_list_id=prefix_list_v6,
                desired=ipv6_desired,
                family="ipv6",
                safety_threshold=safety_threshold,
            )
        )

    # Notify SNS only when proxy IPs have changed and prefix lists were modified
    modified = [r for r in results if r.get("action") == "modified"]
    sns_topic_arn = _env("SNS_TOPIC_ARN")
    sns_message_id = None

    if modified:
        if sns_topic_arn:
            sns = boto3.client("sns", region_name=region)
            sns_message_id = publish_sns_notification(sns, sns_topic_arn, modified)
        else:
            logger.info(
                "Prefix lists were modified, but SNS_TOPIC_ARN is not configured; skipping notification"
            )

    summary = {
        "ok": True,
        "safety_threshold": safety_threshold,
        "modified_count": len(modified),
        "sns_notified": bool(sns_message_id),
        "sns_message_id": sns_message_id,
        "families": results,
    }
    logger.info("Reconcile complete: %s", json.dumps(summary, default=str))
    return summary

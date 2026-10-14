"""Ludus range broker.

Launch posture: Ludus does not exist yet (it will run on the Hetzner/Proxmox
box). Until LUDUS_API_URL is set, enrollment records a RangeRequest in the
`queued` state and returns cleanly. Nothing breaks, no range is promised.

When the Hetzner box is up, set two env vars on the service:

    LUDUS_API_URL   e.g. https://ludus.internal.qwalora.com/api
    LUDUS_API_KEY   the Ludus admin API key

and the same enroll path begins actually calling Ludus to provision a
per-candidate isolated range. The call surface here matches Ludus's REST
API shape; wire the exact endpoint when the box is live.
"""
import os


def broker_status():
    """Human-readable state of the broker, for the admin dashboard."""
    return "live" if os.environ.get("LUDUS_API_URL") else "stubbed (no LUDUS_API_URL)"


def queue_range(candidate):
    """Return (status, ludus_range_id, detail) for a candidate's range request.

    Stubbed until LUDUS_API_URL is configured. When live, this is where the
    POST to Ludus to deploy the candidate's range template goes.
    """
    api = os.environ.get("LUDUS_API_URL")
    if not api:
        return ("queued", None,
                "Ludus not configured yet; request parked. Will provision when "
                "LUDUS_API_URL is set on the service.")
    # --- Live path (wire when Ludus is reachable) -----------------------------
    # import urllib.request, json
    # key = os.environ.get("LUDUS_API_KEY", "")
    # payload = json.dumps({"user": candidate.handle, "template": "goad-ranger"}).encode()
    # req = urllib.request.Request(f"{api}/range/deploy", data=payload, method="POST",
    #                              headers={"Content-Type": "application/json",
    #                                       "X-API-KEY": key})
    # with urllib.request.urlopen(req, timeout=15) as r:
    #     data = json.load(r)
    # return ("provisioned", data.get("rangeId"), "deploy accepted")
    return ("queued", None, "Ludus configured; live deploy not yet wired in broker.")

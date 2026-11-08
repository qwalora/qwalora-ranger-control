"""Ranger Foundation Track — Cisco Networking Academy (NetAcad) alignment.

Qwalora partners with Cisco Networking Academy: candidates build their baseline on NetAcad
BEFORE the Ranger qualification ladder, and each NetAcad course is mapped to the Ranger board or
competency it prepares them for. This module is the single source of truth for that mapping and
for the public, self-serve enrollment links surfaced on the candidate dashboard as "must take".

Design notes
------------
* Links are REAL public NetAcad entry points. Where a course has a verified direct self-enrollment
  deep link it is used; otherwise the course points at NetAcad's public cybersecurity catalog, where
  that course is enrollable. Nothing here is a fabricated course id.
* The track is per program. STRATA (SOC -> IR -> detection -> hunt -> red team) maps to the
  Junior Cybersecurity Analyst Career Path plus Ethical Hacker for the offensive rungs. PARALLAX
  (AI security) maps to the security fundamentals a candidate needs before AI-specific boards.
* Completion is attested per course by the candidate (stored server-side, see models.FoundationAttestation)
  and the dashboard reports progress. The foundation is REQUIRED: it is the candidate's "start here".
"""

PROVIDER = "Cisco Networking Academy"
# NetAcad's public cybersecurity catalog: every foundation course below is enrollable from here.
CATALOG_URL = "https://www.netacad.com/courses/cybersecurity"

# Course catalog. `url` is the public enrollment entry point; `verified_direct` marks a confirmed
# direct self-enroll deep link (vs. the catalog landing). Hours/level are from NetAcad's catalog.
COURSES = {
    "intro-cyber": {
        "title": "Introduction to Cybersecurity",
        "url": "https://www.netacad.com/portal/web/self-enroll/m/course-1605348",
        "verified_direct": True, "hours": 6, "level": "Foundational",
    },
    "networking-basics": {
        "title": "Networking Basics",
        "url": CATALOG_URL, "verified_direct": False, "hours": 25, "level": "Foundational",
    },
    "endpoint-security": {
        "title": "Endpoint Security",
        "url": CATALOG_URL, "verified_direct": False, "hours": 27, "level": "Introductory",
    },
    "network-defense": {
        "title": "Network Defense",
        "url": CATALOG_URL, "verified_direct": False, "hours": 27, "level": "Intermediate",
    },
    "cyber-threat-management": {
        "title": "Cyber Threat Management",
        "url": CATALOG_URL, "verified_direct": False, "hours": 16, "level": "Advanced",
    },
    "ethical-hacker": {
        "title": "Ethical Hacker",
        "url": CATALOG_URL, "verified_direct": False, "hours": 70, "level": "Advanced",
    },
    "cybersecurity-essentials": {
        "title": "Cybersecurity Essentials",
        "url": "https://www.netacad.com/portal/web/self-enroll/m/course-650455",
        "verified_direct": True, "hours": 70, "level": "Intermediate",
    },
}

# Per-program tracks. Each step maps a NetAcad course to the Ranger board/competency it prepares.
TRACKS = {
    "strata": {
        "title": "STRATA foundation",
        "pathway_name": "Cisco Junior Cybersecurity Analyst Career Path + Ethical Hacker",
        "intro": ("Build your defensive and offensive baseline on NetAcad, then prove it on the "
                  "Ranger ladder. Each course below maps to the board it readies you for."),
        "steps": [
            {"course": "intro-cyber",
             "maps_to": "Orientation - the vocabulary and threat landscape the whole ladder assumes"},
            {"course": "networking-basics",
             "maps_to": "Board 1 (SOC Analyst, triage) - you cannot triage traffic you cannot read"},
            {"course": "endpoint-security",
             "maps_to": "Board 1 (SOC Analyst, triage) - endpoint telemetry, the signals your SOC console surfaces"},
            {"course": "network-defense",
             "maps_to": "Board 3 (Detection Engineer) - monitoring, access control and the detection logic you will write"},
            {"course": "cyber-threat-management",
             "maps_to": "Board 2 + Board 4 (Threat Hunter + Incident Responder) - hunting, threat intel and incident response"},
            {"course": "ethical-hacker",
             "maps_to": "Boards 5-6 (Red Team + Capstone) - Active Directory attack paths and the forest capstone"},
        ],
    },
    "parallax": {
        "title": "PARALLAX foundation",
        "pathway_name": "Cisco security fundamentals",
        "intro": ("Before you harden and attack AI systems, you establish the security fundamentals "
                  "every PARALLAX board reasons from. These NetAcad courses are that groundwork."),
        "steps": [
            {"course": "intro-cyber",
             "maps_to": "Orientation - core security concepts the research console assumes"},
            {"course": "cybersecurity-essentials",
             "maps_to": "All PARALLAX boards - cryptography, access control, and defense principles you "
                        "carry into prompt-injection defense, secure architecture review, and the capstone"},
        ],
    },
}


def track_for(program):
    """The foundation track dict for a program, or None if the program has no NetAcad track."""
    return TRACKS.get(program)


def required_course_keys(program):
    t = TRACKS.get(program)
    return [s["course"] for s in t["steps"]] if t else []


def build_vm(program, attested_keys):
    """Dashboard view model for a program's foundation track.

    `attested_keys` is the set of course keys the candidate has marked complete. Returns None when
    the program has no track (so the template simply omits the card)."""
    t = TRACKS.get(program)
    if not t:
        return None
    attested = set(attested_keys or ())
    steps = []
    for i, step in enumerate(t["steps"], start=1):
        c = COURSES[step["course"]]
        steps.append({
            "n": i,
            "key": step["course"],
            "title": c["title"],
            "url": c["url"],
            "verified_direct": c["verified_direct"],
            "hours": c["hours"],
            "level": c["level"],
            "maps_to": step["maps_to"],
            "done": step["course"] in attested,
        })
    total = len(steps)
    done = sum(1 for s in steps if s["done"])
    return {
        "program": program,
        "title": t["title"],
        "pathway_name": t["pathway_name"],
        "intro": t["intro"],
        "provider": PROVIDER,
        "catalog_url": CATALOG_URL,
        "steps": steps,
        "total": total,
        "done": done,
        "complete": (total > 0 and done == total),
        "next_title": next((s["title"] for s in steps if not s["done"]), None),
    }

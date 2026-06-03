import hmac
import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from modules.url_utils import normalize_url, get_domain
from modules.dns_check import run_dns_check
from modules.ssl_check import run_ssl_check
from modules.robots_check import run_robots_check
from modules.page_metadata import fetch_page_metadata
from modules.tracker_detection import detect_trackers, load_trackers
from modules.rdap_lookup import run_rdap_lookup
from modules.parent_company_lookup import run_parent_company_lookup
from modules.virustotal_check import run_virustotal_url_check
from modules.recommendation_engine import suggest_recommendation
from modules.excel_writer import (
    assessment_to_row,
    write_draft_excel,
    append_rows_to_template,
    COLUMNS,
)


# ------------------------------------------------------------
# Basic setup
# ------------------------------------------------------------

APP_DIR = Path(__file__).parent
OUTPUT_DIR = APP_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

load_dotenv(APP_DIR / ".env")

st.set_page_config(
    page_title="MA Tier 0 Risk Assessment Assistant",
    layout="wide",
)


# ------------------------------------------------------------
# General helper functions
# ------------------------------------------------------------

def get_secret_or_env(name: str) -> str:
    """
    Reads from Streamlit secrets first, then from .env/environment.
    """
    try:
        val = st.secrets.get(name, "")
        if val:
            return str(val).strip()
    except Exception:
        pass

    return os.getenv(name, "").strip()


def load_review_links() -> dict:
    review_links_path = APP_DIR / "config" / "review_links.json"
    with open(review_links_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_review_links(url: str, domain: str) -> dict:
    links = load_review_links()
    return {
        name: template.format(url=url, domain=domain)
        for name, template in links.items()
    }


def safe_virustotal_check(url: str, vt_key: str, use_vt: bool) -> dict:
    """
    Wrapper around VirusTotal so raw API errors do not dump into the workbook fields.
    """
    if not use_vt:
        return {
            "status": "Skipped",
            "malicious": "N/A",
            "suspicious": "N/A",
            "harmless": "N/A",
            "undetected": "N/A",
            "notes": "VirusTotal check skipped by user.",
        }

    if not vt_key:
        return {
            "status": "Manual Review Required",
            "malicious": "N/A",
            "suspicious": "N/A",
            "harmless": "N/A",
            "undetected": "N/A",
            "notes": (
                "VirusTotal API key was not loaded. Add VT_API_KEY to the .env "
                "file or paste the key into the sidebar field. Manual VirusTotal "
                "review required."
            ),
        }

    try:
        result = run_virustotal_url_check(url, vt_key)

        if not isinstance(result, dict):
            return {
                "status": "Needs Review",
                "malicious": "N/A",
                "suspicious": "N/A",
                "harmless": "N/A",
                "undetected": "N/A",
                "notes": f"VirusTotal returned an unexpected result: {result}",
            }

        status = str(result.get("status", "")).strip()
        result_text = str(result)
        if (
            "WrongCredentialsError" in result_text
            or "Wrong API key" in result_text
            or status.startswith("HTTP 401")
            or status.startswith("HTTP 403")
            or status == "No API key"
        ):
            return {
                "status": "Authentication Failed",
                "malicious": "N/A",
                "suspicious": "N/A",
                "harmless": "N/A",
                "undetected": "N/A",
                "notes": (
                    "VirusTotal API authentication failed. Check that VT_API_KEY "
                    "in your .env file is correct, has no quotes/spaces, and is a "
                    "valid VirusTotal API key. Manual VirusTotal review required."
                ),
            }

        if status.startswith("HTTP ") or status.startswith("Submit failed HTTP"):
            return {
                "status": "Needs Review",
                "malicious": "N/A",
                "suspicious": "N/A",
                "harmless": "N/A",
                "undetected": "N/A",
                "notes": (
                    "VirusTotal did not return a usable report. Manual review is "
                    f"required. Details: {result.get('notes', status)}"
                ),
            }

        if not result.get("notes"):
            result["notes"] = "VirusTotal check completed."

        return result

    except Exception as exc:
        return {
            "status": "Error",
            "malicious": "N/A",
            "suspicious": "N/A",
            "harmless": "N/A",
            "undetected": "N/A",
            "notes": (
                "VirusTotal check failed. This may be caused by an invalid key, "
                "network blocking, rate limiting, or a temporary VirusTotal issue. "
                f"Error: {exc}"
            ),
        }


def run_assessment(raw_url: str, vt_key: str, use_vt: bool) -> dict:
    url = normalize_url(raw_url)
    domain = get_domain(url)

    metadata = fetch_page_metadata(url)

    assessment = {
        "url": url,
        "domain": domain,
        "dns": run_dns_check(domain),
        "ssl": run_ssl_check(domain),
        "robots": run_robots_check(f"https://{domain}"),
        "metadata": metadata,
        "tracking": detect_trackers(
            metadata.get("html", ""),
            load_trackers(str(APP_DIR / "config" / "known_trackers.json")),
        ),
        "rdap": run_rdap_lookup(domain),
        "parent_company": run_parent_company_lookup(url, domain),
        "virustotal": safe_virustotal_check(url, vt_key, use_vt),
    }

    assessment["recommendation"] = suggest_recommendation(assessment)
    assessment["review_links"] = build_review_links(url, domain)

    return assessment


def build_default_origin_text(assessment: dict) -> str:
    parent = assessment.get("parent_company", {})

    possible_owner = parent.get("possible_owner") or "Unable to determine"
    possible_location = parent.get("possible_location") or "Unable to determine"
    confidence = parent.get("confidence") or "Low"

    return (
        f"Possible Owner: {possible_owner}\n"
        f"Possible Location: {possible_location}\n"
        f"Confidence: {confidence}"
    )


def build_default_vulnerability_text(assessment: dict) -> str:
    dns = assessment.get("dns", {})
    ssl = assessment.get("ssl", {})
    robots = assessment.get("robots", {})

    return (
        f"DNS: {dns.get('notes', '')} | "
        f"SSL: {ssl.get('notes', '')} | "
        f"robots.txt: {robots.get('notes', '')}"
    )


# ------------------------------------------------------------
# Guided topical review helper functions
# ------------------------------------------------------------

def draft_content_association_from_metadata(assessment: dict) -> str:
    """
    Uses page title and meta description to create a preliminary Content Association draft.
    This is supporting evidence only and still requires analyst confirmation.
    """
    metadata = assessment.get("metadata", {})
    title = metadata.get("title", "") or "Not found"
    description = metadata.get("description", "") or "Not found"

    combined = f"{title} {description}".lower()

    low_risk_terms = [
        "government",
        "official",
        "library",
        "education",
        "university",
        "college",
        "museum",
        "public",
        "research",
        "archive",
        "health",
        "science",
        "news",
        "agency",
        "department",
        "institute",
        "library of congress",
        "national archives",
    ]

    concern_terms = [
        "malware",
        "exploit",
        "hacking",
        "darknet",
        "dark web",
        "leak",
        "stolen",
        "torrent",
        "piracy",
        "weapon",
        "weapons",
        "extremist",
        "propaganda",
        "gambling",
        "adult",
        "fraud",
        "scam",
        "phishing",
        "counterfeit",
        "breach",
        "dump",
        "credential",
        "ransomware",
    ]

    concern_hits = [term for term in concern_terms if term in combined]
    low_risk_hits = [term for term in low_risk_terms if term in combined]

    if concern_hits:
        preliminary = (
            "Potential concern identified from site-provided metadata. "
            f"Matched terms: {', '.join(concern_hits)}. Analyst review required."
        )
    elif low_risk_hits:
        preliminary = (
            "Preliminary low-risk content association based on site-provided metadata. "
            f"Matched terms: {', '.join(low_risk_hits)}. Analyst should validate with review links."
        )
    elif title != "Not found" or description != "Not found":
        preliminary = (
            "Metadata was available, but it did not clearly establish a low-risk or high-risk association. "
            "Analyst review required."
        )
    else:
        preliminary = (
            "No useful page title or meta description was found. Analyst review required."
        )

    return (
        "Automated metadata-based draft only. Analyst confirmation required.\n\n"
        f"Page Title: {title}\n"
        f"Meta Description: {description}\n\n"
        f"Preliminary Content Association: {preliminary}"
    )


def format_guided_review_result(
    category: str,
    finding: str,
    reviewed_links: list,
    notes: str,
) -> str:
    reviewed = ", ".join(reviewed_links) if reviewed_links else "No links selected"

    if not notes or not notes.strip():
        notes = "None entered."

    return (
        f"{category}: {finding}. "
        f"Reviewed sources: {reviewed}. "
        f"Notes: {notes}"
    )


def guided_review_panel(
    title: str,
    purpose: str,
    link_names: list,
    review_links: dict,
    finding_options: list,
    default_index: int,
    notes_default: str,
    session_key_prefix: str,
) -> str:
    """
    Reusable guided analyst review panel.
    Returns an Excel-ready text summary.
    """
    st.markdown(f"#### {title}")
    st.caption(purpose)

    available_links = []
    for link_name in link_names:
        if review_links.get(link_name):
            available_links.append(link_name)

    if available_links:
        link_cols = st.columns(min(3, len(available_links)))
        for idx, link_name in enumerate(available_links):
            with link_cols[idx % len(link_cols)]:
                st.link_button(link_name, review_links[link_name])
    else:
        st.warning("No review links available for this category.")

    finding = st.selectbox(
        f"{title} Finding",
        finding_options,
        index=default_index,
        key=f"{session_key_prefix}_finding",
    )

    reviewed_links = st.multiselect(
        f"{title} Sources Reviewed",
        available_links,
        default=available_links,
        key=f"{session_key_prefix}_sources",
    )

    notes = st.text_area(
        f"{title} Notes",
        value="",
        height=120,
        key=f"{session_key_prefix}_notes",
        help=notes_default,
        placeholder="Enter analyst notes here, if needed.",
    )

    result = format_guided_review_result(
        category=title,
        finding=finding,
        reviewed_links=reviewed_links,
        notes=notes,
    )

    st.text_area(
        f"{title} Excel Output Preview",
        value=result,
        height=110,
        key=f"{session_key_prefix}_preview",
        disabled=True,
    )

    return result


def get_topical_recommendation_override() -> str | None:
    """
    Uses analyst topical review findings to adjust the suggested recommendation.
    """
    content_finding = st.session_state.get("content_association_finding", "")
    adversarial_finding = st.session_state.get("adversarial_finding", "")
    reputation_finding = st.session_state.get("reputation_finding", "")

    analyst_flags = [
        content_finding,
        st.session_state.get("mainstream_finding", ""),
        adversarial_finding,
        reputation_finding,
    ]

    if reputation_finding == "Poor":
        return "Unsuitable"

    if adversarial_finding == "Concern Found":
        return "Exception–Escalate"

    if content_finding == "Concern Found":
        return "Exception–Escalate"

    if "Not Accessible" in analyst_flags:
        return "Needs Review"

    if "Needs Review" in analyst_flags:
        return "Needs Review"

    return None


def get_batch_topical_recommendation_override(key_prefix: str) -> str | None:
    """
    Uses batch-specific analyst topical review findings to adjust the suggested recommendation.
    """
    content_finding = st.session_state.get(f"{key_prefix}_content_association_finding", "")
    mainstream_finding = st.session_state.get(f"{key_prefix}_mainstream_finding", "")
    adversarial_finding = st.session_state.get(f"{key_prefix}_adversarial_finding", "")
    reputation_finding = st.session_state.get(f"{key_prefix}_reputation_finding", "")

    analyst_flags = [
        content_finding,
        mainstream_finding,
        adversarial_finding,
        reputation_finding,
    ]

    if reputation_finding == "Poor":
        return "Unsuitable"

    if adversarial_finding == "Concern Found":
        return "Exception–Escalate"

    if content_finding == "Concern Found":
        return "Exception–Escalate"

    if "Not Accessible" in analyst_flags:
        return "Needs Review"

    if "Needs Review" in analyst_flags:
        return "Needs Review"

    return None


def build_manual_row_dict(
    evaluator: str,
    site_number: str,
    manual_title: str,
    manual_blurb: str,
    final_recommendation: str,
    comments: str,
) -> dict:
    return {
        "site_number": site_number,
        "evaluator": evaluator,
        "site_title": manual_title,
        "blurb": manual_blurb,
        "origin": st.session_state.get("origin", ""),
        "malware": st.session_state.get("malware", ""),
        "tracking": st.session_state.get("tracking", ""),
        "vulnerability": st.session_state.get("vulnerability", ""),
        "content_association": st.session_state.get("content_association", ""),
        "mainstream": st.session_state.get("mainstream", ""),
        "adversarial": st.session_state.get("adversarial", ""),
        "reputation": st.session_state.get("reputation", ""),
        "final_recommendation": final_recommendation,
        "comments": comments,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


def build_batch_review_row(
    evaluator: str,
    site_number: str,
    manual_title: str,
    manual_blurb: str,
    final_recommendation: str,
    comments: str,
    key_prefix: str,
) -> dict:
    """
    Builds one reviewed Excel row from the current batch review screen.
    Uses unique batch widget keys so batch review does not interfere with single URL review.
    """
    return {
        "site_number": site_number,
        "evaluator": evaluator,
        "site_title": manual_title,
        "blurb": manual_blurb,
        "origin": st.session_state.get(f"{key_prefix}_origin", ""),
        "malware": st.session_state.get(f"{key_prefix}_malware", ""),
        "tracking": st.session_state.get(f"{key_prefix}_tracking", ""),
        "vulnerability": st.session_state.get(f"{key_prefix}_vulnerability", ""),
        "content_association": st.session_state.get(f"{key_prefix}_content_association", ""),
        "mainstream": st.session_state.get(f"{key_prefix}_mainstream", ""),
        "adversarial": st.session_state.get(f"{key_prefix}_adversarial", ""),
        "reputation": st.session_state.get(f"{key_prefix}_reputation", ""),
        "final_recommendation": final_recommendation,
        "comments": comments,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


def get_batch_saved_value(
    reviewed_rows: dict,
    current_index: int,
    column_name: str,
    fallback: str = "",
) -> str:
    """
    Returns a previously saved value for the current batch URL if it exists.
    This prevents reviewed values from disappearing when the analyst navigates
    away from a URL and comes back later.
    """
    saved_row = reviewed_rows.get(current_index, {})
    value = saved_row.get(column_name, fallback)

    if value is None:
        return fallback

    return str(value)


def require_app_password() -> None:
    """
    Blocks app access unless APP_ACCESS_PASSWORD is provided and entered correctly.
    If APP_ACCESS_PASSWORD is not configured, the app remains open.
    """
    configured_password = get_secret_or_env("APP_ACCESS_PASSWORD")

    if not configured_password:
        return

    if st.session_state.get("is_authenticated", False):
        return

    st.title("MA Tier 0 Risk Assessment Assistant")
    st.warning("This app is password protected.")

    with st.form("app_login_form"):
        entered_password = st.text_input("App Password", type="password")
        submitted = st.form_submit_button("Unlock App")

    if submitted:
        if hmac.compare_digest(entered_password, configured_password):
            st.session_state["is_authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password. Please try again.")

    st.stop()


# ------------------------------------------------------------
# Sidebar
# ------------------------------------------------------------

require_app_password()

st.title("MA Tier 0 Risk Assessment Assistant")
st.caption(
    "Prototype: single URL and batch draft-row generation aligned to the MA Tier 0 SOP."
)

with st.sidebar:
    st.header("Settings")

    if get_secret_or_env("APP_ACCESS_PASSWORD") and st.button("Log Out"):
        st.session_state["is_authenticated"] = False
        st.rerun()

    evaluator = st.selectbox(
        "Evaluator / Approver",
        ["B", "A", "R", "P"],
        index=0,
    )

    environment = st.selectbox(
        "Environment",
        ["Home/Test", "NIPR"],
        index=0,
    )

    use_vt = st.checkbox("Use VirusTotal API", value=True)

    env_vt_api_key = get_secret_or_env("VT_API_KEY")

    vt_override_key = st.text_input(
        "VirusTotal API Key (optional override)",
        value="",
        type="password",
        help=(
            "The app will use VT_API_KEY from .env or Streamlit secrets by default. "
            "Use this field only for a temporary session override."
        ),
    ).strip()

    vt_key = vt_override_key or env_vt_api_key

    if use_vt and vt_key:
        if vt_override_key:
            st.success("VirusTotal key loaded from temporary session override.")
        else:
            st.success("VirusTotal key loaded from environment/secrets.")
    elif use_vt and not vt_key:
        st.warning(
            "VirusTotal API key not loaded. Add VT_API_KEY to your .env file "
            "or paste it into this field."
        )
    else:
        st.info("VirusTotal checks are disabled.")

    st.info("Do not hard-code your real API key into the app.py file.")

    st.divider()

    template_file = st.file_uploader(
        "Optional: Upload MA Tier 0 Checklist Template",
        type=["xlsx"],
        help=(
            "Upload the official checklist workbook if you want the app to write "
            "the draft row into a copy of that template."
        ),
    )

    st.caption(f"Environment profile: {environment}")


# ------------------------------------------------------------
# App tabs
# ------------------------------------------------------------

single_tab, batch_tab, about_tab = st.tabs(
    ["Single URL Assessment", "Batch Assessment", "About SOP Mapping"]
)


# ------------------------------------------------------------
# Single URL Assessment
# ------------------------------------------------------------

with single_tab:
    st.subheader("Single URL Assessment")

    col_a, col_b = st.columns([1, 2])

    with col_a:
        site_number = st.text_input("Site #", value="")
        raw_url = st.text_input("Website URL", placeholder="https://example.com")
        manual_title = st.text_input("Site Title override", value="")
        manual_blurb = st.text_area(
            "Blurb/Description override",
            value="",
            height=100,
        )

        run_btn = st.button("Run SOP Checks", type="primary")

    if run_btn:
        if not raw_url.strip():
            st.error("Please enter a website URL first.")
        else:
            with st.spinner("Running MA Tier 0 checks..."):
                st.session_state["assessment"] = run_assessment(
                    raw_url=raw_url,
                    vt_key=vt_key,
                    use_vt=use_vt,
                )
                st.session_state["site_number"] = site_number
                st.session_state["manual_title"] = manual_title
                st.session_state["manual_blurb"] = manual_blurb

    assessment = st.session_state.get("assessment")

    if assessment:
        with col_b:
            st.markdown("### Automated Findings")

            c1, c2, c3 = st.columns(3)

            c1.metric("Domain", assessment.get("domain", "Unknown"))
            c2.metric("SSL", assessment.get("ssl", {}).get("status", "Unknown"))
            c3.metric(
                "VT Malicious",
                assessment.get("virustotal", {}).get("malicious", "N/A"),
            )

            st.write(
                "**Page Title:**",
                assessment.get("metadata", {}).get("title") or "Not found",
            )
            st.write(
                "**Meta Description:**",
                assessment.get("metadata", {}).get("description") or "Not found",
            )
            parent = assessment.get("parent_company", {})
            st.write(
                "**Parent Company / Ownership Draft:**",
                parent.get("possible_owner") or "Manual review required",
            )
            st.write(
                "**Parent Location / Jurisdiction Draft:**",
                parent.get("possible_country") or parent.get("possible_location") or "Manual review required",
            )
            st.write(
                "**Recommendation Suggestion:**",
                assessment.get("recommendation", {}).get(
                    "recommendation", "Needs Review"
                ),
            )
            st.write(
                "**Reason:**",
                assessment.get("recommendation", {}).get("reason", ""),
            )

            vt_status = assessment.get("virustotal", {}).get("status", "Unknown")
            if vt_status in ["Authentication Failed", "Error"]:
                st.error(assessment.get("virustotal", {}).get("notes", ""))
            elif vt_status in ["Manual Review Required", "Needs Review"]:
                st.warning(assessment.get("virustotal", {}).get("notes", ""))
            elif vt_status == "Skipped":
                st.info(assessment.get("virustotal", {}).get("notes", ""))
            elif use_vt and vt_status == "Report found":
                st.success("VirusTotal check completed or returned usable results.")
            elif use_vt:
                st.warning(assessment.get("virustotal", {}).get("notes", ""))

        st.markdown("---")

        tech_col, topical_col = st.columns(2)

        with tech_col:
            st.markdown("### Technical Risk")

            st.text_area(
                "Origin (FVEY?)",
                value=build_default_origin_text(assessment),
                key="origin",
                height=130,
            )

            st.text_area(
                "Malware/Spyware",
                value=assessment.get("virustotal", {}).get(
                    "notes", "Manual review required."
                ),
                key="malware",
                height=130,
            )

            st.text_area(
                "Tracking",
                value=assessment.get("tracking", {}).get("notes", ""),
                key="tracking",
                height=110,
            )

            st.text_area(
                "Vulnerability",
                value=build_default_vulnerability_text(assessment),
                key="vulnerability",
                height=130,
            )

        with topical_col:
            st.markdown("### Topical Risk / Analyst Review")

            review_links = assessment.get("review_links", {})
            content_draft = draft_content_association_from_metadata(assessment)

            st.markdown("#### Content Association")
            st.caption(
                "Purpose: Determine whether association with this website could create "
                "reputational, legal, or policy concerns."
            )

            content_link_names = [
                "Google News",
                "Wikipedia Search",
                "Cisco Talos",
                "WOT",
                "URLVoid",
            ]

            available_content_links = [
                name for name in content_link_names if review_links.get(name)
            ]

            if available_content_links:
                ca_cols = st.columns(min(3, len(available_content_links)))
                for idx, link_name in enumerate(available_content_links):
                    with ca_cols[idx % len(ca_cols)]:
                        st.link_button(link_name, review_links[link_name])
            else:
                st.warning("No review links available for Content Association.")

            st.text_area(
                "Automated Metadata Draft",
                value=content_draft,
                height=180,
                key="content_association_metadata_draft",
                disabled=True,
            )

            ca_finding = st.selectbox(
                "Content Association Finding",
                ["Low Risk", "Concern Found", "Needs Review", "Not Accessible"],
                index=2,
                key="content_association_finding",
            )

            ca_sources = st.multiselect(
                "Content Association Sources Reviewed",
                ["Metadata"] + available_content_links,
                default=["Metadata"],
                key="content_association_sources",
            )

            ca_notes = st.text_area(
                "Content Association Analyst Notes",
                value="",
                height=120,
                key="content_association_notes",
                help=(
                    "Review the automated metadata draft and validate with the linked sources. "
                    "Document any reputational, legal, or policy concerns."
                ),
                placeholder="Enter analyst notes here, if needed.",
            )

            st.session_state["content_association"] = format_guided_review_result(
                category="Content Association",
                finding=ca_finding,
                reviewed_links=ca_sources,
                notes=f"{content_draft}\n\nAnalyst Notes: {ca_notes}",
            )

            st.text_area(
                "Content Association Excel Output Preview",
                value=st.session_state["content_association"],
                height=130,
                disabled=True,
            )

            st.divider()

            st.session_state["mainstream"] = guided_review_panel(
                title="Mainstream",
                purpose=(
                    "Purpose: Determine whether the site is a commonly accessed, mainstream "
                    "public resource or a niche/obscure site."
                ),
                link_names=["SimilarWeb", "Google News", "Wikipedia Search"],
                review_links=review_links,
                finding_options=[
                    "Mainstream",
                    "Niche",
                    "Needs Review",
                    "Not Accessible",
                ],
                default_index=2,
                notes_default=(
                    "Review traffic/common-use indicators. Document whether the site appears "
                    "mainstream, niche, or insufficiently verifiable."
                ),
                session_key_prefix="mainstream",
            )

            st.divider()

            st.session_state["adversarial"] = guided_review_panel(
                title="Adversarial",
                purpose=(
                    "Purpose: Screen for niche, sensitive, adversarial, extremist, illicit, "
                    "hostile, or otherwise high-risk content associations."
                ),
                link_names=[
                    "Google News",
                    "Wikipedia Search",
                    "Cisco Talos",
                    "WOT",
                    "ScamAdviser",
                ],
                review_links=review_links,
                finding_options=[
                    "No Concern",
                    "Concern Found",
                    "Needs Review",
                    "Not Accessible",
                ],
                default_index=2,
                notes_default=(
                    "Review whether the site has sensitive, adversarial, extremist, illicit, "
                    "or hostile associations. Document any concerns."
                ),
                session_key_prefix="adversarial",
            )

            st.divider()

            st.session_state["reputation"] = guided_review_panel(
                title="Reputation Check",
                purpose=(
                    "Purpose: Summarize trust, safety, and content-category results from "
                    "available reputation tools."
                ),
                link_names=[
                    "VirusTotal",
                    "Cisco Talos",
                    "WOT",
                    "ScamAdviser",
                    "URLVoid",
                ],
                review_links=review_links,
                finding_options=[
                    "Trusted",
                    "Mixed",
                    "Poor",
                    "Needs Review",
                    "Not Accessible",
                ],
                default_index=3,
                notes_default=(
                    "Review available reputation tools and summarize trust/category results. "
                    "If tools conflict, mark Mixed or Needs Review."
                ),
                session_key_prefix="reputation",
            )

        st.markdown("---")
        st.markdown("### Finalize Draft Row")

        recommendation_options = [
            "Suitable",
            "Unsuitable",
            "Exception–Escalate",
            "Needs Review",
        ]

        topical_recommendation_override = get_topical_recommendation_override()

        suggested_rec = topical_recommendation_override or assessment.get(
            "recommendation", {}
        ).get("recommendation", "Needs Review")

        if suggested_rec not in recommendation_options:
            suggested_rec = "Needs Review"

        final_recommendation = st.selectbox(
            "Final Recommendation",
            recommendation_options,
            index=recommendation_options.index(suggested_rec),
        )

        comments = st.text_area(
            "Comments",
            value=assessment.get("recommendation", {}).get("reason", ""),
            height=100,
        )

        if topical_recommendation_override:
            st.info(
                f"Recommendation adjusted by analyst topical review selections: "
                f"{topical_recommendation_override}"
            )

        if st.button("Create Draft Excel File"):
            manual = build_manual_row_dict(
                evaluator=evaluator,
                site_number=st.session_state.get("site_number", ""),
                manual_title=st.session_state.get("manual_title", ""),
                manual_blurb=st.session_state.get("manual_blurb", ""),
                final_recommendation=final_recommendation,
                comments=comments,
            )

            row = assessment_to_row(assessment, manual)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            if template_file is not None:
                template_path = OUTPUT_DIR / f"uploaded_template_{timestamp}.xlsx"

                with open(template_path, "wb") as f:
                    f.write(template_file.getbuffer())

                output_path = (
                    OUTPUT_DIR
                    / f"MA_Tier0_Checklist_DRAFT_FILLED_{timestamp}.xlsx"
                )

                append_rows_to_template(
                    rows=[row],
                    template_path=str(template_path),
                    output_path=str(output_path),
                )

                st.success(
                    "Draft row written into a copy of the uploaded checklist template."
                )

                with open(output_path, "rb") as f:
                    st.download_button(
                        "Download Filled Checklist Copy",
                        f,
                        file_name=output_path.name,
                    )

            else:
                output_path = OUTPUT_DIR / f"MA_Tier0_Draft_Results_{timestamp}.xlsx"

                write_draft_excel([row], str(output_path))

                st.success("Standalone draft Excel file created.")

                with open(output_path, "rb") as f:
                    st.download_button(
                        "Download Draft Results Excel",
                        f,
                        file_name=output_path.name,
                    )

            st.dataframe(
                pd.DataFrame([row], columns=COLUMNS),
                use_container_width=True,
            )


# ------------------------------------------------------------
# Batch Assessment
# ------------------------------------------------------------

with batch_tab:
    st.subheader("Batch Assessment Review Queue")

    st.info(
        "Batch mode works as a review queue. First run automated checks, "
        "then review each URL individually before exporting to Excel."
    )

    uploaded = st.file_uploader(
        "Upload CSV or Excel with a URL column",
        type=["csv", "xlsx"],
        key="batch_upload_file",
    )

    url_column = st.text_input(
        "URL column name",
        value="URL",
        key="batch_url_column",
    )

    batch_limit = st.number_input(
        "Maximum URLs to process",
        min_value=1,
        max_value=100,
        value=5,
        key="batch_limit",
    )

    col_run, col_reset = st.columns(2)

    with col_run:
        run_batch_btn = st.button("Run Batch Automated Checks", type="primary")

    with col_reset:
        reset_batch_btn = st.button("Reset Batch Review")

    if reset_batch_btn:
        for key in list(st.session_state.keys()):
            if key.startswith("batch_"):
                del st.session_state[key]
        st.success("Batch review state cleared.")
        st.rerun()

    if run_batch_btn:
        if uploaded is None:
            st.error("Please upload a CSV or Excel file first.")
        else:
            try:
                if uploaded.name.lower().endswith(".csv"):
                    df = pd.read_csv(uploaded)
                else:
                    df = pd.read_excel(uploaded)

                if url_column not in df.columns:
                    st.error(
                        f"Column '{url_column}' not found. "
                        f"Available columns: {', '.join(df.columns)}"
                    )
                else:
                    batch_df = df[df[url_column].notna()].copy().head(batch_limit)

                    if batch_df.empty:
                        st.error("No URLs found in the selected column.")
                    else:
                        st.session_state["batch_assessments"] = []
                        st.session_state["batch_review_index"] = 0
                        st.session_state["batch_reviewed_rows"] = {}
                        st.session_state["batch_source_filename"] = uploaded.name

                        progress = st.progress(0)
                        status_box = st.empty()

                        for i, (_, input_row) in enumerate(batch_df.iterrows(), start=1):
                            raw_url_value = str(input_row[url_column]).strip()
                            status_box.write(
                                f"Checking {i} of {len(batch_df)}: {raw_url_value}"
                            )

                            assessment = run_assessment(
                                raw_url=raw_url_value,
                                vt_key=vt_key,
                                use_vt=use_vt,
                            )

                            site_number_value = ""
                            if "Site #" in df.columns:
                                site_number_value = str(input_row.get("Site #", "") or "")
                            elif "Site Number" in df.columns:
                                site_number_value = str(input_row.get("Site Number", "") or "")

                            st.session_state["batch_assessments"].append(
                                {
                                    "assessment": assessment,
                                    "site_number": site_number_value,
                                    "manual_title": "",
                                    "manual_blurb": "",
                                    "raw_url": raw_url_value,
                                }
                            )

                            progress.progress(i / len(batch_df))

                        status_box.success(
                            f"Automated checks complete for {len(batch_df)} URLs. "
                            "Begin analyst review below."
                        )

            except Exception as exc:
                st.error(f"Batch automated checks failed: {exc}")

    batch_assessments = st.session_state.get("batch_assessments", [])
    batch_reviewed_rows = st.session_state.get("batch_reviewed_rows", {})

    if batch_assessments:
        total = len(batch_assessments)

        if "batch_review_index" not in st.session_state:
            st.session_state["batch_review_index"] = 0

        current_index = st.session_state["batch_review_index"]
        current_index = max(0, min(current_index, total - 1))
        st.session_state["batch_review_index"] = current_index

        current_item = batch_assessments[current_index]
        assessment = current_item["assessment"]
        key_prefix = f"batch_{current_index}"

        st.markdown("---")
        st.markdown(
            f"### Reviewing URL {current_index + 1} of {total}: "
            f"`{assessment.get('url', '')}`"
        )

        reviewed_count = len(batch_reviewed_rows)
        st.progress(reviewed_count / total)
        st.caption(f"Reviewed {reviewed_count} of {total} URLs.")

        nav_col1, nav_col2, nav_col3 = st.columns(3)

        with nav_col1:
            if st.button("Previous URL", disabled=current_index == 0, key=f"{key_prefix}_prev"):
                st.session_state["batch_review_index"] = current_index - 1
                st.rerun()

        with nav_col2:
            selected_display = st.selectbox(
                "Jump to URL",
                options=list(range(total)),
                index=current_index,
                format_func=lambda i: (
                    f"{i + 1}. "
                    f"{'✅ ' if i in batch_reviewed_rows else '⬜ '}"
                    f"{batch_assessments[i]['assessment'].get('url', '')}"
                ),
                key=f"batch_jump_select_{current_index}",
            )

            if selected_display != current_index:
                st.session_state["batch_review_index"] = selected_display
                st.rerun()

        with nav_col3:
            if st.button("Next URL", disabled=current_index >= total - 1, key=f"{key_prefix}_next"):
                st.session_state["batch_review_index"] = current_index + 1
                st.rerun()

        st.markdown("### Automated Findings")

        af1, af2, af3 = st.columns(3)

        af1.metric("Domain", assessment.get("domain", "Unknown"))
        af2.metric("SSL", assessment.get("ssl", {}).get("status", "Unknown"))
        af3.metric(
            "VT Malicious",
            assessment.get("virustotal", {}).get("malicious", "N/A"),
        )

        st.write(
            "**Page Title:**",
            assessment.get("metadata", {}).get("title") or "Not found",
        )
        st.write(
            "**Meta Description:**",
            assessment.get("metadata", {}).get("description") or "Not found",
        )

        parent = assessment.get("parent_company", {})
        st.write(
            "**Parent Company / Ownership Draft:**",
            parent.get("possible_owner") or "Manual review required",
        )
        st.write(
            "**Parent Location Draft:**",
            parent.get("possible_location") or "Manual review required",
        )

        st.write(
            "**Automated Recommendation Suggestion:**",
            assessment.get("recommendation", {}).get("recommendation", "Needs Review"),
        )
        st.write(
            "**Reason:**",
            assessment.get("recommendation", {}).get("reason", ""),
        )

        vt_status = assessment.get("virustotal", {}).get("status", "Unknown")
        if vt_status in ["Authentication Failed", "Error"]:
            st.error(assessment.get("virustotal", {}).get("notes", ""))
        elif vt_status in ["Manual Review Required", "Needs Review"]:
            st.warning(assessment.get("virustotal", {}).get("notes", ""))
        elif vt_status == "Skipped":
            st.info(assessment.get("virustotal", {}).get("notes", ""))
        elif use_vt and vt_status == "Report found":
            st.success("VirusTotal check completed or returned usable results.")
        elif use_vt:
            st.warning(assessment.get("virustotal", {}).get("notes", ""))

        st.markdown("---")
        st.markdown("### Site Information")

        site_col1, site_col2 = st.columns(2)

        with site_col1:
            site_number_value = st.text_input(
                "Site #",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Site #",
                    current_item.get("site_number", ""),
                ),
                key=f"{key_prefix}_site_number",
            )

            manual_title_value = st.text_input(
                "Site Title override",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Site Title",
                    current_item.get("manual_title", "")
                    or assessment.get("metadata", {}).get("title", ""),
                ),
                key=f"{key_prefix}_manual_title",
            )

        with site_col2:
            manual_blurb_value = st.text_area(
                "Blurb/Description override",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Blurb/Description",
                    current_item.get("manual_blurb", "")
                    or assessment.get("metadata", {}).get("description", ""),
                ),
                height=100,
                key=f"{key_prefix}_manual_blurb",
            )

        tech_col, topical_col = st.columns(2)

        with tech_col:
            st.markdown("### Technical Risk")

            st.text_area(
                "Origin (FVEY?)",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Origin (FVEY?)",
                    build_default_origin_text(assessment),
                ),
                key=f"{key_prefix}_origin",
                height=130,
            )

            st.text_area(
                "Malware/Spyware",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Malware/Spyware",
                    assessment.get("virustotal", {}).get(
                        "notes", "Manual review required."
                    ),
                ),
                key=f"{key_prefix}_malware",
                height=130,
            )

            st.text_area(
                "Tracking",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Tracking",
                    assessment.get("tracking", {}).get("notes", ""),
                ),
                key=f"{key_prefix}_tracking",
                height=110,
            )

            st.text_area(
                "Vulnerability",
                value=get_batch_saved_value(
                    batch_reviewed_rows,
                    current_index,
                    "Vulnerability",
                    build_default_vulnerability_text(assessment),
                ),
                key=f"{key_prefix}_vulnerability",
                height=130,
            )

        with topical_col:
            st.markdown("### Topical Risk / Analyst Review")

            review_links = assessment.get("review_links", {})
            content_draft = draft_content_association_from_metadata(assessment)

            st.markdown("#### Content Association")
            st.caption(
                "Purpose: Determine whether association with this website could create "
                "reputational, legal, or policy concerns."
            )

            content_link_names = [
                "Google News",
                "Wikipedia Search",
                "Cisco Talos",
                "WOT",
                "URLVoid",
            ]

            available_content_links = [
                name for name in content_link_names if review_links.get(name)
            ]

            if available_content_links:
                ca_cols = st.columns(min(3, len(available_content_links)))
                for idx, link_name in enumerate(available_content_links):
                    with ca_cols[idx % len(ca_cols)]:
                        st.link_button(link_name, review_links[link_name])
            else:
                st.warning("No review links available for Content Association.")

            st.text_area(
                "Automated Metadata Draft",
                value=content_draft,
                height=180,
                key=f"{key_prefix}_content_association_metadata_draft",
                disabled=True,
            )

            saved_content = get_batch_saved_value(
                batch_reviewed_rows,
                current_index,
                "Content Association",
                "",
            )

            default_ca_index = 2
            if "Content Association: Low Risk" in saved_content:
                default_ca_index = 0
            elif "Content Association: Concern Found" in saved_content:
                default_ca_index = 1
            elif "Content Association: Not Accessible" in saved_content:
                default_ca_index = 3

            ca_finding = st.selectbox(
                "Content Association Finding",
                ["Low Risk", "Concern Found", "Needs Review", "Not Accessible"],
                index=default_ca_index,
                key=f"{key_prefix}_content_association_finding",
            )

            ca_sources = st.multiselect(
                "Content Association Sources Reviewed",
                ["Metadata"] + available_content_links,
                default=["Metadata"],
                key=f"{key_prefix}_content_association_sources",
            )

            ca_notes = st.text_area(
                "Content Association Analyst Notes",
                value="",
                height=120,
                key=f"{key_prefix}_content_association_notes",
                help=(
                    "Review the automated metadata draft and validate with the linked sources. "
                    "Document any reputational, legal, or policy concerns."
                ),
                placeholder="Enter analyst notes here, if needed.",
            )

            st.session_state[f"{key_prefix}_content_association"] = format_guided_review_result(
                category="Content Association",
                finding=ca_finding,
                reviewed_links=ca_sources,
                notes=f"{content_draft}\n\nAnalyst Notes: {ca_notes}",
            )

            st.text_area(
                "Content Association Excel Output Preview",
                value=st.session_state[f"{key_prefix}_content_association"],
                height=130,
                key=f"{key_prefix}_content_association_preview",
                disabled=True,
            )

            st.divider()

            st.session_state[f"{key_prefix}_mainstream"] = guided_review_panel(
                title="Mainstream",
                purpose=(
                    "Purpose: Determine whether the site is a commonly accessed, mainstream "
                    "public resource or a niche/obscure site."
                ),
                link_names=["SimilarWeb", "Google News", "Wikipedia Search"],
                review_links=review_links,
                finding_options=[
                    "Mainstream",
                    "Niche",
                    "Needs Review",
                    "Not Accessible",
                ],
                default_index=2,
                notes_default=(
                    "Review traffic/common-use indicators. Document whether the site appears "
                    "mainstream, niche, or insufficiently verifiable."
                ),
                session_key_prefix=f"{key_prefix}_mainstream",
            )

            st.divider()

            st.session_state[f"{key_prefix}_adversarial"] = guided_review_panel(
                title="Adversarial",
                purpose=(
                    "Purpose: Screen for niche, sensitive, adversarial, extremist, illicit, "
                    "hostile, or otherwise high-risk content associations."
                ),
                link_names=[
                    "Google News",
                    "Wikipedia Search",
                    "Cisco Talos",
                    "WOT",
                    "ScamAdviser",
                ],
                review_links=review_links,
                finding_options=[
                    "No Concern",
                    "Concern Found",
                    "Needs Review",
                    "Not Accessible",
                ],
                default_index=2,
                notes_default=(
                    "Review whether the site has sensitive, adversarial, extremist, illicit, "
                    "or hostile associations. Document any concerns."
                ),
                session_key_prefix=f"{key_prefix}_adversarial",
            )

            st.divider()

            st.session_state[f"{key_prefix}_reputation"] = guided_review_panel(
                title="Reputation Check",
                purpose=(
                    "Purpose: Summarize trust, safety, and content-category results from "
                    "available reputation tools."
                ),
                link_names=[
                    "VirusTotal",
                    "Cisco Talos",
                    "WOT",
                    "ScamAdviser",
                    "URLVoid",
                ],
                review_links=review_links,
                finding_options=[
                    "Trusted",
                    "Mixed",
                    "Poor",
                    "Needs Review",
                    "Not Accessible",
                ],
                default_index=3,
                notes_default=(
                    "Review available reputation tools and summarize trust/category results. "
                    "If tools conflict, mark Mixed or Needs Review."
                ),
                session_key_prefix=f"{key_prefix}_reputation",
            )

        st.markdown("---")
        st.markdown("### Finalize This URL")

        recommendation_options = [
            "Suitable",
            "Unsuitable",
            "Exception–Escalate",
            "Needs Review",
        ]

        batch_topical_override = get_batch_topical_recommendation_override(key_prefix)

        suggested_rec = batch_topical_override or assessment.get(
            "recommendation", {}
        ).get("recommendation", "Needs Review")

        saved_recommendation = get_batch_saved_value(
            batch_reviewed_rows,
            current_index,
            "Final Recommendation",
            "",
        )

        if saved_recommendation in recommendation_options:
            suggested_rec = saved_recommendation

        if suggested_rec not in recommendation_options:
            suggested_rec = "Needs Review"

        final_recommendation = st.selectbox(
            "Final Recommendation",
            recommendation_options,
            index=recommendation_options.index(suggested_rec),
            key=f"{key_prefix}_final_recommendation",
        )

        comments = st.text_area(
            "Comments",
            value=get_batch_saved_value(
                batch_reviewed_rows,
                current_index,
                "Comments",
                assessment.get("recommendation", {}).get("reason", ""),
            ),
            height=100,
            key=f"{key_prefix}_comments",
        )

        if batch_topical_override:
            st.info(
                f"Recommendation adjusted by analyst topical review selections: "
                f"{batch_topical_override}"
            )

        save_col1, save_col2 = st.columns(2)

        with save_col1:
            save_review_btn = st.button(
                "Save Review for This URL",
                type="primary",
                key=f"{key_prefix}_save_review",
            )

        with save_col2:
            save_next_btn = st.button(
                "Save Review and Go to Next URL",
                key=f"{key_prefix}_save_next",
            )

        if save_review_btn or save_next_btn:
            manual = build_batch_review_row(
                evaluator=evaluator,
                site_number=site_number_value,
                manual_title=manual_title_value,
                manual_blurb=manual_blurb_value,
                final_recommendation=final_recommendation,
                comments=comments,
                key_prefix=key_prefix,
            )

            row = assessment_to_row(assessment, manual)

            st.session_state["batch_reviewed_rows"][current_index] = row

            st.success(
                f"Review saved for URL {current_index + 1} of {total}: "
                f"{assessment.get('url', '')}"
            )

            if save_next_btn and current_index < total - 1:
                st.session_state["batch_review_index"] = current_index + 1
                st.rerun()

        st.markdown("---")
        st.markdown("### Completed URL Reviews")

        reviewed_rows_dict = st.session_state.get("batch_reviewed_rows", {})
        reviewed_rows = [
            reviewed_rows_dict[i]
            for i in sorted(reviewed_rows_dict.keys())
        ]

        if reviewed_rows:
            completed_summary = []

            for i in sorted(reviewed_rows_dict.keys()):
                row = reviewed_rows_dict[i]
                completed_summary.append(
                    {
                        "#": i + 1,
                        "Site #": row.get("Site #", ""),
                        "URL": row.get("URL", ""),
                        "Final Recommendation": row.get("Final Recommendation", ""),
                        "Reviewed": "Yes",
                    }
                )

            st.dataframe(
                pd.DataFrame(completed_summary),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No URLs have been finalized yet.")

        st.markdown("---")
        st.markdown("### Export Reviewed Batch")

        st.write(f"Reviewed rows ready to export: **{len(reviewed_rows)} of {total}**")

        if len(reviewed_rows) < total:
            st.warning(
                "Not all URLs have been reviewed. You can export reviewed rows only, "
                "or continue reviewing the remaining URLs."
            )
        else:
            st.success("All URLs have been reviewed and are ready to export.")

        export_col1, export_col2 = st.columns(2)

        with export_col1:
            export_reviewed_btn = st.button(
                "Export Reviewed Batch to Excel",
                disabled=len(reviewed_rows) == 0,
            )

        with export_col2:
            st.caption(
                "Export uses the uploaded checklist template if one was provided "
                "in the sidebar. Otherwise, it creates a standalone draft workbook."
            )

        if export_reviewed_btn:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            if template_file is not None:
                template_path = OUTPUT_DIR / f"uploaded_batch_template_{timestamp}.xlsx"

                with open(template_path, "wb") as f:
                    f.write(template_file.getbuffer())

                output_path = (
                    OUTPUT_DIR
                    / f"MA_Tier0_Checklist_BATCH_REVIEWED_{timestamp}.xlsx"
                )

                append_rows_to_template(
                    rows=reviewed_rows,
                    template_path=str(template_path),
                    output_path=str(output_path),
                )

                st.success(
                    "Reviewed batch rows written into a copy of the uploaded checklist template."
                )

                with open(output_path, "rb") as f:
                    st.download_button(
                        "Download Reviewed Batch Checklist Copy",
                        f,
                        file_name=output_path.name,
                    )

            else:
                output_path = (
                    OUTPUT_DIR
                    / f"MA_Tier0_Batch_REVIEWED_Results_{timestamp}.xlsx"
                )

                write_draft_excel(reviewed_rows, str(output_path))

                st.success("Standalone reviewed batch Excel file created.")

                with open(output_path, "rb") as f:
                    st.download_button(
                        "Download Reviewed Batch Results Excel",
                        f,
                        file_name=output_path.name,
                    )

            st.dataframe(
                pd.DataFrame(reviewed_rows, columns=COLUMNS),
                use_container_width=True,
            )

# ------------------------------------------------------------
# About / SOP Mapping
# ------------------------------------------------------------

with about_tab:
    st.subheader("SOP Mapping")

    st.write(
        "This prototype maps automated and manual checks to the MA Tier 0 SOP columns."
    )

    st.table(
        pd.DataFrame(
            [
                {
                    "SOP Area": "Origin",
                    "Automation": "RDAP lookup, registrar/country where available",
                    "Status": "Automated + analyst review",
                },
                {
                    "SOP Area": "Malware/Spyware",
                    "Automation": "VirusTotal API if key provided",
                    "Status": "Automated",
                },
                {
                    "SOP Area": "Tracking",
                    "Automation": "robots.txt + common tracker script detection",
                    "Status": "Automated + analyst review",
                },
                {
                    "SOP Area": "Vulnerability",
                    "Automation": "DNS + SSL validity + robots notes",
                    "Status": "Automated + analyst review",
                },
                {
                    "SOP Area": "Content Association",
                    "Automation": "Page title/meta description draft + manual review links",
                    "Status": "Automated draft + analyst decision",
                },
                {
                    "SOP Area": "Mainstream",
                    "Automation": "Manual SimilarWeb/news/Wikipedia review",
                    "Status": "Guided analyst decision",
                },
                {
                    "SOP Area": "Adversarial",
                    "Automation": "Manual news/Wikipedia/reputation review",
                    "Status": "Guided analyst decision",
                },
                {
                    "SOP Area": "Reputation Check",
                    "Automation": "Manual links; future API optional",
                    "Status": "Guided analyst decision",
                },
                {
                    "SOP Area": "Excel Export",
                    "Automation": "Standalone draft workbook or filled copy of uploaded checklist template",
                    "Status": "Automated",
                },
                {
                    "SOP Area": "Batch Mode",
                    "Automation": "Automated checks followed by URL-by-URL analyst review queue",
                    "Status": "Automated + analyst decision before export",
                },
            ]
        )
    )
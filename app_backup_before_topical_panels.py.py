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
from modules.virustotal_check import run_virustotal_url_check
from modules.recommendation_engine import suggest_recommendation
from modules.excel_writer import assessment_to_row, write_draft_excel, COLUMNS


# ------------------------------------------------------------
# Basic setup
# ------------------------------------------------------------

APP_DIR = Path(__file__).parent
OUTPUT_DIR = APP_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

# Load local .env file from the same folder as app.py
load_dotenv(APP_DIR / ".env")

st.set_page_config(
    page_title="MA Tier 0 Risk Assessment Assistant",
    layout="wide",
)


# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

def get_secret_or_env(name: str) -> str:
    """
    Get a secret from Streamlit secrets first, then fallback to .env/environment.
    This lets you use either:
      1. .env file locally
      2. .streamlit/secrets.toml later
      3. operating system environment variable
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
    Wrapper around the VirusTotal check so raw API errors do not dump into
    the Malware/Spyware field.
    """
    if not use_vt:
        return {
            "status": "Skipped",
            "malicious": "N/A",
            "suspicious": "N/A",
            "harmless": "N/A",
            "notes": "VirusTotal check skipped by user.",
        }

    if not vt_key:
        return {
            "status": "Manual Review Required",
            "malicious": "N/A",
            "suspicious": "N/A",
            "harmless": "N/A",
            "notes": (
                "VirusTotal API key was not loaded. Add VT_API_KEY to the .env "
                "file or paste the key into the sidebar field. Manual VirusTotal "
                "review required."
            ),
        }

    try:
        result = run_virustotal_url_check(url, vt_key)

        # Catch common API auth error returned as JSON/dict
        result_text = str(result)
        if "WrongCredentialsError" in result_text or "Wrong API key" in result_text:
            return {
                "status": "Authentication Failed",
                "malicious": "N/A",
                "suspicious": "N/A",
                "harmless": "N/A",
                "notes": (
                    "VirusTotal API authentication failed. Check that VT_API_KEY "
                    "in your .env file is correct, has no quotes/spaces, and is a "
                    "valid VirusTotal API key. Manual VirusTotal review required."
                ),
            }

        if not isinstance(result, dict):
            return {
                "status": "Needs Review",
                "malicious": "N/A",
                "suspicious": "N/A",
                "harmless": "N/A",
                "notes": f"VirusTotal returned an unexpected result: {result}",
            }

        # Ensure notes exist
        if not result.get("notes"):
            result["notes"] = "VirusTotal check completed."

        return result

    except Exception as exc:
        return {
            "status": "Error",
            "malicious": "N/A",
            "suspicious": "N/A",
            "harmless": "N/A",
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
        "virustotal": safe_virustotal_check(url, vt_key, use_vt),
    }

    assessment["recommendation"] = suggest_recommendation(assessment)
    assessment["review_links"] = build_review_links(url, domain)

    return assessment


def build_default_origin_text(assessment: dict) -> str:
    rdap = assessment.get("rdap", {})
    return (
        f"RDAP status: {rdap.get('status', 'Unknown')}; "
        f"Registrar: {rdap.get('registrar', '')}; "
        f"Country: {rdap.get('country', '')}; "
        f"Source: {rdap.get('source', '')}; "
        f"Notes: {rdap.get('notes', '')}"
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


def build_manual_row_dict(
    assessment: dict,
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


# ------------------------------------------------------------
# Sidebar
# ------------------------------------------------------------

st.title("MA Tier 0 Risk Assessment Assistant")
st.caption(
    "Prototype: single URL and batch draft-row generation aligned to the MA Tier 0 SOP."
)

with st.sidebar:
    st.header("Settings")

    evaluator = st.selectbox(
        "Evaluator / Approver",
        ["BH", "AP", "RL", "PC"],
        index=0,
    )

    environment = st.selectbox(
        "Environment",
        ["Home/Test", "NIPR"],
        index=0,
    )

    use_vt = st.checkbox("Use VirusTotal API", value=True)

    env_vt_api_key = get_secret_or_env("VT_API_KEY")

    vt_key = st.text_input(
        "VirusTotal API Key",
        value=env_vt_api_key,
        type="password",
        help=(
            "Loaded from .env if VT_API_KEY is set. You may also paste a key "
            "here for this session. Do not hard-code your real API key into app.py."
        ),
    ).strip()

    if use_vt and vt_key:
        st.success(f"VirusTotal API key loaded. Length: {len(vt_key)} characters.")
    elif use_vt and not vt_key:
        st.warning(
            "VirusTotal API key not loaded. Add VT_API_KEY to your .env file "
            "or paste it into this field."
        )
    else:
        st.info("VirusTotal checks are disabled.")

    st.info("Do not hard-code your real API key into the app.py file.")

    st.divider()
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
            elif vt_status == "Manual Review Required":
                st.warning(assessment.get("virustotal", {}).get("notes", ""))
            elif use_vt:
                st.success("VirusTotal check completed or returned usable results.")

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

            st.text_area(
                "Content Association",
                value="Manual analyst review required.",
                key="content_association",
                height=100,
            )

            st.text_area(
                "Mainstream",
                value="Manual analyst review required.",
                key="mainstream",
                height=100,
            )

            st.text_area(
                "Adversarial",
                value="Manual analyst review required.",
                key="adversarial",
                height=100,
            )

            st.text_area(
                "Reputation Check",
                value="Manual reputation review required.",
                key="reputation",
                height=100,
            )

        st.markdown("### Manual Review Links")

        link_cols = st.columns(3)
        for idx, (name, link) in enumerate(
            assessment.get("review_links", {}).items()
        ):
            with link_cols[idx % 3]:
                st.link_button(name, link)

        st.markdown("---")
        st.markdown("### Finalize Draft Row")

        recommendation_options = [
            "Suitable",
            "Unsuitable",
            "Exception–Escalate",
            "Needs Review",
        ]

        suggested_rec = assessment.get("recommendation", {}).get(
            "recommendation", "Needs Review"
        )

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

        if st.button("Create Draft Excel File"):
            manual = build_manual_row_dict(
                assessment=assessment,
                evaluator=evaluator,
                site_number=st.session_state.get("site_number", ""),
                manual_title=st.session_state.get("manual_title", ""),
                manual_blurb=st.session_state.get("manual_blurb", ""),
                final_recommendation=final_recommendation,
                comments=comments,
            )

            row = assessment_to_row(assessment, manual)

            output_path = (
                OUTPUT_DIR
                / f"MA_Tier0_Draft_Results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            )

            write_draft_excel([row], str(output_path))

            st.success("Draft Excel file created.")

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
    st.subheader("Batch Assessment")

    st.warning(
        "Prototype batch mode processes multiple URLs using the same core checks. "
        "Keep batches small while testing to avoid rate limits or blocked sites."
    )

    uploaded = st.file_uploader(
        "Upload CSV or Excel with a URL column",
        type=["csv", "xlsx"],
    )

    url_column = st.text_input("URL column name", value="URL")

    batch_limit = st.number_input(
        "Maximum URLs to process",
        min_value=1,
        max_value=50,
        value=5,
    )

    if uploaded is not None and st.button("Run Batch Checks"):
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
                rows = []
                progress = st.progress(0)

                urls = (
                    df[url_column]
                    .dropna()
                    .astype(str)
                    .head(batch_limit)
                    .tolist()
                )

                if not urls:
                    st.error("No URLs found in the selected column.")
                else:
                    for i, u in enumerate(urls, start=1):
                        assessment = run_assessment(
                            raw_url=u,
                            vt_key=vt_key,
                            use_vt=use_vt,
                        )

                        manual = {
                            "site_number": (
                                df.iloc[i - 1].get("Site #", "")
                                if "Site #" in df.columns
                                else ""
                            ),
                            "evaluator": evaluator,
                            "origin": build_default_origin_text(assessment),
                            "malware": assessment.get("virustotal", {}).get(
                                "notes", "Manual review required."
                            ),
                            "tracking": assessment.get("tracking", {}).get(
                                "notes", ""
                            ),
                            "vulnerability": build_default_vulnerability_text(
                                assessment
                            ),
                            "content_association": "Manual analyst review required.",
                            "mainstream": "Manual analyst review required.",
                            "adversarial": "Manual analyst review required.",
                            "reputation": "Manual reputation review required.",
                            "final_recommendation": assessment.get(
                                "recommendation", {}
                            ).get("recommendation", "Needs Review"),
                            "comments": assessment.get("recommendation", {}).get(
                                "reason", ""
                            ),
                            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        }

                        rows.append(assessment_to_row(assessment, manual))
                        progress.progress(i / len(urls))

                    output_path = (
                        OUTPUT_DIR
                        / f"MA_Tier0_Batch_Draft_Results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                    )

                    write_draft_excel(rows, str(output_path))

                    st.dataframe(
                        pd.DataFrame(rows, columns=COLUMNS),
                        use_container_width=True,
                    )

                    with open(output_path, "rb") as f:
                        st.download_button(
                            "Download Batch Draft Results Excel",
                            f,
                            file_name=output_path.name,
                        )

        except Exception as exc:
            st.error(f"Batch processing failed: {exc}")


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
                    "Automation": "Manual review links",
                    "Status": "Manual",
                },
                {
                    "SOP Area": "Mainstream",
                    "Automation": "Manual SimilarWeb/news review",
                    "Status": "Manual",
                },
                {
                    "SOP Area": "Adversarial",
                    "Automation": "Manual news/Wikipedia/reputation review",
                    "Status": "Manual",
                },
                {
                    "SOP Area": "Reputation Check",
                    "Automation": "Manual links; future API optional",
                    "Status": "Manual",
                },
            ]
        )
    )
"""Streamlit dashboard for the AI Smart Firewall.

Run from the project root:  streamlit run app.py
"""
import json
import os
import sys

import pandas as pd
import streamlit as st

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
from data_loader import load, split_xy  # noqa: E402
from firewall import SmartFirewall  # noqa: E402

RESULTS = os.path.join(ROOT, "results")
st.set_page_config(page_title="AI Smart Firewall", layout="wide")


@st.cache_data
def test_data():
    return load(os.path.join(ROOT, "data", "KDDTest+.txt"))


metrics = json.load(open(os.path.join(RESULTS, "metrics.json")))
rf = metrics["Random Forest"]["test"]

st.title("AI-Based Smart Firewall")
st.caption("Computer Networks Mini Project · Karnavati University · Random Forest model trained on NSL-KDD")

tab_live, tab_model, tab_rules = st.tabs(["Live inspection", "Model performance", "Generated rules"])

with tab_live:
    c1, c2, c3 = st.columns(3)
    n = c1.slider("Flows to replay", 50, 2000, 500, step=50)
    block_t = c2.slider("Block threshold", 0.5, 0.95, 0.7, step=0.05)
    alert_t = c3.slider("Alert threshold", 0.1, 0.5, 0.3, step=0.05)

    sample = test_data().sample(n, random_state=7).reset_index(drop=True)
    attack_id = {lab: k for k, lab in enumerate(sorted(sample["label"].unique()))}
    ips = [f"10.0.{i % 8}.{i % 250 + 1}" if lab == "normal" else f"203.0.{attack_id[lab]}.{i % 3 + 10}"
           for i, lab in enumerate(sample["label"])]
    X, _ = split_xy(sample)
    fw = SmartFirewall(os.path.join(ROOT, "models", "firewall_model.joblib"), block_t, alert_t)
    log = fw.inspect_batch(X, ips)
    log["actual"] = sample["family"]

    counts = log["decision"].value_counts()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Allowed", int(counts.get("ALLOW", 0)))
    m2.metric("Alerts for review", int(counts.get("ALERT", 0)))
    m3.metric("Blocked", int(counts.get("BLOCK", 0)))
    m4.metric("IPs banned", len(fw.banned))

    colours = {"BLOCK": "background-color: #f8d7da", "ALERT": "background-color: #fff3cd",
               "ALLOW": "background-color: #e6f2ea"}
    st.dataframe(log.style.map(lambda v: colours.get(v, ""), subset=["decision"]).format({"attack_score": "{:.2f}"}),
                 use_container_width=True, height=420)

with tab_model:
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Accuracy", f"{rf['accuracy']:.1%}")
    m2.metric("Precision", f"{rf['precision']:.1%}")
    m3.metric("Recall", f"{rf['recall']:.1%}")
    m4.metric("F1-score", f"{rf['f1']:.1%}")
    c1, c2 = st.columns(2)
    c1.image(os.path.join(RESULTS, "confusion_matrix.png"))
    c2.image(os.path.join(RESULTS, "model_comparison.png"))
    c1.image(os.path.join(RESULTS, "detection_by_family.png"))
    c2.image(os.path.join(RESULTS, "feature_importance.png"))

with tab_rules:
    st.write("Rules produced when the full test set was replayed (`python src/simulate.py`):")
    st.code(open(os.path.join(RESULTS, "iptables_rules.txt")).read(), language="bash")
    st.download_button("Download firewall log (CSV)", open(os.path.join(RESULTS, "firewall_log.csv"), "rb"),
                       "firewall_log.csv")

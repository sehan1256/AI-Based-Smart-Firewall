# AI-Based Smart Firewall

**Computer Networks – Mini Project**
Unitedworld Institute of Technology (UIT), Karnavati University
Faculty: Ms. Pragya Vats

| Team member | Enrollment No. |
|---|---|
| Tanmay Garg | KU2407U1118 |
| Sehan Wadhwaniya | KU2407U196 |
| Nisarg Shah | KU2407U740 |
| Khush Dadhaniya | KU2407U837 |

---

## What it does

A traditional firewall only follows fixed rules, so it misses attacks that no rule describes. This project adds a machine-learning layer that looks at the **behaviour of each network connection** (protocol, service, bytes sent, error rates, how many connections were made to the same host, and so on) and decides whether to let it through.

Every connection passes through three layers:

| Layer | What it checks | Action |
|---|---|---|
| 1. Static rules | Land attack (same source and destination), malformed IP fragments, Telnet | BLOCK |
| 2. AI model (Random Forest) | Attack probability from 41 traffic features | ≥ 0.70 → **BLOCK**, 0.30–0.70 → **ALERT** (allowed but flagged for human review), < 0.30 → **ALLOW** |
| 3. Automatic IP ban | A source IP blocked 10 times | Every later packet from that IP is dropped and an `iptables` rule is generated |

## Results (official NSL-KDD test set, 22,544 connections)

| Model | Accuracy | Precision | Recall | F1-score |
|---|---|---|---|---|
| Decision Tree (baseline) | 79.1% | 92.0% | 69.3% | 79.0% |
| **Random Forest (used in the firewall)** | **77.1%** | **96.8%** | **61.9%** | **75.5%** |

- On a held-out 20% of the training file (attack types the model has seen), both models score above **99.8%**. The drop on the test file is expected: KDDTest+ deliberately contains attack types that never appear in training.
- Random Forest was chosen because it blocks far fewer legitimate users: a **2.7% false-positive rate** (265 normal flows) against **8.0%** (778 flows) for the Decision Tree – about three times fewer genuine users wrongly blocked.
- Detection by attack family: DoS **79.0%**, Probe **77.5%**, R2L **5.6%**, U2R **11.9%**. R2L and U2R attacks look like normal logins at the connection level, which is the main limitation.
- When the full test set is replayed through all three layers (`simulate.py`), **78.3%** of attacks are blocked and a further **7.7%** raised as alerts, while **2.9%** of normal traffic is blocked. 36 attacker IPs were banned and no internal host was banned.

> NSL-KDD contains no IP addresses, so `simulate.py` assigns simulated source IPs (2,000 internal hosts for normal traffic, three attacker hosts per attack type) to demonstrate the IP-ban layer. The model metrics above do not depend on this.

![Confusion matrix](results/confusion_matrix.png)
![Dashboard](results/dashboard_live.png)

## Project structure

```
ai-smart-firewall/
├── app.py                  Streamlit dashboard
├── src/
│   ├── data_loader.py      Column names, labels and attack families for NSL-KDD
│   ├── train.py            Preprocessing, training, evaluation and charts
│   ├── firewall.py         SmartFirewall class (static rules + AI + IP ban)
│   └── simulate.py         Replays test traffic through the firewall
├── data/                   KDDTrain+.txt and KDDTest+.txt
├── models/                 Saved model (created by train.py)
└── results/                Metrics, charts, firewall log and generated iptables rules
```

## How to run

```bash
pip install -r requirements.txt

python src/train.py       # trains both models, saves the model, metrics and charts (~15 s)
python src/simulate.py    # replays the test traffic, writes firewall_log.csv and iptables_rules.txt
streamlit run app.py      # opens the dashboard at http://localhost:8501
```

Tested with Python 3.13, scikit-learn 1.9, pandas 3.0 and Streamlit 1.66.

## Workflow

Load → check missing values → one-hot encode `protocol_type`, `service`, `flag` (41 → 121 features) → 80/20 stratified split → train Decision Tree and Random Forest (100 trees, `random_state=42`) → evaluate on validation and KDDTest+ → save model → replay traffic through the firewall.

## Dataset

**NSL-KDD** (Tavallaee et al., 2009), Canadian Institute for Cybersecurity, University of New Brunswick – https://www.unb.ca/cic/datasets/nsl.html. 125,973 training and 22,544 test connections, each with 41 features and a label (normal or one of 39 attack types grouped into DoS, Probe, R2L and U2R).

## Limitations

- Works on connection records, not on live packet capture.
- Weak on R2L and U2R attacks.
- A learning prototype: alerts and bans should be reviewed by a network administrator before being enforced on a real network.

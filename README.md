# Sentinel AI-IDS

An AI-based Intrusion Detection System using Random Forest
and Isolation Forest ML models combined with Snort IDS.

## Features
- Real-time packet capture using Pyshark and Scapy
- Supervised detection using Random Forest
- Anomaly detection using Isolation Forest
- Snort rule-based detection and auto-updating
- Live web dashboard at http://localhost:5000
- Alert logging and reporting

## Project Structure
```
sentinel/
├── data/           # Captured data and logs
├── models/         # Saved ML models
├── snort/          # Snort rules and configs
├── src/
│   ├── capture/    # Packet capture modules
│   ├── features/   # Feature extraction
│   ├── ml/         # ML models
│   ├── engine/     # Decision engine
│   ├── dashboard/  # Web dashboard
│   └── utils/      # Logger and config
├── config.yaml     # Main configuration
├── requirements.txt
└── main.py         # Entry point
```

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python main.py
```

## ML Models
- Random Forest: Detects known attack patterns
- Isolation Forest: Detects unknown anomalies

## Alert Severity Levels
- CRITICAL: Both models detect threat
- HIGH: RF confidence above 90%
- MEDIUM: RF confidence above 70%
- LOW: Anomaly detected only

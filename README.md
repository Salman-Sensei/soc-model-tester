# SOC Model Tester
### Network Intrusion Detection and SOC Triage with Machine Learning

SOC Model Tester is a local web application for testing machine learning models developed for network intrusion detection and Security Operations Center (SOC) triage.

Built with **React, Vite, Flask, and scikit-learn**, the application provides a browser-based interface for loading a serialized model, analyzing network-flow records, predicting benign or attack-like behavior, identifying potential attack families, and assigning provisional triage priorities.

The project brings together the model development workflow in Google Colab and a separate web application for interactive inference and evaluation.

> **Project scope:** This is an offline model-testing and research project. It does not inspect live network traffic or replace a production intrusion detection system.

## Table of Contents

- [Project Overview](#project-overview)
- [Screenshots](#screenshots)
- [Model Development Notebook](#model-development-notebook)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Model Input Schema](#model-input-schema)
- [Application Features](#application-features)
- [Benchmark Results](#benchmark-results)
- [Getting Started](#getting-started)
- [Running the Application](#running-the-application)
- [Using the Application](#using-the-application)
- [Prediction and Triage Policy](#prediction-and-triage-policy)
- [CSV Evaluation](#csv-evaluation)
- [Preprocessing and Model Compatibility](#preprocessing-and-model-compatibility)
- [Project Structure](#project-structure)
- [Security and Limitations](#security-and-limitations)
- [References](#references)

## Project Overview

Security analysts need reproducible ways to examine network activity, distinguish benign traffic from potentially malicious behavior, and prioritize suspicious records for further investigation.

This project explores that workflow using network-flow data from two public benchmark datasets:

- **CIC-IDS2017**
- **UNSW-NB15**

The development notebook covers data auditing, feature alignment, exploratory data analysis, preprocessing, model training, classification evaluation, and SOC triage experiments.

The web application provides an interface for testing the resulting model artifact without requiring users to call the Python inference code manually.

### Prediction workflow

1. Load the saved model artifact.
2. Provide a network-flow record or upload a CSV dataset.
3. Predict `BENIGN` or `ATTACK`.
4. Estimate an attack family when the binary classifier predicts an attack and the family classifier is available.
5. Assign a provisional triage priority from the available attack probability.
6. Review the predictions and export batch results when required.

## Screenshots

### Model Upload

Upload a trusted model artifact and inspect the model-loading status.

![SOC Model Tester: Model Upload](docs/images/model-upload.png)

### Prediction and Triage Results

Review the predicted label, available confidence scores, attack-family prediction, and triage priority.

![SOC Model Tester: Prediction Results](docs/images/prediction-results.png)

## Model Development Notebook

The machine learning workflow is documented in the project's Jupyter notebook, which can be viewed directly on GitHub.

**[View the complete SOC model development notebook](notebooks/soc_intrusion_detection_pipeline.ipynb)**

The notebook includes:

- Dataset loading and data quality auditing.
- Feature alignment between CIC-IDS2017 and UNSW-NB15.
- Exploratory data analysis and label distribution analysis.
- Train/test splitting and preprocessing validation.
- Baseline, logistic regression, weighted logistic regression, and Random Forest experiments.
- Binary attack detection and attack-family classification.
- Confusion matrices, classification metrics, and error analysis.
- Provisional SOC triage thresholds and severity-related analysis.
- Inference tests and model artifact preparation.

For additional notebook information, see [`notebooks/ReadMe.md`](notebooks/ReadMe.md).

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Frontend | React | Interactive single-page user interface |
| Frontend tooling | Vite | Development server and frontend build tooling |
| Interface | JavaScript, HTML, CSS | Forms, layouts, input validation, and result presentation |
| Backend | Python | Model loading, inference, and evaluation logic |
| Web API | Flask | Connects the frontend to backend operations |
| Machine learning | scikit-learn | Classification estimators and preprocessing |
| Model serialization | joblib | Persistence and loading of trained model objects |
| Data exchange | CSV | Batch input, prediction output, and optional evaluation |

The backend requirements pin scikit-learn to version `1.6.1` to align with the version reported by the development notebook.

## System Architecture

```text
                       SOC Analyst
                            |
                            v
                    React + Vite UI
                    localhost:5173
                            |
                            | HTTP requests
                            v
                      Flask API
                    127.0.0.1:5000
                            |
                            v
                     Model Artifact
                    soc_model.joblib
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          Binary Classifier     Family Classifier
          BENIGN / ATTACK       Attack Category
                 |
                 v
           Triage Assessment
                 |
                 v
          Results and CSV Export
```

The binary classifier predicts benign or attack-like behavior. The family classifier is used in the combined workflow for records predicted as `ATTACK`, provided that the required classifier is available.

The application and API run locally as separate development services.

## Model Input Schema

The application uses seven aligned numerical features in the following order:

| Feature | Description |
|---|---|
| `flow_duration_seconds` | Duration of the network flow |
| `src_packets` | Number of packets sent from the source |
| `dst_packets` | Number of packets sent from the destination |
| `src_bytes` | Total bytes sent from the source |
| `dst_bytes` | Total bytes sent from the destination |
| `src_mean_packet_bytes` | Mean packet size for source traffic |
| `dst_mean_packet_bytes` | Mean packet size for destination traffic |

CSV processing selects these features by name, allowing the input columns to appear in a different order.

The following columns are label or audit fields, not model inputs:

- `is_attack`
- `attack_category`
- `dataset_source`
- `original_label`
- `binary_label`

Keeping ground-truth labels outside the model input helps prevent label leakage during evaluation.

## Application Features

### Model Loading and Inspection

- Upload a trusted `.joblib`, `.pkl`, or `.pickle` model artifact.
- Inspect supported model bundles for recognizable estimator objects.
- Identify likely binary and family classifiers from the available model structure.
- Display discoverable benign percentile and severity-related configuration.
- Report model-loading and compatibility errors.

### Single-Record Prediction

- Enter the seven network-flow features manually.
- Populate the form using example flow records.
- Generate synthetic random feature values for a functional test.
- Run a selected classifier directly.
- Run the combined binary detection and attack-family workflow.
- Display available predicted labels and probability scores.

### CSV Batch Testing

- Upload CSV files containing the required feature columns.
- Process up to 5,000 rows per batch.
- Generate 25 synthetic rows from the interface.
- Calculate binary classification metrics when supported ground-truth labels are present.
- Export prediction results to CSV.

Synthetic records are intended for testing the application workflow. They are not real traffic observations and should not be used to establish detection accuracy.

## Benchmark Results

The development notebook reported the following results for its particular evaluation setup:

| Model or task | Metric | Reported result |
|---|---|---:|
| Random Forest: attack vs. benign | Accuracy | 88.59% |
| Random Forest: attack vs. benign | F1-score | 89.12% |
| Attack-family classifier | Accuracy on true-attack alerts | 82.18% |
| Attack-family classifier | Macro F1-score | 65.70% |

The family classifier metrics were reported on 47,837 true-attack alerts.

These figures are **not guarantees of production performance**. They describe the particular data preparation, train/test split, and evaluation workflow used in the notebook. Results can change with dataset composition, preprocessing, class distribution, and evaluation methodology.

For a meaningful assessment, examine false negatives, false positives, attack recall, precision, confusion matrices, and results for each dataset separately.

## Getting Started

### Prerequisites

Install the following software:

- Python 3.12
- Node.js LTS, including npm
- Visual Studio Code or another code editor
- A compatible, trusted `soc_model.joblib` artifact for inference testing

Verify the installations in a terminal:

```powershell
python --version
node --version
npm.cmd --version
git --version
```

The application can be developed without VS Code, but VS Code provides a convenient interface for managing the React and Flask code.

### Clone the Repository

```powershell
git clone https://github.com/Salman-Sensei/soc-model-tester.git
cd soc-model-tester
```

Open the project folder in VS Code if desired.

## Running the Application

The frontend and backend run in two separate terminals. Keep both terminals open while using the application.

### Terminal 1: Flask Backend

From the project root, run:

```powershell
cd backend
python -m venv .venv
```

Install the dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start the Flask API:

```powershell
.\.venv\Scripts\python.exe app.py
```

The backend should be available at:

`http://127.0.0.1:5000`

### Terminal 2: React Frontend

Open a second terminal from the project root:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open the local URL printed by Vite. The default development address is:

`http://127.0.0.1:5173`

**Windows PowerShell note:** Use `npm.cmd` if the PowerShell execution policy blocks `npm.ps1`. This avoids changing the system-wide PowerShell security policy.

If the backend or frontend fails to start, check the corresponding terminal output and verify that the dependencies are installed.

## Using the Application

### 1. Load the Model

Open the frontend and upload your trusted model artifact using the model upload control. Confirm that the backend reports successful loading.

### 2. Run a Prediction

Choose the combined SOC triage workflow or an individual classifier. Enter a sample manually, select an available example, or generate a synthetic sample.

Run the prediction and inspect the returned information.

### 3. Test a Dataset

Select CSV batch mode and upload a CSV containing the required seven features. A labeled CSV can additionally support evaluation if its target labels are recognized.

For a quick functionality check, generate the 25-row synthetic sample directly in the interface.

### 4. Inspect and Export Results

Review the predictions and available metrics. Export the batch results when needed.

A successful model response confirms that the inference path executed. It does not prove that an individual prediction is correct.

## Prediction and Triage Policy

The combined workflow uses the binary classifier to predict `BENIGN` or `ATTACK`. When the prediction is `ATTACK`, the family classifier may estimate the likely attack family.

If the binary classifier provides a usable attack probability, the default provisional policy is:

| Attack probability | Triage priority |
|---|---|
| Below `0.50` | `LOW_PRIORITY` |
| `0.50` to below `0.85` | `REVIEW` |
| `0.85` or above | `HIGH_PRIORITY_REVIEW` |

These thresholds come from the project specification. They are demonstration settings, not calibrated or validated operational rules.

The application should not be interpreted as providing a validated severity score, confirmed incident attribution, or automated response authorization unless those capabilities are explicitly supported by the saved configuration and implementation.

## CSV Evaluation

When a supported target label is included in an uploaded dataset, the application can calculate binary classification metrics such as:

- Accuracy
- Attack precision
- Attack recall
- F1-score
- True positives (TP)
- True negatives (TN)
- False positives (FP)
- False negatives (FN)

Metrics are meaningful only when ground-truth labels are correctly mapped to predictions from the same records.

For reliable evaluation, use an appropriate held-out test set and examine CIC-IDS2017 and UNSW-NB15 results separately where possible. Differences between datasets may expose domain shift that aggregate metrics conceal.

Metrics calculated on training records must not be presented as independent test performance.

## Preprocessing and Model Compatibility

The development notebook reports that the prepared training matrix used standardized features, with means near zero and standard deviations near one.

If a classifier was trained on standardized features, its inference inputs must receive the same fitted transformation. The saved artifact should therefore contain the required fitted preprocessing pipeline or the corresponding fitted transformer and compatible inference logic.

The application checks for recognizable scikit-learn pipelines or separate preprocessing objects where supported. If no appropriate preprocessing object is found, raw feature values may be passed directly to the estimator, potentially producing misleading predictions.

Before trusting the results, confirm that:

1. The bundle contains the intended binary and family classifiers.
2. Feature names, units, order, and definitions match those used during training.
3. The fitted preprocessing is present and applied correctly.
4. The installed scikit-learn version is compatible with the saved estimators.
5. The target labels and probability columns are mapped correctly.

The dependency pin reduces version mismatch risk but cannot guarantee compatibility with every serialized model.

## Project Structure

```text
soc-model-tester/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── .gitignore
│
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── styles.css
│
├── notebooks/
│   ├── soc_intrusion_detection_pipeline.ipynb
│   └── ReadMe.md
│
├── docs/
│   └── images/
│       ├── model-upload.png
│       └── prediction-results.png
│
├── .gitignore
└── README.md
```

Runtime-generated directories, such as local model storage and uploads, may be created when the application runs.

## Security and Limitations

- **Offline demonstration:** The application is not a production SOC platform and does not capture live network traffic.
- **Serialized model security:** Joblib and pickle-based formats can execute code during deserialization. Load only model artifacts from trusted sources.
- **Preprocessing:** Prediction outputs should not be trusted until the inference transformations are verified against training.
- **Synthetic test data:** Random values help test the interface and inference path but cannot establish real-world detection quality.
- **Evaluation:** Metrics depend on valid labels, an appropriate test split, and the model's training and preprocessing procedure.
- **Triage policy:** Alert priorities are provisional and should not be used to automatically block traffic.
- **Privacy:** Do not commit private datasets, API credentials, environment files, or confidential traffic records.
- **Artifact distribution:** Only publish a trained model artifact if you intend to distribute it and have checked its contents, size, licensing implications, and security considerations.

## References

- [React Documentation](https://react.dev/)
- [Vite Documentation](https://vite.dev/guide/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [scikit-learn Documentation](https://scikit-learn.org/stable/)
- [joblib Persistence and Security Guidance](https://joblib.readthedocs.io/en/latest/user_guide/persistence.html)
- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [Python Downloads](https://www.python.org/downloads/)
- [Node.js Downloads](https://nodejs.org/en/download)

---

**Maintainer:** [Salman-Sensei](https://github.com/Salman-Sensei)

**Repository:** [soc-model-tester](https://github.com/Salman-Sensei/soc-model-tester)

The project provides a reproducible starting point for experimenting with network intrusion classification and exploring how trained model outputs can support SOC triage workflows.

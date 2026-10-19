from __future__ import annotations

import math
import re
import threading
import time
import warnings
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
UPLOAD_DIR = BASE_DIR / "uploads"
MODEL_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
DEFAULT_MODEL_PATH = MODEL_DIR / "soc_model.joblib"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_CSV_BYTES = 25 * 1024 * 1024
MAX_BATCH_ROWS = 5000

# This is the canonical shared schema from the SOC notebook. Dataset label
# columns (is_attack, attack_category, binary_label, etc.) are never model inputs.
SOC_FEATURES = [
    "flow_duration_seconds",
    "src_packets",
    "dst_packets",
    "src_bytes",
    "dst_bytes",
    "src_mean_packet_bytes",
    "dst_mean_packet_bytes",
]
LABEL_COLUMNS = {
    "is_attack", "attack_category", "dataset_source", "original_label", "binary_label"
}
DEFAULT_TRIAGE_POLICY = {
    "low_priority_if_probability_below": 0.50,
    "review_if_probability_at_least": 0.50,
    "high_priority_if_probability_at_least": 0.85,
    "status": "Provisional demonstration thresholds; not calibrated or validated",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}})

_state_lock = threading.RLock()
_bundle: Any = None
_model_path: str | None = None
_models: list[dict[str, Any]] = []
_metadata: dict[str, Any] = {}
_triage_policy: dict[str, Any] = dict(DEFAULT_TRIAGE_POLICY)
_last_load_error: str | None = None


def _safe_scalar(value: Any) -> Any:
    """Convert common numpy/scikit-learn values to JSON-safe values."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, np.generic):
        return _safe_scalar(value.item())
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_safe_scalar(item) for item in list(value)[:100]]
    if isinstance(value, np.ndarray):
        return _safe_scalar(value.tolist())
    if isinstance(value, dict):
        output = {}
        for key, item in list(value.items())[:100]:
            if isinstance(key, (str, int, float, bool)):
                output[str(key)] = _safe_scalar(item)
        return output
    return str(value)


def _walk_objects(obj: Any, path: str = "bundle", seen: set[int] | None = None) -> Iterable[tuple[str, Any]]:
    """Find estimators inside common dict/list/tuple model bundles."""
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return
    seen.add(obj_id)

    if callable(getattr(obj, "predict", None)):
        yield path, obj
        # A Pipeline/estimator is one prediction unit: don't traverse internals.
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, (str, int, float)):
                yield from _walk_objects(value, f"{path}.{key}", seen)
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            yield from _walk_objects(value, f"{path}[{index}]", seen)


def _walk_values(obj: Any, path: str = "bundle", depth: int = 0) -> Iterable[tuple[str, Any]]:
    """Walk container values, including non-estimator transformers, conservatively."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}"
            yield child_path, value
            if isinstance(value, (dict, list, tuple)):
                yield from _walk_values(value, child_path, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            child_path = f"{path}[{index}]"
            yield child_path, value
            if isinstance(value, (dict, list, tuple)):
                yield from _walk_values(value, child_path, depth + 1)


def _is_generic_feature_name(name: Any) -> bool:
    return bool(re.fullmatch(r"(?:feature|x)_?\d+", str(name).strip(), flags=re.I))


def _feature_schema(estimator: Any) -> tuple[list[str], bool]:
    """Use fitted names where available, otherwise use the known seven-column SOC schema."""
    names = getattr(estimator, "feature_names_in_", None)
    if names is None:
        for attr in ("estimator", "model", "classifier", "best_estimator_"):
            nested = getattr(estimator, attr, None)
            names = getattr(nested, "feature_names_in_", None) if nested is not None else None
            if names is not None:
                break
    if names is not None:
        result = [str(name) for name in list(names)]
        if len(result) == len(SOC_FEATURES) and all(_is_generic_feature_name(name) for name in result):
            return list(SOC_FEATURES), False
        return result, True

    count = getattr(estimator, "n_features_in_", None)
    if count is None:
        for attr in ("estimator", "model", "classifier", "best_estimator_"):
            nested = getattr(estimator, attr, None)
            count = getattr(nested, "n_features_in_", None) if nested is not None else None
            if count is not None:
                break
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = 0
    if count == len(SOC_FEATURES):
        return list(SOC_FEATURES), False
    return [f"feature_{index + 1}" for index in range(max(0, count))], False


def _human_label(path: str) -> str:
    label = path.replace("bundle.", "").replace("_", " ").replace(".", " / ")
    label = re.sub(r"\s+", " ", label).strip()
    return label.title() if label else "Classifier"


def _classes_for(estimator: Any) -> list[Any]:
    classes = getattr(estimator, "classes_", None)
    if classes is None:
        for attr in ("estimator", "model", "classifier", "best_estimator_"):
            nested = getattr(estimator, attr, None)
            classes = getattr(nested, "classes_", None) if nested is not None else None
            if classes is not None:
                break
    return _safe_scalar(list(classes)) if classes is not None else []


def _role_for(path: str, classes: list[Any], feature_count: int) -> str:
    key = path.lower().replace("-", "_")
    tokens = set(re.split(r"[^a-z0-9]+", key))
    family_terms = ("family", "families", "attack_type", "multiclass", "category")
    attack_terms = ("attack", "benign", "random_forest", "randomforest", "rf_model", "binary", "soc_model")
    if any(term in key for term in family_terms) or len(classes) > 2:
        return "Family classifier"
    if "rf" in tokens or any(term in key for term in attack_terms):
        return "Attack vs benign"
    # The supplied SOC bundle is known to contain a binary head and a family
    # head. Use the 7-feature/two-class shape as a useful fallback for unnamed keys.
    if feature_count == len(SOC_FEATURES) and len(classes) == 2:
        return "Attack vs benign"
    return "Classifier"


def _collect_metadata(root: Any) -> dict[str, Any]:
    found: dict[str, Any] = {}
    wanted = ("benign_percentile", "percentile", "severity", "threshold", "triage_policy")
    for path, value in _walk_values(root):
        key = path.rsplit(".", 1)[-1].lower()
        if any(term in key for term in wanted):
            # Store the original key/path so equally named nested settings aren't lost.
            if isinstance(value, (dict, list, tuple, str, int, float, bool)) or value is None:
                found[path.replace("bundle.", "")] = _safe_scalar(value)
    return found


def _find_policy(root: Any) -> dict[str, Any]:
    for path, value in _walk_values(root):
        key = path.rsplit(".", 1)[-1].lower()
        if key in {"triage_policy", "triage_thresholds", "alert_thresholds"} and isinstance(value, dict):
            policy = dict(DEFAULT_TRIAGE_POLICY)
            for name in ("low_priority_if_probability_below", "review_if_probability_at_least", "high_priority_if_probability_at_least"):
                if name in value:
                    try:
                        policy[name] = float(value[name])
                    except (TypeError, ValueError):
                        pass
            if isinstance(value.get("status"), str):
                policy["status"] = value["status"]
            try:
                review = float(policy["review_if_probability_at_least"])
                high = float(policy["high_priority_if_probability_at_least"])
                low = float(policy["low_priority_if_probability_below"])
                if not (0 <= low <= review < high <= 1):
                    return dict(DEFAULT_TRIAGE_POLICY)
            except (TypeError, ValueError):
                return dict(DEFAULT_TRIAGE_POLICY)
            return policy
    return dict(DEFAULT_TRIAGE_POLICY)


def _inspect_bundle(root: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    unique: list[tuple[str, Any]] = []
    used_ids: set[int] = set()
    for path, estimator in _walk_objects(root):
        if id(estimator) not in used_ids:
            unique.append((path, estimator))
            used_ids.add(id(estimator))

    models = []
    for index, (path, estimator) in enumerate(unique):
        names, has_named_schema = _feature_schema(estimator)
        classes = _classes_for(estimator)
        role = _role_for(path, classes, len(names))
        if hasattr(estimator, "steps"):
            preprocessing_status = "pipeline"
            input_note = "This estimator is a scikit-learn Pipeline; preprocessing steps run inside predict()."
        elif _find_transformer(root, role) is not None:
            preprocessing_status = "separate_transformer"
            input_note = "A separate fitted transformer was detected and will be applied before prediction."
        else:
            preprocessing_status = "none_detected"
            input_note = "No separate preprocessing object was detected. Values are passed directly to this estimator."
        models.append({
            "id": f"model_{index}",
            "path": path,
            "label": _human_label(path),
            "role": role,
            "feature_names": names,
            "feature_names_are_real": has_named_schema,
            "feature_count": len(names),
            "classes": classes,
            "has_predict_proba": callable(getattr(estimator, "predict_proba", None)),
            "preprocessing_status": preprocessing_status,
            "input_note": input_note,
        })

    models.sort(key=lambda item: (0 if item["role"] == "Attack vs benign" else 1 if item["role"] == "Family classifier" else 2, item["path"].lower()))
    for index, item in enumerate(models):
        item["id"] = f"model_{index}"
    return models, _collect_metadata(root)


def _serialize_model_info() -> dict[str, Any]:
    return {
        "loaded": _bundle is not None,
        "filename": Path(_model_path).name if _model_path else None,
        "models": _models,
        "metadata": _metadata,
        "triage_policy": _triage_policy,
        "feature_schema": SOC_FEATURES,
        "model_count": len(_models),
        "triage_supported": any(m["role"] == "Attack vs benign" for m in _models),
        "load_error": _last_load_error,
    }


def _load_model(filepath: Path) -> dict[str, Any]:
    global _bundle, _model_path, _models, _metadata, _triage_policy, _last_load_error
    # Joblib is pickle-based. Only load a model artifact you trust.
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        candidate = joblib.load(filepath)
    models, metadata = _inspect_bundle(candidate)
    if not models:
        raise ValueError(
            "The file loaded, but no object with a .predict() method was found. "
            "Expected scikit-learn-style estimators in a dictionary/list or as the root object."
        )

    with _state_lock:
        _bundle = candidate
        _model_path = str(filepath)
        _models = models
        _metadata = metadata
        _triage_policy = _find_policy(candidate)
        _last_load_error = None
    return _serialize_model_info()


def _find_estimator(obj: Any, path: str) -> Any:
    for candidate_path, estimator in _walk_objects(obj):
        if candidate_path == path:
            return estimator
    raise KeyError("Selected model could not be found in the loaded bundle. Please upload the model again.")


def _model_record(model_id: str) -> dict[str, Any]:
    for item in _models:
        if item["id"] == model_id:
            return item
    raise KeyError("Choose a valid classifier first.")


def _pick_role(role: str) -> dict[str, Any] | None:
    matches = [item for item in _models if item["role"] == role]
    if matches:
        return matches[0]
    return None


def _find_transformer(root: Any, role: str) -> Any | None:
    """Return a separate saved transformer when a bundle includes one.

    A Pipeline already owns its transform steps, so its internal transformer is
    not separately applied. For plain classifiers, common sibling keys such as
    preprocessor/scaler are supported when present.
    """
    possible = []
    for path, value in _walk_values(root):
        if callable(getattr(value, "transform", None)) and not callable(getattr(value, "predict", None)):
            key = path.lower()
            if any(token in key for token in ("preprocess", "transformer", "scaler", "imputer", "normalizer")):
                role_match = ("family" in key) if role == "Family classifier" else any(token in key for token in ("binary", "attack", "random_forest", "rf_model"))
                generic = not any(token in key for token in ("family", "binary", "attack", "random_forest", "rf_model"))
                possible.append((0 if role_match else 1 if generic else 2, path, value))
    possible.sort(key=lambda item: (item[0], len(item[1])))
    return possible[0][2] if possible else None


def _model_input(root: Any, estimator: Any, model_info: dict[str, Any], frame: pd.DataFrame) -> Any:
    # A sklearn Pipeline performs preprocessing inside predict(). Don't transform twice.
    if callable(getattr(estimator, "predict", None)) and hasattr(estimator, "steps"):
        return frame
    transformer = _find_transformer(root, model_info["role"])
    if transformer is None:
        return frame
    try:
        return transformer.transform(frame)
    except Exception as first_error:
        try:
            return transformer.transform(frame.to_numpy())
        except Exception:
            raise ValueError(
                "A saved preprocessing object was found, but it could not transform the seven SOC features. "
                "Check that the same fitted preprocessing pipeline used for training is included in the bundle."
            ) from first_error


def _predict(estimator: Any, model_input: Any) -> tuple[np.ndarray, np.ndarray | None]:
    try:
        predictions = np.asarray(estimator.predict(model_input)).reshape(-1)
    except Exception as first_error:
        fallback = model_input.to_numpy() if isinstance(model_input, pd.DataFrame) else np.asarray(model_input)
        try:
            predictions = np.asarray(estimator.predict(fallback)).reshape(-1)
        except Exception:
            raise first_error

    probabilities = None
    if callable(getattr(estimator, "predict_proba", None)):
        try:
            probabilities = np.asarray(estimator.predict_proba(model_input))
        except Exception:
            fallback = model_input.to_numpy() if isinstance(model_input, pd.DataFrame) else np.asarray(model_input)
            try:
                probabilities = np.asarray(estimator.predict_proba(fallback))
            except Exception:
                probabilities = None
    return predictions, probabilities


def _classes_for_input(estimator: Any, model_info: dict[str, Any]) -> list[Any]:
    classes = _classes_for(estimator)
    return classes if classes else list(model_info.get("classes") or [])


def _probability_pairs(estimator: Any, model_info: dict[str, Any], probability_row: Any) -> list[dict[str, Any]]:
    classes = _classes_for_input(estimator, model_info)
    values = np.asarray(probability_row).reshape(-1)
    pairs = []
    for index, probability in enumerate(values):
        label = classes[index] if index < len(classes) else index
        number = float(probability)
        pairs.append({"class": _safe_scalar(label), "probability": number if math.isfinite(number) else None})
    pairs.sort(key=lambda pair: pair["probability"] if pair["probability"] is not None else -1, reverse=True)
    return pairs


def _prediction_payload(estimator: Any, model_info: dict[str, Any], model_input: Any) -> dict[str, Any]:
    predictions, probabilities = _predict(estimator, model_input)
    raw_prediction = _safe_scalar(predictions[0])
    result: dict[str, Any] = {
        "prediction": raw_prediction,
        "probabilities": [],
        "confidence": None,
    }
    if probabilities is not None and probabilities.ndim == 2 and len(probabilities):
        pairs = _probability_pairs(estimator, model_info, probabilities[0])
        result["probabilities"] = pairs
        # Confidence refers to the probability attached to the predicted label,
        # not blindly to the maximum probability if a custom estimator differs.
        predicted_pair = next((p for p in pairs if str(p["class"]) == str(raw_prediction)), None)
        result["confidence"] = predicted_pair["probability"] if predicted_pair else (pairs[0]["probability"] if pairs else None)
    return result


def _parse_value(value: Any) -> Any:
    if value is None:
        return np.nan
    if not isinstance(value, str):
        return value
    raw = value.strip()
    if raw == "":
        return np.nan
    lower = raw.lower()
    if lower in {"true", "yes"}:
        return 1
    if lower in {"false", "no"}:
        return 0
    if lower in {"none", "null", "nan"}:
        return np.nan
    try:
        if re.fullmatch(r"[+-]?\d+", raw):
            return int(raw)
        number = float(raw)
        return number if math.isfinite(number) else np.nan
    except ValueError:
        return raw


def _frame_from_mapping(model_info: dict[str, Any], values: dict[str, Any]) -> pd.DataFrame:
    expected = model_info["feature_names"]
    if not expected:
        raise ValueError("This classifier does not expose its expected feature count. Check the training code or use a CSV with a known feature schema.")
    missing = [name for name in expected if name not in values or str(values[name]).strip() == ""]
    if missing:
        show = ", ".join(missing[:8])
        suffix = " …" if len(missing) > 8 else ""
        raise ValueError(f"Fill in all {len(missing)} required feature(s). Missing: {show}{suffix}")
    return pd.DataFrame([{name: _parse_value(values[name]) for name in expected}], columns=expected)


def _frame_from_csv(model_info: dict[str, Any], csv_frame: pd.DataFrame) -> pd.DataFrame:
    expected = list(model_info["feature_names"])
    # The known SOC features take precedence over CSV physical column order. This
    # prevents dataset_source/label columns from accidentally entering the model.
    if expected == SOC_FEATURES:
        missing = [name for name in SOC_FEATURES if name not in csv_frame.columns]
        if missing:
            raise ValueError("CSV is missing the expected SOC feature columns: " + ", ".join(missing))
        return csv_frame.loc[:, SOC_FEATURES].copy()
    if expected and model_info.get("feature_names_are_real", False):
        missing = [name for name in expected if name not in csv_frame.columns]
        if missing:
            shown = ", ".join(missing[:10])
            suffix = " …" if len(missing) > 10 else ""
            raise ValueError(f"CSV is missing {len(missing)} required column(s): {shown}{suffix}")
        return csv_frame.loc[:, expected].copy()
    count = model_info["feature_count"]
    if count <= 0:
        raise ValueError("The classifier does not expose its feature count, so CSV columns cannot be inferred.")
    if len(csv_frame.columns) < count:
        raise ValueError(f"The model expects {count} input columns, but the CSV has only {len(csv_frame.columns)} columns.")
    feature_columns = [column for column in csv_frame.columns if str(column).lower() not in LABEL_COLUMNS]
    if len(feature_columns) < count:
        raise ValueError(f"After excluding known label/audit columns, fewer than {count} feature columns remain.")
    return csv_frame.loc[:, feature_columns[:count]].copy()


def _is_attack_label(value: Any) -> bool | None:
    label = str(value).strip().lower()
    if label in {"0", "0.0", "benign", "normal", "clean", "false", "no"}:
        return False
    if label in {"1", "1.0", "attack", "malicious", "anomaly", "intrusion", "true", "yes"}:
        return True
    return None


def _family_model() -> dict[str, Any] | None:
    family = _pick_role("Family classifier")
    if family:
        return family
    # Useful fallback if the bundle keys are generic but the multiclass labels aren't.
    return next((item for item in _models if len(item.get("classes") or []) > 2), None)


def _binary_model() -> dict[str, Any] | None:
    binary = _pick_role("Attack vs benign")
    if binary:
        return binary
    return next((item for item in _models if len(item.get("classes") or []) == 2 and item.get("feature_count") == len(SOC_FEATURES)), None)


def _attack_probability(estimator: Any, model_info: dict[str, Any], probabilities: np.ndarray | None) -> float | None:
    if probabilities is None or probabilities.ndim != 2 or not len(probabilities):
        return None
    row = np.asarray(probabilities[0]).reshape(-1)
    classes = _classes_for_input(estimator, model_info)
    attack_indices = [index for index, label in enumerate(classes) if _is_attack_label(label) is True]
    if attack_indices:
        return float(sum(row[index] for index in attack_indices if index < len(row)))
    if len(row) == 2:
        # The notebook target is binary_label/is_attack where 1 means ATTACK.
        class_one_index = next((index for index, label in enumerate(classes) if str(label).strip() in {"1", "1.0"}), 1)
        if class_one_index < len(row):
            return float(row[class_one_index])
    return None


def _class_confidence(estimator: Any, model_info: dict[str, Any], predicted: Any, probability_row: Any | None) -> float | None:
    if probability_row is None:
        return None
    pairs = _probability_pairs(estimator, model_info, probability_row)
    match = next((pair for pair in pairs if str(pair["class"]) == str(_safe_scalar(predicted))), None)
    return match["probability"] if match else (pairs[0]["probability"] if pairs else None)


def _triage_label(probability: float | None) -> str:
    if probability is None or not math.isfinite(probability) or not 0 <= probability <= 1:
        return "NOT_AVAILABLE"
    try:
        review = float(_triage_policy.get("review_if_probability_at_least", 0.50))
        high = float(_triage_policy.get("high_priority_if_probability_at_least", 0.85))
    except (TypeError, ValueError):
        review, high = 0.50, 0.85
    if not (0 <= review < high <= 1):
        review, high = 0.50, 0.85
    if probability < review:
        return "LOW_PRIORITY"
    if probability >= high:
        return "HIGH_PRIORITY_REVIEW"
    return "REVIEW"


def _run_triage(values: dict[str, Any], dataset_source: str | None = None) -> dict[str, Any]:
    if _bundle is None:
        raise ValueError("Load your soc_model.joblib file first.")
    binary_info = _binary_model()
    if binary_info is None:
        raise ValueError("A binary attack-vs-benign classifier could not be detected in this bundle. Check the saved model keys and classes.")
    binary_estimator = _find_estimator(_bundle, binary_info["path"])
    frame = _frame_from_mapping(binary_info, values)
    binary_input = _model_input(_bundle, binary_estimator, binary_info, frame)
    binary_predictions, binary_probabilities = _predict(binary_estimator, binary_input)
    raw_prediction = _safe_scalar(binary_predictions[0])
    is_attack = _is_attack_label(raw_prediction)
    if is_attack is None:
        raise ValueError(f"The binary classifier returned an unrecognized label: {raw_prediction!r}. Expected 0/1 or BENIGN/ATTACK.")
    prediction = "ATTACK" if is_attack else "BENIGN"
    attack_probability = _attack_probability(binary_estimator, binary_info, binary_probabilities)
    binary_probability_row = binary_probabilities[0] if binary_probabilities is not None and len(binary_probabilities) else None
    binary_confidence = _class_confidence(
        binary_estimator, binary_info, raw_prediction, binary_probability_row,
    )
    binary_probability_pairs = _probability_pairs(binary_estimator, binary_info, binary_probability_row) if binary_probability_row is not None else []

    family = None
    family_confidence = None
    family_probability_pairs = []
    family_info = _family_model()
    if is_attack and family_info is not None:
        family_estimator = _find_estimator(_bundle, family_info["path"])
        family_frame = _frame_from_mapping(family_info, values)
        family_input = _model_input(_bundle, family_estimator, family_info, family_frame)
        family_predictions, family_probabilities = _predict(family_estimator, family_input)
        family = _safe_scalar(family_predictions[0])
        family_probability_row = family_probabilities[0] if family_probabilities is not None and len(family_probabilities) else None
        family_confidence = _class_confidence(
            family_estimator, family_info, family_predictions[0], family_probability_row,
        )
        family_probability_pairs = _probability_pairs(family_estimator, family_info, family_probability_row) if family_probability_row is not None else []

    return {
        "prediction": prediction,
        "raw_binary_prediction": raw_prediction,
        "prediction_confidence": binary_confidence,
        "confidence": binary_confidence,
        "probabilities": binary_probability_pairs,
        "family_probabilities": family_probability_pairs,
        "attack_probability": attack_probability,
        "triage_priority": _triage_label(attack_probability),
        "triage_policy": _triage_policy,
        "family": family,
        "family_confidence": family_confidence,
        "dataset_source": dataset_source or "Not specified",
        "severity_score": None,
        "severity_level": None,
        "evidence": [],
        "processing_ms": None,
        "model_label": binary_info["label"],
        "family_model_label": family_info["label"] if family_info else None,
        "feature_count": len(frame.columns),
        "note": (
            "Triage priority uses the notebook's provisional probability thresholds. Severity score/evidence are not fabricated. "
            + ("No fitted preprocessing object was detected for the binary classifier. If training used the standardized Prepared training matrix, include the same fitted preprocessing object in soc_model.joblib before trusting raw-input predictions." if binary_info.get("preprocessing_status") == "none_detected" else "Preprocessing is detected in the saved estimator/bundle.")
        ),
    }



def _binary_metrics(comparable: list[tuple[bool, bool]], target_column: str, scope_note: str) -> dict[str, Any] | None:
    if not comparable:
        return None
    tp = sum(actual and predicted for actual, predicted in comparable)
    tn = sum((not actual) and (not predicted) for actual, predicted in comparable)
    fp = sum((not actual) and predicted for actual, predicted in comparable)
    fn = sum(actual and (not predicted) for actual, predicted in comparable)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "target_column": target_column,
        "rows_evaluated": len(comparable),
        "accuracy": (tp + tn) / len(comparable),
        "precision_attack": precision,
        "recall_attack": recall,
        "f1_attack": (2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
        "true_positive": tp, "true_negative": tn,
        "false_positive": fp, "false_negative": fn,
        "scope_note": scope_note,
    }

def _uploaded_size(upload: Any) -> int:
    try:
        upload.stream.seek(0, 2)
        size = int(upload.stream.tell())
        upload.stream.seek(0)
        return size
    except Exception:
        return 0


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "File is too large. Maximum model size is 200 MB and maximum CSV size is 25 MB."}), 413


@app.get("/api/health")
def health():
    return jsonify(_serialize_model_info())


@app.post("/api/upload-model")
def upload_model():
    global _last_load_error
    upload = request.files.get("model")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a .joblib file first."}), 400
    if not upload.filename.lower().endswith((".joblib", ".pkl", ".pickle")):
        return jsonify({"error": "Please upload a .joblib, .pkl, or .pickle model bundle."}), 400
    if _uploaded_size(upload) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "The model file exceeds the 200 MB upload limit."}), 413

    safe_name = secure_filename(upload.filename) or "soc_model.joblib"
    destination = UPLOAD_DIR / safe_name
    try:
        upload.save(destination)
        info = _load_model(destination)
        return jsonify({"message": "Model loaded successfully.", "model": info})
    except Exception as exc:
        _last_load_error = str(exc)
        return jsonify({"error": f"Could not load this model: {exc}"}), 400


@app.post("/api/predict")
def predict():
    body = request.get_json(silent=True) or {}
    model_id = str(body.get("model_id", ""))
    values = body.get("features")
    if not isinstance(values, dict):
        return jsonify({"error": "Send feature values as a JSON object."}), 400
    try:
        with _state_lock:
            if _bundle is None:
                raise ValueError("Load your soc_model.joblib file first.")
            info = _model_record(model_id)
            estimator = _find_estimator(_bundle, info["path"])
        frame = _frame_from_mapping(info, values)
        model_input = _model_input(_bundle, estimator, info, frame)
        output = _prediction_payload(estimator, info, model_input)
        output.update({"model_id": model_id, "model_label": info["label"], "feature_count": len(frame.columns)})
        return jsonify(output)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/triage")
def triage():
    body = request.get_json(silent=True) or {}
    values = body.get("features")
    if not isinstance(values, dict):
        return jsonify({"error": "Send the seven SOC feature values as a JSON object."}), 400
    source = body.get("dataset_source")
    if source not in {None, "", "CIC-IDS2017", "UNSW-NB15"}:
        return jsonify({"error": "Dataset source must be CIC-IDS2017 or UNSW-NB15."}), 400
    started = time.perf_counter()
    try:
        with _state_lock:
            result = _run_triage(values, source)
        result["processing_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/predict-csv")
def predict_csv():
    upload = request.files.get("file")
    model_id = str(request.form.get("model_id", ""))
    dataset_source = request.form.get("dataset_source")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a CSV file first."}), 400
    if not upload.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please upload a .csv file."}), 400
    if _uploaded_size(upload) > MAX_CSV_BYTES:
        return jsonify({"error": "The CSV exceeds the 25 MB upload limit."}), 413
    try:
        with _state_lock:
            if _bundle is None:
                raise ValueError("Load your soc_model.joblib file first.")
        data = pd.read_csv(upload, nrows=MAX_BATCH_ROWS + 1)
        data = data.dropna(how="all").reset_index(drop=True)
        if data.empty:
            raise ValueError("The CSV has no data rows.")
        if len(data) > MAX_BATCH_ROWS:
            raise ValueError(f"The tester currently limits batch predictions to {MAX_BATCH_ROWS:,} rows.")

        if model_id == "soc_triage":
            missing = [name for name in SOC_FEATURES if name not in data.columns]
            if missing:
                raise ValueError("CSV is missing the expected SOC feature columns: " + ", ".join(missing))
            source_col = data["dataset_source"] if "dataset_source" in data.columns else None
            rows = []
            for index, (_, record) in enumerate(data.iterrows()):
                row_values = {name: record[name] for name in SOC_FEATURES}
                row_source = str(source_col.iloc[index]) if source_col is not None and pd.notna(source_col.iloc[index]) else dataset_source
                result = _run_triage(row_values, row_source)
                result["row"] = index + 1
                rows.append(result)

            # If the uploaded CSV includes a known binary ground-truth column,
            # calculate metrics against it. These metrics describe only this file.
            target_column = "is_attack" if "is_attack" in data.columns else ("binary_label" if "binary_label" in data.columns else None)
            metrics = None
            per_dataset_metrics = {}
            scope_note = "Metrics describe only the uploaded rows. Use a held-out test split for meaningful evaluation; results on training rows are not test performance."
            if target_column:
                comparable = []
                for index, (_, record) in enumerate(data.iterrows()):
                    truth = _is_attack_label(record[target_column])
                    predicted = _is_attack_label(rows[index]["prediction"])
                    if truth is not None and predicted is not None:
                        comparable.append((truth, predicted))
                metrics = _binary_metrics(comparable, target_column, scope_note)

                if "dataset_source" in data.columns:
                    for source, source_frame in data.groupby("dataset_source", dropna=False):
                        group_pairs = []
                        for source_index, record in source_frame.iterrows():
                            truth = _is_attack_label(record[target_column])
                            predicted = _is_attack_label(rows[int(source_index)]["prediction"])
                            if truth is not None and predicted is not None:
                                group_pairs.append((truth, predicted))
                        group_metrics = _binary_metrics(group_pairs, target_column, f"Uploaded rows for dataset source {source} only.")
                        if group_metrics is not None:
                            per_dataset_metrics[str(source) if pd.notna(source) else "Unknown"] = group_metrics
            return jsonify({
                "model_label": "SOC triage (binary + family)",
                "rows_processed": len(rows),
                "input_columns": list(SOC_FEATURES),
                "rows": rows,
                "label_column_available": target_column is not None,
                "metrics": metrics,
                "per_dataset_metrics": per_dataset_metrics,
            })

        with _state_lock:
            info = _model_record(model_id)
            estimator = _find_estimator(_bundle, info["path"])
        input_frame = _frame_from_csv(info, data)
        model_input = _model_input(_bundle, estimator, info, input_frame)
        predictions, probability_matrix = _predict(estimator, model_input)
        rows = []
        for index, prediction in enumerate(predictions):
            row_result: dict[str, Any] = {"row": index + 1, "prediction": _safe_scalar(prediction), "confidence": None, "probabilities": []}
            if probability_matrix is not None and probability_matrix.ndim == 2 and index < len(probability_matrix):
                pairs = _probability_pairs(estimator, info, probability_matrix[index])
                row_result["probabilities"] = pairs
                row_result["confidence"] = _class_confidence(estimator, info, prediction, probability_matrix[index])
            rows.append(row_result)
        return jsonify({
            "model_label": info["label"],
            "rows_processed": len(rows),
            "input_columns": list(input_frame.columns),
            "rows": rows,
            "label_column_available": bool(set(data.columns).intersection({"binary_label", "is_attack"})),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# Auto-load the model when it exists in backend/models/soc_model.joblib.
if DEFAULT_MODEL_PATH.exists():
    try:
        _load_model(DEFAULT_MODEL_PATH)
    except Exception as startup_error:
        _last_load_error = str(startup_error)
        print(f"[SOC Model Tester] Could not auto-load {DEFAULT_MODEL_PATH.name}: {startup_error}")


if __name__ == "__main__":
    # Keep the development server bound to localhost. Don't expose joblib loading publicly.
    app.run(host="127.0.0.1", port=5000, debug=False)

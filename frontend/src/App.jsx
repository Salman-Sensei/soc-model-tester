import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, AlertCircle, ArrowDownToLine, ArrowUpFromLine, CheckCircle2,
  ChevronDown, ChevronUp, Cpu, FileSpreadsheet, FileUp, Fingerprint,
  FlaskConical, Info, Network, RotateCcw, ShieldAlert, ShieldCheck,
  SlidersHorizontal, Sparkles, UploadCloud, XCircle,
} from 'lucide-react';

const SOC_FEATURES = [
  'flow_duration_seconds',
  'src_packets',
  'dst_packets',
  'src_bytes',
  'dst_bytes',
  'src_mean_packet_bytes',
  'dst_mean_packet_bytes',
];

const BENIGN_EXAMPLE = {
  flow_duration_seconds: '0.031226',
  src_packets: '2',
  dst_packets: '2',
  src_bytes: '68',
  dst_bytes: '380',
  src_mean_packet_bytes: '34',
  dst_mean_packet_bytes: '190',
};

const ATTACK_EXAMPLE = {
  flow_duration_seconds: '99.951883',
  src_packets: '9',
  dst_packets: '7',
  src_bytes: '317',
  dst_bytes: '11595',
  src_mean_packet_bytes: '35.222222',
  dst_mean_packet_bytes: '1656.428571',
};

const EMPTY_INFO = {
  loaded: false, filename: null, models: [], metadata: {}, model_count: 0,
  feature_schema: SOC_FEATURES, triage_policy: {}, triage_supported: false,
};

function prettyBytes(bytes) {
  if (!Number.isFinite(bytes)) return '';
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatProbability(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return 'Not available';
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function classTone(prediction) {
  const normal = String(prediction ?? '').toLowerCase();
  if (/(benign|normal|clean|safe)/.test(normal)) return 'good';
  if (/(attack|malicious|anomaly|intrusion|botnet|dos|ddos|exploit)/.test(normal)) return 'danger';
  return 'neutral';
}

function App() {
  const modelInputRef = useRef(null);
  const csvInputRef = useRef(null);
  const [modelInfo, setModelInfo] = useState(EMPTY_INFO);
  const [selectedModelId, setSelectedModelId] = useState('');
  const [featureValues, setFeatureValues] = useState({});
  const [modelFile, setModelFile] = useState(null);
  const [csvFile, setCsvFile] = useState(null);
  const [mode, setMode] = useState('manual');
  const [uploading, setUploading] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [csvResult, setCsvResult] = useState(null);
  const [error, setError] = useState('');
  const [showMetadata, setShowMetadata] = useState(false);
  const [showFields, setShowFields] = useState(true);
  const [toast, setToast] = useState('');
  const [datasetSource, setDatasetSource] = useState('UNSW-NB15');
  const isTriageMode = selectedModelId === 'soc_triage';

  const selectedModel = useMemo(() => {
    if (selectedModelId === 'soc_triage') {
      return {
        id: 'soc_triage', label: 'SOC Triage · Binary + family', role: 'SOC Triage',
        feature_names: SOC_FEATURES, feature_count: SOC_FEATURES.length,
        classes: ['BENIGN', 'ATTACK'], has_predict_proba: true,
        input_note: modelInfo.models.find((model) => model.role === 'Attack vs benign')?.input_note || 'A binary classifier will be selected from the loaded bundle.',
        preprocessing_status: modelInfo.models.find((model) => model.role === 'Attack vs benign')?.preprocessing_status || 'unknown',
      };
    }
    return modelInfo.models.find((model) => model.id === selectedModelId) || modelInfo.models[0] || null;
  }, [modelInfo.models, selectedModelId]);

  function applyModelInfo(info) {
    setModelInfo(info || EMPTY_INFO);
    const models = info?.models || [];
    const nextId = models.length ? 'soc_triage' : '';
    setSelectedModelId(nextId);
    const defaults = {};
    (nextId === 'soc_triage' ? SOC_FEATURES : (models[0]?.feature_names || [])).forEach((name) => { defaults[name] = ''; });
    setFeatureValues(defaults);
    setResult(null);
    setCsvResult(null);
    setError('');
  }

  async function refreshHealth() {
    try {
      const response = await fetch('/api/health');
      const data = await response.json();
      if (data.loaded) applyModelInfo(data);
      else if (data.load_error) setError(`A model was found, but it could not be loaded: ${data.load_error}`);
    } catch {
      setError('The Flask API is not reachable yet. Start the backend, then refresh this page.');
    }
  }

  useEffect(() => { refreshHealth(); }, []);

  function chooseModel(modelId) {
    setSelectedModelId(modelId);
    const info = modelInfo.models.find((item) => item.id === modelId);
    const defaults = {};
    (modelId === 'soc_triage' ? SOC_FEATURES : (info?.feature_names || [])).forEach((name) => { defaults[name] = ''; });
    setFeatureValues(defaults);
    setResult(null);
    setCsvResult(null);
    setError('');
  }

  async function uploadModel(file = modelFile) {
    if (!file) {
      setError('Choose your soc_model.joblib file first.');
      return;
    }
    setUploading(true);
    setError('');
    setToast('');
    setResult(null);
    setCsvResult(null);
    const form = new FormData();
    form.append('model', file);
    try {
      const response = await fetch('/api/upload-model', { method: 'POST', body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Model upload failed.');
      applyModelInfo(data.model);
      setToast('Model loaded and inspected successfully.');
      setModelFile(file);
    } catch (err) {
      setError(err.message || 'Could not load the model.');
    } finally {
      setUploading(false);
    }
  }

  function setFeature(name, value) {
    setFeatureValues((current) => ({ ...current, [name]: value }));
  }

  function fillZeros() {
    if (!selectedModel) return;
    const zeros = {};
    selectedModel.feature_names.forEach((name) => { zeros[name] = '0'; });
    setFeatureValues(zeros);
    setToast('Filled with zeros for an integration smoke test. This is not a meaningful security test sample.');
    setError('');
  }

  function loadExample(kind) {
    setFeatureValues(kind === 'attack' ? { ...ATTACK_EXAMPLE } : { ...BENIGN_EXAMPLE });
    setDatasetSource('CIC-IDS2017');
    setResult(null);
    setError('');
    setToast(kind === 'attack'
      ? 'Loaded the labeled DoS Hulk example from your EDA sample.'
      : 'Loaded a labeled benign example from your EDA sample.');
  }

  function clearFields() {
    const empty = {};
    (selectedModel?.feature_names || []).forEach((name) => { empty[name] = ''; });
    setFeatureValues(empty);
    setResult(null);
    setError('');
  }

  async function runSingle(event) {
    event.preventDefault();
    if (!selectedModel) {
      setError('Load a model with a supported classifier first.');
      return;
    }
    setRunning(true);
    setError('');
    setToast('');
    setResult(null);
    const blankFields = selectedModel.feature_names.filter((name) => String(featureValues[name] ?? '').trim() === '');
    if (blankFields.length) {
      setRunning(false);
      setError(`Fill every required feature before running. ${blankFields.length} field(s) are empty.`);
      return;
    }
    try {
      const response = await fetch(isTriageMode ? '/api/triage' : '/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isTriageMode
          ? { features: featureValues, dataset_source: datasetSource }
          : { model_id: selectedModel.id, features: featureValues }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Prediction failed.');
      setResult(data);
    } catch (err) {
      setError(err.message || 'Prediction failed.');
    } finally {
      setRunning(false);
    }
  }

  async function runCsv(event) {
    event.preventDefault();
    if (!selectedModel) {
      setError('Load a model with a supported classifier first.');
      return;
    }
    if (!csvFile) {
      setError('Choose a CSV file first.');
      return;
    }
    setRunning(true);
    setError('');
    setToast('');
    setCsvResult(null);
    const form = new FormData();
    form.append('file', csvFile);
    form.append('model_id', selectedModel.id);
    form.append('dataset_source', datasetSource);
    try {
      const response = await fetch('/api/predict-csv', { method: 'POST', body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'CSV prediction failed.');
      setCsvResult(data);
    } catch (err) {
      setError(err.message || 'CSV prediction failed.');
    } finally {
      setRunning(false);
    }
  }

  const hasModel = modelInfo.loaded && modelInfo.models.length > 0;
  const metadataEntries = Object.entries(modelInfo.metadata || {});

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <main className="workspace">
        <header className="topbar">
          <div className="brand-lockup">
            <div className="brand-mark"><Network size={19} strokeWidth={1.8} /></div>
            <div>
              <div className="brand-name">FIELDNOTE <span>/ SOC LAB</span></div>
              <div className="brand-caption">LOCAL MODEL TEST CONSOLE</div>
            </div>
          </div>
          <div className={`system-chip ${hasModel ? 'online' : ''}`}>
            <span className="status-dot" />
            {hasModel ? 'MODEL READY' : 'AWAITING MODEL'}
          </div>
        </header>

        <section className="hero-row">
          <div className="hero-copy">
            <p className="eyebrow"><span className="eyebrow-line" /> MODEL PLAYGROUND / 01</p>
            <h1>Test your SOC<br /><em>model bundle.</em></h1>
            <p className="hero-description">Load the trained artifact, test the seven shared flow features, and inspect attack probability, family prediction, and provisional triage priority. Everything runs on your machine.</p>
          </div>
          <div className="hero-stamp" aria-hidden="true">
            <div className="stamp-ring"><ShieldCheck size={31} strokeWidth={1.4} /></div>
            <span>LOCAL</span>
            <span>INFERENCE</span>
            <div className="stamp-code">SOC / ML</div>
          </div>
        </section>

        <section className="model-panel panel">
          <div className="section-heading">
            <div className="section-number">01</div>
            <div className="section-title-wrap">
              <h2>Model artifact</h2>
              <p>Start with your <code>soc_model.joblib</code> bundle.</p>
            </div>
            <div className="section-state"><span className={`mini-dot ${hasModel ? 'online' : ''}`} />{hasModel ? 'INSPECTED' : 'NOT LOADED'}</div>
          </div>
          <div className="upload-row">
            <button type="button" className="drop-zone" onClick={() => modelInputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); const file = event.dataTransfer.files?.[0]; if (file) { setModelFile(file); uploadModel(file); } }}>
              <div className="drop-icon"><UploadCloud size={22} /></div>
              <div className="drop-copy">
                <strong>{modelFile?.name || modelInfo.filename || 'Choose a model bundle'}</strong>
                <span>{modelFile ? `${prettyBytes(modelFile.size)} · selected` : 'Click to browse, or drag a file here'}</span>
              </div>
              <span className="file-kind">JOBLIB / PKL</span>
            </button>
            <input ref={modelInputRef} className="visually-hidden" type="file" accept=".joblib,.pkl,.pickle" onChange={(event) => { const file = event.target.files?.[0]; if (file) { setModelFile(file); uploadModel(file); } }} />
            <button type="button" className="primary-button upload-button" onClick={() => uploadModel()} disabled={uploading || !modelFile}>
              {uploading ? <span className="spinner" /> : <ArrowUpFromLine size={16} />}
              {uploading ? 'Inspecting…' : 'Load model'}
            </button>
          </div>
          <div className="panel-footnote"><Info size={14} /> Only load a model file you trust. Joblib files use Python deserialization and are not safe to open from unknown sources.</div>

          {hasModel && (
            <div className="model-summary">
              <div className="summary-stat"><span className="stat-icon"><Cpu size={16} /></span><div><strong>{modelInfo.model_count}</strong><span>DETECTED MODEL{modelInfo.model_count === 1 ? '' : 'S'}</span></div></div>
              <div className="summary-stat"><span className="stat-icon"><Fingerprint size={16} /></span><div><strong>{selectedModel?.feature_count ?? 0}</strong><span>FEATURES IN SELECTED MODEL</span></div></div>
              <div className="summary-stat"><span className="stat-icon"><CheckCircle2 size={16} /></span><div><strong>{metadataEntries.length}</strong><span>CONFIG ITEMS FOUND</span></div></div>
              <button type="button" className="text-button metadata-toggle" onClick={() => setShowMetadata((value) => !value)}>
                Bundle details {showMetadata ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
              </button>
            </div>
          )}
          {hasModel && showMetadata && (
            <div className="metadata-block">
              <div className="metadata-title">DETECTED CLASSIFIERS</div>
              <div className="classifier-list">
                {modelInfo.models.map((model) => (
                  <div className="classifier-item" key={model.id}>
                    <span className="classifier-dot" />
                    <div><strong>{model.role}</strong><span>{model.label}</span></div>
                    <small>{model.feature_count} features</small>
                  </div>
                ))}
              </div>
              <div className="metadata-title metadata-second-title">BENIGN PERCENTILES / SEVERITY SETTINGS</div>
              {metadataEntries.length ? <pre className="metadata-json">{JSON.stringify(modelInfo.metadata, null, 2)}</pre> : <p className="muted-note">No percentile or severity keys were automatically identified. The bundle may use different key names.</p>}
            </div>
          )}
        </section>

        <section className="test-panel panel">
          <div className="section-heading">
            <div className="section-number">02</div>
            <div className="section-title-wrap">
              <h2>Run a test</h2>
              <p>Enter one sample or test a CSV batch.</p>
            </div>
            <div className="segmented-control" role="tablist" aria-label="Test input mode">
              <button type="button" role="tab" aria-selected={mode === 'manual'} className={mode === 'manual' ? 'active' : ''} onClick={() => { setMode('manual'); setError(''); }}>Single sample</button>
              <button type="button" role="tab" aria-selected={mode === 'csv'} className={mode === 'csv' ? 'active' : ''} onClick={() => { setMode('csv'); setError(''); }}>CSV batch</button>
            </div>
          </div>

          {!hasModel ? (
            <div className="empty-state">
              <div className="empty-icon"><FlaskConical size={23} /></div>
              <h3>Your test bench is ready.</h3>
              <p>Load the model bundle above to inspect its classifiers and generate the matching input form.</p>
            </div>
          ) : (
            <>
              <div className="model-select-row">
                <label htmlFor="classifier-select">CLASSIFIER</label>
                <div className="select-shell">
                  <select id="classifier-select" value={selectedModel?.id || ''} onChange={(event) => chooseModel(event.target.value)}>
                    <option value="soc_triage">SOC triage · attack + family</option>
                    {modelInfo.models.map((model) => <option value={model.id} key={model.id}>{model.role} · {model.label}</option>)}
                  </select>
                  <ChevronDown size={16} />
                </div>
              </div>

              {mode === 'manual' ? (
                <form onSubmit={runSingle}>
                  {isTriageMode && (
                    <div className="source-row">
                      <label htmlFor="dataset-source">DATASET SOURCE</label>
                      <div className="select-shell source-select">
                        <select id="dataset-source" value={datasetSource} onChange={(event) => setDatasetSource(event.target.value)}>
                          <option value="CIC-IDS2017">CIC-IDS2017</option>
                          <option value="UNSW-NB15">UNSW-NB15</option>
                        </select>
                        <ChevronDown size={16} />
                      </div>
                      <span>Used for audit context. Inputs remain the seven shared flow features.</span>
                    </div>
                  )}
                  {selectedModel?.preprocessing_status === 'none_detected' && (
                    <div className="preprocessing-warning"><AlertCircle size={16} /><span><strong>Preprocessing check:</strong> no fitted scaler/preprocessor was detected. Your notebook shows standardized training inputs. If the saved classifiers were trained on that transformed matrix, the matching fitted preprocessing object must be included in the joblib bundle for raw flow values to be scored correctly.</span></div>
                  )}
                  <div className="feature-heading">
                    <div><h3>Feature values</h3><p>{selectedModel?.feature_count || 0} expected input fields{isTriageMode ? ', in the canonical SOC schema order.' : ', in model feature order.'}</p></div>
                    <div className="feature-actions">
                      {isTriageMode && <>
                        <button type="button" className="text-button" onClick={() => loadExample('benign')}>Benign sample</button>
                        <button type="button" className="text-button" onClick={() => loadExample('attack')}>Attack sample</button>
                      </>}
                      <button type="button" className="text-button" onClick={fillZeros} title="Only use this to check that model loading and prediction run end-to-end">Fill zeros</button>
                      <button type="button" className="text-button" onClick={clearFields}><RotateCcw size={13} /> Clear</button>
                      <button type="button" className="text-button" onClick={() => setShowFields((value) => !value)}>{showFields ? 'Collapse' : 'Expand'} {showFields ? <ChevronUp size={13} /> : <ChevronDown size={13} />}</button>
                    </div>
                  </div>
                  {selectedModel?.feature_names?.length ? (
                    showFields && <div className="feature-grid">
                      {selectedModel.feature_names.map((name, index) => (
                        <label className="feature-field" key={`${selectedModel.id}-${name}`}>
                          <span><b>{String(index + 1).padStart(2, '0')}</b>{name}</span>
                          <input
                            value={featureValues[name] ?? ''}
                            onChange={(event) => setFeature(name, event.target.value)}
                            placeholder="Enter value"
                            autoComplete="off"
                            spellCheck="false"
                          />
                        </label>
                      ))}
                    </div>
                  ) : (
                    <div className="schema-warning"><AlertCircle size={17} /><div><strong>Feature schema unavailable</strong><p>This classifier does not expose its input feature names/count. Use CSV mode or inspect the training code to confirm the expected input structure.</p></div></div>
                  )}
                  <div className="run-row">
                    <div className="run-note"><ShieldAlert size={15} /><span>Use values in the same units and order as the training data.</span></div>
                    <button className="primary-button run-button" disabled={running || !selectedModel?.feature_names?.length} type="submit">
                      {running ? <span className="spinner" /> : <Activity size={16} />}
                      {running ? 'Running inference…' : 'Run prediction'}
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={runCsv} className="csv-form">
                  <button type="button" className={`csv-drop ${csvFile ? 'has-file' : ''}`} onClick={() => csvInputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); const file = event.dataTransfer.files?.[0]; if (file) setCsvFile(file); }}>
                    <span className="csv-icon"><FileSpreadsheet size={23} /></span>
                    <strong>{csvFile?.name || 'Choose a CSV dataset'}</strong>
                    <span>{csvFile ? `${prettyBytes(csvFile.size)} · ready to process` : 'CSV should contain the seven SOC feature columns'}</span>
                    <span className="csv-browse"><FileUp size={15} /> Browse CSV</span>
                  </button>
                  <input ref={csvInputRef} className="visually-hidden" type="file" accept=".csv,text/csv" onChange={(event) => setCsvFile(event.target.files?.[0] || null)} />
                  <div className="csv-guidance">
                    <div><CheckCircle2 size={15} /><span>Known label/audit columns stay out of the model inputs.</span></div>
                    <div><CheckCircle2 size={15} /><span>Batch limit: 5,000 rows per run.</span></div>
                    <div><AlertCircle size={15} /><span>The seven canonical SOC columns are selected by name, not CSV order.</span></div>
                  </div>
                  <div className="run-row">
                    <div className="run-note"><Info size={15} /><span>Use a small, representative sample first.</span></div>
                    <button className="primary-button run-button" disabled={running || !csvFile} type="submit">
                      {running ? <span className="spinner" /> : <Activity size={16} />}
                      {running ? 'Scoring rows…' : 'Run CSV test'}
                    </button>
                  </div>
                </form>
              )}
            </>
          )}
        </section>

        {error && <div className="message error-message"><XCircle size={17} /><span>{error}</span><button type="button" aria-label="Dismiss error" onClick={() => setError('')}><XCircle size={15} /></button></div>}
        {toast && <div className="message success-message"><CheckCircle2 size={17} /><span>{toast}</span><button type="button" aria-label="Dismiss message" onClick={() => setToast('')}><XCircle size={15} /></button></div>}

        {result && (
          <section className="results-panel panel" aria-live="polite">
            <div className="section-heading results-heading">
              <div className="section-number">03</div>
              <div className="section-title-wrap"><h2>Prediction result</h2><p>{result.model_label}</p></div>
              <span className="result-status"><CheckCircle2 size={14} /> INFERENCE COMPLETE</span>
            </div>
            <div className="prediction-card">
              <div className="prediction-main">
                <div className="prediction-label">PREDICTED CLASS</div>
                <div className={`prediction-value ${classTone(result.prediction)}`}>{String(result.prediction)}</div>
                <div className="prediction-caption">Output returned by the selected classifier</div>
              </div>
              <div className="confidence-box">
                <span>{result.triage_priority ? 'P(ATTACK)' : 'TOP CLASS CONFIDENCE'}</span>
                <strong>{formatProbability(result.triage_priority ? result.attack_probability : result.confidence)}</strong>
                <div className="confidence-track"><div style={{ width: `${Math.max(0, Math.min(100, ((result.triage_priority ? result.attack_probability : result.confidence) || 0) * 100))}%` }} /></div>
                <small>{result.triage_priority ? 'Attack probability from the binary classifier.' : 'Only shown when the estimator supports predict_proba.'}</small>
              </div>
            </div>
            {result.triage_priority && (
              <div className="triage-detail-grid">
                <div><span>PROVISIONAL TRIAGE PRIORITY</span><strong className={result.triage_priority === 'HIGH_PRIORITY_REVIEW' ? 'danger-text' : result.triage_priority === 'LOW_PRIORITY' ? 'good-text' : ''}>{result.triage_priority.replaceAll('_', ' ')}</strong></div>
                <div><span>ATTACK FAMILY</span><strong>{result.family || (result.prediction === 'BENIGN' ? 'Not applicable' : 'Unavailable')}</strong><small>{result.family_confidence !== null && result.family_confidence !== undefined ? `${formatProbability(result.family_confidence)} family confidence` : 'No family probability available'}</small></div>
                <div><span>DATASET SOURCE</span><strong>{result.dataset_source || 'Not specified'}</strong><small>For audit context only</small></div>
              </div>
            )}
            {result.probabilities?.length > 0 && (
              <div className="probability-section">
                <div className="results-subhead"><h3>Class probabilities</h3><span>{result.probabilities.length} classes</span></div>
                <div className="probability-list">
                  {result.probabilities.map((item) => (
                    <div className="probability-row" key={String(item.class)}>
                      <span className="probability-class">{String(item.class)}</span>
                      <div className="probability-track"><div style={{ width: `${Math.max(0, Math.min(100, item.probability * 100))}%` }} /></div>
                      <span className="probability-value">{formatProbability(item.probability)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {result.family_probabilities?.length > 0 && (
              <div className="probability-section">
                <div className="results-subhead"><h3>Attack family probabilities</h3><span>{result.family_probabilities.length} classes</span></div>
                <div className="probability-list">
                  {result.family_probabilities.map((item) => (
                    <div className="probability-row" key={String(item.class)}>
                      <span className="probability-class">{String(item.class)}</span>
                      <div className="probability-track"><div style={{ width: `${Math.max(0, Math.min(100, item.probability * 100))}%` }} /></div>
                      <span className="probability-value">{formatProbability(item.probability)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="result-foot"><Info size={14} /><span>{result.note || "The UI displays the estimator's outputs as-is. It does not invent a severity score or incident evidence."}</span></div>
          </section>
        )}

        {csvResult && (
          <section className="results-panel panel" aria-live="polite">
            <div className="section-heading results-heading">
              <div className="section-number">03</div>
              <div className="section-title-wrap"><h2>Batch results</h2><p>{csvResult.model_label} · {csvResult.rows_processed.toLocaleString()} rows scored</p></div>
              <button type="button" className="text-button export-button" onClick={() => {
                const header = ['row', 'prediction', 'confidence', 'attack_probability', 'triage_priority', 'family', 'family_confidence', 'dataset_source'];
                const quote = (value) => {
                  const raw = value === null || value === undefined ? '' : String(value);
                  return `"${raw.replaceAll('"', '""')}"`;
                };
                const lines = [header.join(','), ...csvResult.rows.map((row) => [
                  row.row, quote(row.prediction), row.confidence ?? row.prediction_confidence ?? '',
                  row.attack_probability ?? '', quote(row.triage_priority || ''), quote(row.family || ''),
                  row.family_confidence ?? '', quote(row.dataset_source || ''),
                ].join(','))];
                const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' }));
                const link = document.createElement('a'); link.href = url; link.download = 'soc-predictions.csv'; link.click(); URL.revokeObjectURL(url);
              }}><ArrowDownToLine size={15} /> Export results</button>
            </div>
            <div className="batch-summary">
              <div><span>ROWS PROCESSED</span><strong>{csvResult.rows_processed.toLocaleString()}</strong></div>
              <div><span>INPUT FEATURES</span><strong>{csvResult.input_columns.length}</strong></div>
              <div><span>CLASSIFIER</span><strong>{isTriageMode ? 'SOC Triage' : (selectedModel?.role || 'Model')}</strong></div>
            </div>
            {csvResult.metrics && (
              <div className="evaluation-block">
                <div className="results-subhead"><h3>Evaluation against uploaded labels</h3><span>{csvResult.metrics.rows_evaluated.toLocaleString()} rows · {csvResult.metrics.target_column}</span></div>
                <div className="evaluation-grid">
                  <div><span>ACCURACY</span><strong>{formatProbability(csvResult.metrics.accuracy)}</strong></div>
                  <div><span>ATTACK PRECISION</span><strong>{formatProbability(csvResult.metrics.precision_attack)}</strong></div>
                  <div><span>ATTACK RECALL</span><strong>{formatProbability(csvResult.metrics.recall_attack)}</strong></div>
                  <div><span>ATTACK F1</span><strong>{formatProbability(csvResult.metrics.f1_attack)}</strong></div>
                </div>
                <div className="confusion-row">
                  <span>TP <b>{csvResult.metrics.true_positive}</b></span>
                  <span>TN <b>{csvResult.metrics.true_negative}</b></span>
                  <span>FP <b>{csvResult.metrics.false_positive}</b></span>
                  <span>FN <b>{csvResult.metrics.false_negative}</b></span>
                </div>
                <p className="metrics-note">{csvResult.metrics.scope_note}</p>
              </div>
            )}
            {Object.keys(csvResult.per_dataset_metrics || {}).length > 0 && (
              <div className="evaluation-block per-dataset-block">
                <div className="results-subhead"><h3>Metrics by dataset source</h3><span>Useful for spotting dataset shift</span></div>
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>DATASET SOURCE</th><th>ROWS</th><th>ACCURACY</th><th>ATTACK PRECISION</th><th>ATTACK RECALL</th><th>ATTACK F1</th></tr></thead>
                    <tbody>
                      {Object.entries(csvResult.per_dataset_metrics).map(([source, metrics]) => (
                        <tr key={source}>
                          <td>{source}</td><td>{metrics.rows_evaluated.toLocaleString()}</td>
                          <td>{formatProbability(metrics.accuracy)}</td><td>{formatProbability(metrics.precision_attack)}</td>
                          <td>{formatProbability(metrics.recall_attack)}</td><td>{formatProbability(metrics.f1_attack)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            <div className="table-wrap">
              <table>
                <thead><tr><th>ROW</th><th>PREDICTION</th><th>P(ATTACK) / CONFIDENCE</th>{csvResult.model_label === 'SOC triage (binary + family)' && <><th>TRIAGE</th><th>FAMILY</th><th>DATASET</th></>}<th>PROBABILITY DETAIL</th></tr></thead>
                <tbody>
                  {csvResult.rows.slice(0, 150).map((row) => (
                    <tr key={row.row}>
                      <td className="row-number">{String(row.row).padStart(3, '0')}</td>
                      <td><span className={`class-chip ${classTone(row.prediction)}`}>{String(row.prediction)}</span></td>
                      <td>{formatProbability(row.attack_probability ?? row.confidence)}</td>
                      {csvResult.model_label === 'SOC triage (binary + family)' && <>
                        <td><span className={`class-chip ${row.triage_priority === 'HIGH_PRIORITY_REVIEW' ? 'danger' : row.triage_priority === 'LOW_PRIORITY' ? 'good' : ''}`}>{String(row.triage_priority || 'N/A').replaceAll('_', ' ')}</span></td>
                        <td>{row.family || 'Not applicable'}</td>
                        <td>{row.dataset_source || 'Not specified'}</td>
                      </>}
                      <td>{row.probabilities?.length ? row.probabilities.map((item) => `${item.class}: ${formatProbability(item.probability)}`).join(' · ') : 'Not available'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {csvResult.rows.length > 150 && <p className="table-limit-note">Showing first 150 rows in the preview. Export includes all {csvResult.rows.length.toLocaleString()} rows.</p>}
            <div className="result-foot"><Info size={14} /><span>CSV output contains predictions and confidence. Original input rows are not modified.</span></div>
          </section>
        )}

        <footer className="page-footer">
          <div className="footer-left"><span className="footer-mark">FN</span><span>FIELDNOTE / SOC LAB</span></div>
          <span>LOCAL FIRST · NO DATA SENT TO A THIRD-PARTY API</span>
          <span className="footer-version">BUILD 01.00</span>
        </footer>
      </main>
    </div>
  );
}

export default App;

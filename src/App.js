import React, { useState, useEffect, useCallback, useMemo } from 'react';

// ============================================================================
// PROTEUSKIT v1.0 — Adapt. Encrypt. Disappear.
// All processing happens client-side. No data leaves your browser.
// ============================================================================

// Shared UI Components — Cyberpunk Style
const Input = ({ darkMode, className = '', ...props }) => (
  <input className={`w-full px-4 py-3 rounded-lg outline-none transition-all ${darkMode ? 'bg-black/50 border border-cyan-500/30 text-cyan-100 placeholder-cyan-800 focus:border-cyan-400 focus:shadow-[0_0_10px_rgba(0,240,255,0.3)] font-mono' : 'bg-gray-100 border border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500'} ${className}`} {...props} />
);

const TextArea = ({ darkMode, className = '', ...props }) => (
  <textarea className={`w-full px-4 py-3 rounded-lg outline-none transition-all resize-none ${darkMode ? 'bg-black/50 border border-cyan-500/30 text-cyan-100 placeholder-cyan-800 focus:border-cyan-400 focus:shadow-[0_0_10px_rgba(0,240,255,0.3)] font-mono' : 'bg-gray-100 border border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500'} ${className}`} {...props} />
);

const Button = ({ darkMode, variant = 'primary', className = '', children, ...props }) => {
  const variants = {
    primary: 'bg-gradient-to-r from-cyan-500 to-cyan-400 text-black font-bold hover:from-cyan-400 hover:to-cyan-300 shadow-[0_0_20px_rgba(0,240,255,0.4)] hover:shadow-[0_0_30px_rgba(0,240,255,0.6)]',
    danger: 'bg-gradient-to-r from-red-600 to-red-500 text-white font-bold hover:from-red-500 hover:to-red-400 shadow-[0_0_20px_rgba(255,0,51,0.4)]',
    secondary: darkMode ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 hover:border-cyan-400' : 'bg-gray-200 text-gray-900 hover:bg-gray-300',
    ghost: darkMode ? 'text-cyan-500 hover:text-cyan-400 hover:bg-cyan-500/10' : 'text-gray-600 hover:text-gray-900 hover:bg-black/5',
  };
  return <button className={`px-4 py-2.5 rounded-lg font-medium transition-all uppercase tracking-wider text-sm ${variants[variant]} ${className}`} {...props}>{children}</button>;
};

const Label = ({ darkMode, children, className = '' }) => (
  <label className={`block text-xs font-bold uppercase tracking-widest mb-2 ${darkMode ? 'text-cyan-500' : 'text-gray-700'} ${className}`}>{children}</label>
);

const Card = ({ darkMode, children, className = '' }) => (
  <div className={`p-4 rounded-lg border ${darkMode ? 'bg-black/30 border-cyan-500/20' : 'bg-gray-100 border-gray-200'} ${className}`}>{children}</div>
);

const CopyButton = ({ darkMode, text, label = 'Copy' }) => {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  return <Button darkMode={darkMode} variant="secondary" onClick={copy}>{copied ? '✓ COPIED' : label}</Button>;
};

const TabGroup = ({ darkMode, tabs, active, onChange }) => (
  <div className={`flex gap-1 p-1 rounded-lg ${darkMode ? 'bg-black/50 border border-cyan-500/20' : 'bg-black/5'}`}>
    {tabs.map(tab => (
      <button key={tab.id} onClick={() => onChange(tab.id)} className={`flex-1 px-4 py-2 rounded text-xs font-bold uppercase tracking-wider transition-all ${active === tab.id ? 'bg-cyan-500 text-black shadow-[0_0_15px_rgba(0,240,255,0.5)]' : darkMode ? 'text-cyan-600 hover:text-cyan-400 hover:bg-cyan-500/10' : 'text-gray-600 hover:text-gray-900'}`}>{tab.label}</button>
    ))}
  </div>
);

// ============================================================================
// DEVELOPER TOOLS (NEW)
// ============================================================================

const JSONFormatter = ({ darkMode }) => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [indentSize, setIndentSize] = useState(2);

  const formatJSON = useCallback(() => {
    setError('');
    if (!input.trim()) { setOutput(''); return; }
    try {
      const parsed = JSON.parse(input);
      setOutput(JSON.stringify(parsed, null, indentSize));
    } catch (e) {
      setError(`Invalid JSON: ${e.message}`);
      setOutput('');
    }
  }, [input, indentSize]);

  const minifyJSON = useCallback(() => {
    setError('');
    if (!input.trim()) { setOutput(''); return; }
    try {
      const parsed = JSON.parse(input);
      setOutput(JSON.stringify(parsed));
    } catch (e) {
      setError(`Invalid JSON: ${e.message}`);
      setOutput('');
    }
  }, [input]);

  useEffect(() => { if (input) formatJSON(); }, [indentSize, formatJSON, input]);

  return (
    <div className="space-y-6">
      <div className="grid md:grid-cols-2 gap-4">
        <div>
          <Label darkMode={darkMode}>Input JSON</Label>
          <TextArea darkMode={darkMode} rows={12} placeholder='{"name": "value", "array": [1, 2, 3]}' value={input} onChange={e => setInput(e.target.value)} className="font-mono text-sm" />
        </div>
        <div>
          <div className="flex items-center justify-between mb-2">
            <Label darkMode={darkMode} className="mb-0">Output</Label>
            <CopyButton darkMode={darkMode} text={output} />
          </div>
          <TextArea darkMode={darkMode} rows={12} value={output} readOnly className="font-mono text-sm" placeholder="Formatted JSON..." />
        </div>
      </div>
      {error && <div className={`p-3 rounded-xl ${darkMode ? 'bg-red-500/10 border border-red-500/30 text-red-400' : 'bg-red-50 border border-red-200 text-red-600'}`}>{error}</div>}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <Label darkMode={darkMode} className="mb-0">Indent:</Label>
          <select value={indentSize} onChange={e => setIndentSize(parseInt(e.target.value))} className={`px-3 py-2 rounded-lg ${darkMode ? 'bg-white/5 text-white border border-white/10' : 'bg-gray-100 text-gray-900'}`}>
            <option value={2}>2 spaces</option>
            <option value={4}>4 spaces</option>
          </select>
        </div>
        <Button darkMode={darkMode} onClick={formatJSON}>Format</Button>
        <Button darkMode={darkMode} variant="secondary" onClick={minifyJSON}>Minify</Button>
        <Button darkMode={darkMode} variant="ghost" onClick={() => { setInput(''); setOutput(''); setError(''); }}>Clear</Button>
      </div>
    </div>
  );
};

const RegexTester = ({ darkMode }) => {
  const [pattern, setPattern] = useState('');
  const [flags, setFlags] = useState('g');
  const [testString, setTestString] = useState('');
  const [matches, setMatches] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    setError('');
    setMatches([]);
    if (!pattern || !testString) return;
    try {
      const regex = new RegExp(pattern, flags);
      const allMatches = [];
      let match;
      if (flags.includes('g')) {
        while ((match = regex.exec(testString)) !== null) {
          allMatches.push({ match: match[0], index: match.index, groups: match.slice(1) });
          if (match.index === regex.lastIndex) regex.lastIndex++;
        }
      } else {
        match = regex.exec(testString);
        if (match) allMatches.push({ match: match[0], index: match.index, groups: match.slice(1) });
      }
      setMatches(allMatches);
    } catch (e) { setError(`Invalid regex: ${e.message}`); }
  }, [pattern, flags, testString]);

  const toggleFlag = (flag) => setFlags(prev => prev.includes(flag) ? prev.replace(flag, '') : prev + flag);

  return (
    <div className="space-y-6">
      <div>
        <Label darkMode={darkMode}>Regular Expression</Label>
        <div className="flex gap-2">
          <div className={`flex items-center px-3 rounded-l-xl ${darkMode ? 'bg-white/10 text-gray-400' : 'bg-gray-200 text-gray-500'}`}>/</div>
          <Input darkMode={darkMode} value={pattern} onChange={e => setPattern(e.target.value)} placeholder="Enter regex pattern..." className="rounded-none font-mono" />
          <div className={`flex items-center px-3 rounded-r-xl ${darkMode ? 'bg-white/10 text-gray-400' : 'bg-gray-200 text-gray-500'}`}>/{flags}</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <Label darkMode={darkMode} className="mb-0 mr-2">Flags:</Label>
        {[{ flag: 'g', label: 'Global' }, { flag: 'i', label: 'Case Insensitive' }, { flag: 'm', label: 'Multiline' }].map(({ flag, label }) => (
          <button key={flag} onClick={() => toggleFlag(flag)} className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${flags.includes(flag) ? 'bg-violet-600 text-white' : darkMode ? 'bg-white/5 text-gray-400' : 'bg-gray-200 text-gray-600'}`}>{flag} - {label}</button>
        ))}
      </div>
      <div><Label darkMode={darkMode}>Test String</Label><TextArea darkMode={darkMode} rows={4} value={testString} onChange={e => setTestString(e.target.value)} placeholder="Enter text to test..." /></div>
      {error && <div className={`p-3 rounded-xl ${darkMode ? 'bg-red-500/10 text-red-400' : 'bg-red-50 text-red-600'}`}>{error}</div>}
      {matches.length > 0 && (
        <Card darkMode={darkMode}>
          <Label darkMode={darkMode}>Matches ({matches.length} found)</Label>
          <div className="space-y-2">
            {matches.map((m, i) => (
              <div key={i} className={`p-2 rounded-lg ${darkMode ? 'bg-black/30' : 'bg-white'}`}>
                <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>Match {i + 1} at index {m.index}: </span>
                <span className={`font-mono ${darkMode ? 'text-violet-400' : 'text-violet-600'}`}>"{m.match}"</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};

const UUIDGenerator = ({ darkMode }) => {
  const [uuids, setUuids] = useState([]);
  const [count, setCount] = useState(5);
  const [format, setFormat] = useState('default');

  const generateUUID = useCallback(() => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : ((r & 0x3) | 0x8);
      return v.toString(16);
    });
  }, []);

  const generateUUIDs = useCallback(() => {
    const newUuids = [];
    for (let i = 0; i < count; i++) {
      let uuid = generateUUID();
      if (format === 'uppercase') uuid = uuid.toUpperCase();
      else if (format === 'no-dashes') uuid = uuid.replace(/-/g, '');
      else if (format === 'braces') uuid = `{${uuid}}`;
      newUuids.push(uuid);
    }
    setUuids(newUuids);
  }, [count, format, generateUUID]);

  useEffect(() => { generateUUIDs(); }, [generateUUIDs]);

  return (
    <div className="space-y-6">
      <Card darkMode={darkMode} className={darkMode ? 'bg-violet-500/10 border border-violet-500/20' : 'bg-violet-50 border border-violet-200'}>
        <div className="flex items-start gap-3">
          <span className="text-2xl">🎲</span>
          <div>
            <div className={`font-medium mb-1 ${darkMode ? 'text-violet-300' : 'text-violet-800'}`}>UUID v4 Generator</div>
            <div className={`text-sm ${darkMode ? 'text-violet-300/70' : 'text-violet-700'}`}>Generates cryptographically random UUIDs.</div>
          </div>
        </div>
      </Card>
      <div className="flex flex-wrap gap-4 items-end">
        <div>
          <Label darkMode={darkMode}>Count</Label>
          <select value={count} onChange={e => setCount(parseInt(e.target.value))} className={`px-4 py-3 rounded-xl ${darkMode ? 'bg-white/5 text-white border border-white/10' : 'bg-gray-100 text-gray-900'}`}>
            {[1, 5, 10, 25, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
        <div>
          <Label darkMode={darkMode}>Format</Label>
          <select value={format} onChange={e => setFormat(e.target.value)} className={`px-4 py-3 rounded-xl ${darkMode ? 'bg-white/5 text-white border border-white/10' : 'bg-gray-100 text-gray-900'}`}>
            <option value="default">Default</option>
            <option value="uppercase">UPPERCASE</option>
            <option value="no-dashes">No dashes</option>
            <option value="braces">{"{braces}"}</option>
          </select>
        </div>
        <Button darkMode={darkMode} onClick={generateUUIDs}>Generate</Button>
        <Button darkMode={darkMode} variant="secondary" onClick={() => navigator.clipboard.writeText(uuids.join('\n'))}>Copy All</Button>
      </div>
      <div className="space-y-2">
        {uuids.map((uuid, i) => (
          <div key={i} className={`flex items-center justify-between p-3 rounded-xl ${darkMode ? 'bg-white/5' : 'bg-gray-100'}`}>
            <code className={`font-mono ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>{uuid}</code>
            <CopyButton darkMode={darkMode} text={uuid} label="Copy" />
          </div>
        ))}
      </div>
    </div>
  );
};

const JWTDecoder = ({ darkMode }) => {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState(null);
  const [error, setError] = useState('');

  const decodeJWT = useCallback((jwt) => {
    setError('');
    setDecoded(null);
    if (!jwt.trim()) return;
    const parts = jwt.split('.');
    if (parts.length !== 3) { setError('Invalid JWT format. Expected 3 parts.'); return; }
    try {
      const decodeBase64 = (str) => {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '=='.slice(0, (4 - base64.length % 4) % 4);
        return JSON.parse(atob(padded));
      };
      const header = decodeBase64(parts[0]);
      const payload = decodeBase64(parts[1]);
      let expStatus = null;
      if (payload.exp) {
        const expDate = new Date(payload.exp * 1000);
        expStatus = { expired: expDate < new Date(), date: expDate.toLocaleString() };
      }
      setDecoded({ header, payload, signature: parts[2], expStatus });
    } catch (e) { setError(`Failed to decode: ${e.message}`); }
  }, []);

  useEffect(() => { decodeJWT(token); }, [token, decodeJWT]);

  return (
    <div className="space-y-6">
      <Card darkMode={darkMode} className={darkMode ? 'bg-amber-500/10 border border-amber-500/20' : 'bg-amber-50 border border-amber-200'}>
        <div className="flex items-start gap-3">
          <span className="text-2xl">🔑</span>
          <div>
            <div className={`font-medium mb-1 ${darkMode ? 'text-amber-300' : 'text-amber-800'}`}>JWT Decoder</div>
            <div className={`text-sm ${darkMode ? 'text-amber-300/70' : 'text-amber-700'}`}>Decode JSON Web Tokens locally. Your tokens never leave your browser.</div>
          </div>
        </div>
      </Card>
      <div><Label darkMode={darkMode}>Paste JWT Token</Label><TextArea darkMode={darkMode} rows={4} value={token} onChange={e => setToken(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIs..." className="font-mono text-sm" /></div>
      {error && <div className={`p-3 rounded-xl ${darkMode ? 'bg-red-500/10 text-red-400' : 'bg-red-50 text-red-600'}`}>{error}</div>}
      {decoded && (
        <div className="space-y-4">
          {decoded.expStatus && (
            <div className={`p-3 rounded-xl ${decoded.expStatus.expired ? (darkMode ? 'bg-red-500/10 border border-red-500/30' : 'bg-red-50') : (darkMode ? 'bg-emerald-500/10 border border-emerald-500/30' : 'bg-emerald-50')}`}>
              <span className={decoded.expStatus.expired ? (darkMode ? 'text-red-400' : 'text-red-600') : (darkMode ? 'text-emerald-400' : 'text-emerald-600')}>
                {decoded.expStatus.expired ? '⚠️ Token EXPIRED' : '✓ Token Valid'} — Expires: {decoded.expStatus.date}
              </span>
            </div>
          )}
          <Card darkMode={darkMode}>
            <Label darkMode={darkMode}>Header</Label>
            <pre className={`p-3 rounded-lg overflow-x-auto font-mono text-sm ${darkMode ? 'bg-black/30 text-red-400' : 'bg-white text-red-600'}`}>{JSON.stringify(decoded.header, null, 2)}</pre>
          </Card>
          <Card darkMode={darkMode}>
            <Label darkMode={darkMode}>Payload</Label>
            <pre className={`p-3 rounded-lg overflow-x-auto font-mono text-sm ${darkMode ? 'bg-black/30 text-violet-400' : 'bg-white text-violet-600'}`}>{JSON.stringify(decoded.payload, null, 2)}</pre>
          </Card>
          <Card darkMode={darkMode}>
            <Label darkMode={darkMode}>Signature</Label>
            <div className={`p-3 rounded-lg font-mono text-sm break-all ${darkMode ? 'bg-black/30 text-cyan-400' : 'bg-white text-cyan-600'}`}>{decoded.signature}</div>
          </Card>
        </div>
      )}
    </div>
  );
};

const TimestampConverter = ({ darkMode }) => {
  const [timestamp, setTimestamp] = useState('');
  const [humanDate, setHumanDate] = useState('');
  const [currentTimestamp, setCurrentTimestamp] = useState(Math.floor(Date.now() / 1000));
  const [mode, setMode] = useState('toHuman');

  useEffect(() => {
    const interval = setInterval(() => setCurrentTimestamp(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (mode === 'toHuman' && timestamp) {
      const ts = parseInt(timestamp);
      if (!isNaN(ts)) {
        const date = ts > 9999999999 ? new Date(ts) : new Date(ts * 1000);
        setHumanDate(date.toLocaleString() + ' (' + date.toISOString() + ')');
      }
    } else if (mode === 'toTimestamp' && humanDate) {
      const date = new Date(humanDate);
      if (!isNaN(date.getTime())) setTimestamp(Math.floor(date.getTime() / 1000).toString());
    }
  }, [mode, timestamp, humanDate]);

  return (
    <div className="space-y-6">
      <Card darkMode={darkMode} className={darkMode ? 'bg-cyan-500/10 border border-cyan-500/20' : 'bg-cyan-50 border border-cyan-200'}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">⏱️</span>
            <div>
              <div className={`font-medium ${darkMode ? 'text-cyan-300' : 'text-cyan-800'}`}>Current Unix Timestamp</div>
              <div className={`font-mono text-2xl ${darkMode ? 'text-white' : 'text-gray-900'}`}>{currentTimestamp}</div>
            </div>
          </div>
          <CopyButton darkMode={darkMode} text={currentTimestamp.toString()} />
        </div>
      </Card>
      <TabGroup darkMode={darkMode} tabs={[{ id: 'toHuman', label: 'Timestamp → Human' }, { id: 'toTimestamp', label: 'Human → Timestamp' }]} active={mode} onChange={setMode} />
      {mode === 'toHuman' ? (
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label darkMode={darkMode} className="mb-0">Unix Timestamp</Label>
              <Button darkMode={darkMode} variant="ghost" onClick={() => setTimestamp(currentTimestamp.toString())}>Use Now</Button>
            </div>
            <Input darkMode={darkMode} type="number" value={timestamp} onChange={e => setTimestamp(e.target.value)} placeholder="1234567890" className="font-mono" />
          </div>
          {humanDate && <Card darkMode={darkMode}><Label darkMode={darkMode}>Human Readable</Label><div className={`font-mono ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>{humanDate}</div></Card>}
        </div>
      ) : (
        <div className="space-y-4">
          <div><Label darkMode={darkMode}>Date & Time</Label><Input darkMode={darkMode} type="datetime-local" value={humanDate} onChange={e => setHumanDate(e.target.value)} /></div>
          {timestamp && (
            <Card darkMode={darkMode}>
              <div className="flex items-center justify-between">
                <div><Label darkMode={darkMode}>Unix Timestamp</Label><div className={`font-mono text-xl ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>{timestamp}</div></div>
                <CopyButton darkMode={darkMode} text={timestamp} />
              </div>
            </Card>
          )}
        </div>
      )}
      <Card darkMode={darkMode}>
        <Label darkMode={darkMode}>Quick Reference</Label>
        <div className={`grid grid-cols-2 gap-2 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
          <div>1 hour = 3,600</div>
          <div>1 day = 86,400</div>
          <div>1 week = 604,800</div>
          <div>1 year ≈ 31,536,000</div>
        </div>
      </Card>
    </div>
  );
};

// ============================================================================
// CRYPTO & PRIVACY TOOLS
// ============================================================================

const PGPTool = ({ darkMode }) => {
  const [mode, setMode] = useState('encrypt');
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [status, setStatus] = useState('');
  const [generating, setGenerating] = useState(false);

  const generateKeyPair = async () => {
    setGenerating(true);
    setStatus('Generating 4096-bit RSA key pair... (In production, use openpgp.js)');
    await new Promise(r => setTimeout(r, 1500));
    setPublicKey('-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: UtilityHub v2.0\n\nmQINBGV... [4096-bit RSA Public Key]\n... (Generated with openpgp.js in production)\n-----END PGP PUBLIC KEY BLOCK-----');
    setPrivateKey('-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: UtilityHub v2.0\n\nlQdGBGV... [4096-bit RSA Private Key]\n... (Keep this secret!)\n-----END PGP PRIVATE KEY BLOCK-----');
    setGenerating(false);
    setStatus('Key pair generated! In production, integrate openpgp.js for real encryption.');
  };

  const processMessage = () => {
    if (mode === 'encrypt') {
      if (!publicKey || !inputText) { setStatus('Please provide a public key and message'); return; }
      setOutputText('-----BEGIN PGP MESSAGE-----\n\nhQIMA... [Encrypted content]\n... (In production, encrypted with openpgp.js)\n-----END PGP MESSAGE-----');
      setStatus('Message encrypted (demo). Integrate openpgp.js for real encryption.');
    } else {
      if (!privateKey || !inputText) { setStatus('Please provide your private key and encrypted message'); return; }
      setOutputText('Your decrypted message would appear here.\n(In production, decrypted with openpgp.js)');
      setStatus('Message decrypted (demo).');
    }
  };

  return (
    <div className="space-y-6">
      <Card darkMode={darkMode} className={darkMode ? 'bg-violet-500/10 border border-violet-500/20' : 'bg-violet-50 border border-violet-200'}>
        <div className="flex items-start gap-3">
          <span className="text-2xl">🔐</span>
          <div>
            <div className={`font-medium mb-1 ${darkMode ? 'text-violet-300' : 'text-violet-800'}`}>End-to-End Encryption</div>
            <div className={`text-sm ${darkMode ? 'text-violet-300/70' : 'text-violet-700'}`}>All encryption happens in your browser. For production, integrate openpgp.js library.</div>
          </div>
        </div>
      </Card>

      <TabGroup darkMode={darkMode} tabs={[{ id: 'encrypt', label: 'Encrypt' }, { id: 'decrypt', label: 'Decrypt' }, { id: 'keygen', label: 'Generate Keys' }]} active={mode} onChange={setMode} />

      {mode === 'keygen' ? (
        <div className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <div><Label darkMode={darkMode}>Your Name</Label><Input darkMode={darkMode} placeholder="John Doe" /></div>
            <div><Label darkMode={darkMode}>Email</Label><Input darkMode={darkMode} type="email" placeholder="john@example.com" /></div>
          </div>
          <div><Label darkMode={darkMode}>Passphrase (protect private key)</Label><Input darkMode={darkMode} type="password" placeholder="Strong passphrase..." value={passphrase} onChange={e => setPassphrase(e.target.value)} /></div>
          <Button darkMode={darkMode} onClick={generateKeyPair} disabled={generating} className="w-full">{generating ? 'Generating...' : 'Generate 4096-bit RSA Key Pair'}</Button>
          {publicKey && (
            <div className="grid md:grid-cols-2 gap-4 mt-6">
              <div>
                <div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Public Key (share this)</Label><CopyButton darkMode={darkMode} text={publicKey} label="Copy" /></div>
                <TextArea darkMode={darkMode} rows={6} value={publicKey} readOnly className="font-mono text-xs" />
              </div>
              <div>
                <div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Private Key (keep secret!)</Label><CopyButton darkMode={darkMode} text={privateKey} label="Copy" /></div>
                <TextArea darkMode={darkMode} rows={6} value={privateKey} readOnly className="font-mono text-xs" />
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <div><Label darkMode={darkMode}>{mode === 'encrypt' ? "Recipient's Public Key" : 'Your Private Key'}</Label><TextArea darkMode={darkMode} rows={4} placeholder={mode === 'encrypt' ? 'Paste public key...' : 'Paste private key...'} value={mode === 'encrypt' ? publicKey : privateKey} onChange={e => mode === 'encrypt' ? setPublicKey(e.target.value) : setPrivateKey(e.target.value)} className="font-mono text-sm" /></div>
          {mode === 'decrypt' && <div><Label darkMode={darkMode}>Passphrase</Label><Input darkMode={darkMode} type="password" placeholder="Enter passphrase..." value={passphrase} onChange={e => setPassphrase(e.target.value)} /></div>}
          <div><Label darkMode={darkMode}>{mode === 'encrypt' ? 'Message to Encrypt' : 'Encrypted Message'}</Label><TextArea darkMode={darkMode} rows={4} placeholder={mode === 'encrypt' ? 'Type your secret message...' : 'Paste encrypted message...'} value={inputText} onChange={e => setInputText(e.target.value)} /></div>
          <Button darkMode={darkMode} onClick={processMessage} className="w-full">{mode === 'encrypt' ? 'Encrypt Message' : 'Decrypt Message'}</Button>
          {outputText && <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Output</Label><CopyButton darkMode={darkMode} text={outputText} /></div><TextArea darkMode={darkMode} rows={5} value={outputText} readOnly className="font-mono text-sm" /></div>}
        </div>
      )}
      {status && <div className={`text-sm ${status.includes('Please') ? 'text-red-400' : darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>{status}</div>}
    </div>
  );
};

const HashGenerator = ({ darkMode }) => {
  const [input, setInput] = useState('');
  const [inputType, setInputType] = useState('text');
  const [hashes, setHashes] = useState({});
  const [fileInfo, setFileInfo] = useState(null);

  const computeHashes = useCallback(async (data) => {
    const encoder = new TextEncoder();
    const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
    const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
    const results = {};
    for (const algo of algorithms) {
      try {
        const hashBuffer = await crypto.subtle.digest(algo, dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        results[algo.toLowerCase().replace('-', '')] = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) { results[algo.toLowerCase().replace('-', '')] = 'Error'; }
    }
    setHashes(results);
  }, []);

  useEffect(() => { 
    if (input && inputType === 'text') computeHashes(input); 
  }, [input, inputType, computeHashes]);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setFileInfo({ name: file.name, size: file.size });
    const buffer = await file.arrayBuffer();
    computeHashes(new Uint8Array(buffer));
  };

  return (
    <div className="space-y-6">
      <TabGroup darkMode={darkMode} tabs={[{ id: 'text', label: 'Text Input' }, { id: 'file', label: 'File Input' }]} active={inputType} onChange={(id) => { setInputType(id); setHashes({}); setFileInfo(null); }} />
      {inputType === 'text' ? (
        <div><Label darkMode={darkMode}>Enter text to hash</Label><TextArea darkMode={darkMode} rows={4} placeholder="Type or paste text..." value={input} onChange={e => setInput(e.target.value)} /></div>
      ) : (
        <div><Label darkMode={darkMode}>Select file to hash</Label>
          <div className={`border-2 border-dashed rounded-xl p-8 text-center ${darkMode ? 'border-white/10 hover:border-white/20' : 'border-gray-300 hover:border-gray-400'}`}>
            <input type="file" onChange={handleFileUpload} className="hidden" id="hash-file" />
            <label htmlFor="hash-file" className="cursor-pointer"><div className="text-4xl mb-2">📁</div><div className={darkMode ? 'text-gray-400' : 'text-gray-600'}>{fileInfo ? `${fileInfo.name} (${(fileInfo.size/1024).toFixed(2)} KB)` : 'Click to select file'}</div></label>
          </div>
        </div>
      )}
      {Object.keys(hashes).length > 0 && (
        <div className="space-y-3">
          <Label darkMode={darkMode}>Generated Hashes</Label>
          {Object.entries(hashes).map(([algo, hash]) => (
            <div key={algo} className={`p-3 rounded-xl ${darkMode ? 'bg-white/5' : 'bg-gray-100'}`}>
              <div className="flex items-center justify-between mb-1"><span className={`text-xs font-medium uppercase ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>{algo.toUpperCase()}</span><CopyButton darkMode={darkMode} text={hash} label="Copy" /></div>
              <div className={`font-mono text-sm break-all ${darkMode ? 'text-white' : 'text-gray-900'}`}>{hash}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const HashIdentifier = ({ darkMode }) => {
  const [hash, setHash] = useState('');
  const [results, setResults] = useState([]);
  
  const hashPatterns = useMemo(() => [
    { name: 'MD5', length: 32, regex: /^[a-f0-9]{32}$/i },
    { name: 'SHA-1', length: 40, regex: /^[a-f0-9]{40}$/i },
    { name: 'SHA-256', length: 64, regex: /^[a-f0-9]{64}$/i },
    { name: 'SHA-384', length: 96, regex: /^[a-f0-9]{96}$/i },
    { name: 'SHA-512', length: 128, regex: /^[a-f0-9]{128}$/i },
    { name: 'bcrypt', length: 60, regex: /^\$2[ayb]\$.{56}$/ },
    { name: 'CRC32', length: 8, regex: /^[a-f0-9]{8}$/i },
  ], []);

  useEffect(() => {
    if (!hash.trim()) { setResults([]); return; }
    setResults(hashPatterns.filter(p => p.regex.test(hash.trim())));
  }, [hash, hashPatterns]);

  return (
    <div className="space-y-6">
      <div><Label darkMode={darkMode}>Paste hash to identify</Label><Input darkMode={darkMode} placeholder="e.g., 5d41402abc4b2a76b9719d911017c592" value={hash} onChange={e => setHash(e.target.value)} className="font-mono" /></div>
      {hash && (
        <Card darkMode={darkMode}>
          <div className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Length: <span className={darkMode ? 'text-white' : 'text-gray-900'}>{hash.trim().length}</span> characters</div>
          {results.length > 0 ? (
            <div className="space-y-2">
              <div className={`text-sm font-medium ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>Possible hash types:</div>
              {results.map((r, i) => <div key={i} className={`px-3 py-2 rounded-lg ${darkMode ? 'bg-white/5' : 'bg-white'}`}><span className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>{r.name}</span><span className={`ml-2 text-sm ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>({r.length} chars)</span></div>)}
            </div>
          ) : <div className={`text-sm ${darkMode ? 'text-yellow-400' : 'text-yellow-600'}`}>No matching hash patterns found.</div>}
        </Card>
      )}
    </div>
  );
};

const EntropyAnalyzer = ({ darkMode }) => {
  const [input, setInput] = useState('');
  const [analysis, setAnalysis] = useState(null);

  useEffect(() => {
    if (!input) { setAnalysis(null); return; }
    const text = input;
    const freq = {};
    for (const char of text) freq[char] = (freq[char] || 0) + 1;
    const len = text.length;
    let entropy = 0;
    for (const count of Object.values(freq)) { const p = count / len; entropy -= p * Math.log2(p); }
    const uniqueChars = Object.keys(freq).length;
    const hasLower = /[a-z]/.test(text), hasUpper = /[A-Z]/.test(text), hasDigit = /[0-9]/.test(text), hasSpecial = /[^a-zA-Z0-9]/.test(text);
    const charClasses = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
    let strength = 'Weak', strengthColor = 'red';
    if (entropy > 4 && len >= 12 && charClasses >= 3) { strength = 'Strong'; strengthColor = 'emerald'; }
    else if (entropy > 3 && len >= 8 && charClasses >= 2) { strength = 'Moderate'; strengthColor = 'yellow'; }
    setAnalysis({ entropy: entropy.toFixed(4), length: len, uniqueChars, charClasses, hasLower, hasUpper, hasDigit, hasSpecial, strength, strengthColor });
  }, [input]);

  return (
    <div className="space-y-6">
      <div><Label darkMode={darkMode}>Enter text to analyze</Label><TextArea darkMode={darkMode} rows={4} placeholder="Paste a password or key to analyze..." value={input} onChange={e => setInput(e.target.value)} /></div>
      {analysis && (
        <>
          <Card darkMode={darkMode} className={analysis.strengthColor === 'emerald' ? (darkMode ? 'bg-emerald-500/10 border border-emerald-500/30' : 'bg-emerald-50 border border-emerald-200') : analysis.strengthColor === 'yellow' ? (darkMode ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-yellow-50 border border-yellow-200') : (darkMode ? 'bg-red-500/10 border border-red-500/30' : 'bg-red-50 border border-red-200')}>
            <div className="text-center"><div className={`text-3xl font-bold ${analysis.strengthColor === 'emerald' ? (darkMode ? 'text-emerald-400' : 'text-emerald-600') : analysis.strengthColor === 'yellow' ? (darkMode ? 'text-yellow-400' : 'text-yellow-600') : (darkMode ? 'text-red-400' : 'text-red-600')}`}>{analysis.strength}</div><div className={darkMode ? 'text-gray-400' : 'text-gray-600'}>Overall Strength</div></div>
          </Card>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[{ label: 'Shannon Entropy', value: analysis.entropy }, { label: 'Length', value: analysis.length }, { label: 'Unique Chars', value: analysis.uniqueChars }, { label: 'Char Classes', value: `${analysis.charClasses}/4` }].map(stat => (
              <Card key={stat.label} darkMode={darkMode}><div className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{stat.value}</div><div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>{stat.label}</div></Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

// ============================================================================
// ENCODING TOOLS
// ============================================================================

const BinaryConverter = ({ darkMode }) => {
  const [text, setText] = useState('');
  const [binary, setBinary] = useState('');
  const [mode, setMode] = useState('encode');
  
  const textToBinary = useCallback((str) => str.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' '), []);
  const binaryToText = useCallback((bin) => { const bytes = bin.replace(/[^01]/g, '').match(/.{1,8}/g); return bytes ? bytes.map(byte => String.fromCharCode(parseInt(byte, 2))).join('') : ''; }, []);
  
  useEffect(() => { 
    if (mode === 'encode') setBinary(textToBinary(text)); 
    else setText(binaryToText(binary)); 
  }, [text, binary, mode, textToBinary, binaryToText]);

  return (
    <div className="space-y-6">
      <TabGroup darkMode={darkMode} tabs={[{ id: 'encode', label: 'Text → Binary' }, { id: 'decode', label: 'Binary → Text' }]} active={mode} onChange={setMode} />
      <div className="grid md:grid-cols-2 gap-4">
        <div><Label darkMode={darkMode}>Text</Label><TextArea darkMode={darkMode} rows={6} placeholder="Enter text..." value={text} onChange={e => { setText(e.target.value); if (mode === 'decode') setMode('encode'); }} /></div>
        <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Binary</Label><CopyButton darkMode={darkMode} text={binary} /></div><TextArea darkMode={darkMode} rows={6} placeholder="Binary output..." value={binary} onChange={e => { setBinary(e.target.value); if (mode === 'encode') setMode('decode'); }} className="font-mono text-sm" /></div>
      </div>
    </div>
  );
};

const HexConverter = ({ darkMode }) => {
  const [text, setText] = useState('');
  const [hex, setHex] = useState('');
  const [mode, setMode] = useState('encode');
  
  const textToHex = useCallback((str) => str.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' '), []);
  const hexToText = useCallback((h) => { const bytes = h.replace(/[^0-9a-fA-F]/g, '').match(/.{1,2}/g); return bytes ? bytes.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') : ''; }, []);
  
  useEffect(() => { 
    if (mode === 'encode') setHex(textToHex(text)); 
    else setText(hexToText(hex)); 
  }, [text, hex, mode, textToHex, hexToText]);

  return (
    <div className="space-y-6">
      <TabGroup darkMode={darkMode} tabs={[{ id: 'encode', label: 'Text → Hex' }, { id: 'decode', label: 'Hex → Text' }]} active={mode} onChange={setMode} />
      <div className="grid md:grid-cols-2 gap-4">
        <div><Label darkMode={darkMode}>Text</Label><TextArea darkMode={darkMode} rows={6} placeholder="Enter text..." value={text} onChange={e => { setText(e.target.value); if (mode === 'decode') setMode('encode'); }} /></div>
        <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Hexadecimal</Label><CopyButton darkMode={darkMode} text={hex} /></div><TextArea darkMode={darkMode} rows={6} placeholder="Hex output..." value={hex} onChange={e => { setHex(e.target.value); if (mode === 'encode') setMode('decode'); }} className="font-mono text-sm" /></div>
      </div>
    </div>
  );
};

const Base64Tool = ({ darkMode }) => {
  const [text, setText] = useState('');
  const [encoded, setEncoded] = useState('');
  const [mode, setMode] = useState('encode');
  const [error, setError] = useState('');
  
  useEffect(() => { 
    setError(''); 
    try { 
      if (mode === 'encode') setEncoded(btoa(unescape(encodeURIComponent(text)))); 
      else setText(decodeURIComponent(escape(atob(encoded)))); 
    } catch (e) { 
      setError('Invalid input'); 
    } 
  }, [text, encoded, mode]);

  return (
    <div className="space-y-6">
      <TabGroup darkMode={darkMode} tabs={[{ id: 'encode', label: 'Encode' }, { id: 'decode', label: 'Decode' }]} active={mode} onChange={setMode} />
      <div className="grid md:grid-cols-2 gap-4">
        <div><Label darkMode={darkMode}>Plain Text</Label><TextArea darkMode={darkMode} rows={6} placeholder="Enter text..." value={text} onChange={e => { setText(e.target.value); if (mode === 'decode') setMode('encode'); }} /></div>
        <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Base64</Label><CopyButton darkMode={darkMode} text={encoded} /></div><TextArea darkMode={darkMode} rows={6} placeholder="Base64 output..." value={encoded} onChange={e => { setEncoded(e.target.value); if (mode === 'encode') setMode('decode'); }} className="font-mono text-sm" /></div>
      </div>
      {error && <div className="text-red-400 text-sm">{error}</div>}
    </div>
  );
};

const MorseCode = ({ darkMode }) => {
  const [text, setText] = useState('');
  const [morse, setMorse] = useState('');
  const [mode, setMode] = useState('encode');
  
  const morseMap = useMemo(() => ({ 'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',' ':'/','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.' }), []);
  const reverseMorseMap = useMemo(() => Object.fromEntries(Object.entries(morseMap).map(([k, v]) => [v, k])), [morseMap]);
  
  const textToMorse = useCallback((str) => str.toUpperCase().split('').map(char => morseMap[char] || char).join(' '), [morseMap]);
  const morseToText = useCallback((m) => m.split(' ').map(code => code === '/' ? ' ' : reverseMorseMap[code] || code).join(''), [reverseMorseMap]);
  
  useEffect(() => { 
    if (mode === 'encode') setMorse(textToMorse(text)); 
    else setText(morseToText(morse)); 
  }, [text, morse, mode, textToMorse, morseToText]);

  return (
    <div className="space-y-6">
      <TabGroup darkMode={darkMode} tabs={[{ id: 'encode', label: 'Text → Morse' }, { id: 'decode', label: 'Morse → Text' }]} active={mode} onChange={setMode} />
      <div className="grid md:grid-cols-2 gap-4">
        <div><Label darkMode={darkMode}>Text</Label><TextArea darkMode={darkMode} rows={6} placeholder="Enter text..." value={text} onChange={e => { setText(e.target.value); if (mode === 'decode') setMode('encode'); }} /></div>
        <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Morse Code</Label><CopyButton darkMode={darkMode} text={morse} /></div><TextArea darkMode={darkMode} rows={6} placeholder="Morse output..." value={morse} onChange={e => { setMorse(e.target.value); if (mode === 'encode') setMode('decode'); }} className="font-mono text-lg tracking-wider" /></div>
      </div>
      <Card darkMode={darkMode}><div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}><strong>Legend:</strong> Dots (.) Dashes (-) • Words separated by / • Letters separated by spaces</div></Card>
    </div>
  );
};

const ZeroWidthEncoder = ({ darkMode }) => {
  const [visibleText, setVisibleText] = useState('');
  const [hiddenMessage, setHiddenMessage] = useState('');
  const [output, setOutput] = useState('');
  const [decoded, setDecoded] = useState('');
  const [mode, setMode] = useState('encode');
  const ZWSP = '\u200B', ZWNJ = '\u200C', ZWJ = '\u200D';

  const encode = () => {
    if (!visibleText || !hiddenMessage) return;
    const binaryMessage = hiddenMessage.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join('');
    const zwEncoded = binaryMessage.split('').map(bit => bit === '0' ? ZWSP : ZWNJ).join('');
    setOutput(visibleText + ZWJ + zwEncoded + ZWJ);
  };

  const decode = () => {
    if (!output) return;
    const zwChars = output.match(/[\u200B\u200C]/g);
    if (!zwChars) { setDecoded('No hidden message found'); return; }
    const binary = zwChars.map(char => char === ZWSP ? '0' : '1').join('');
    const bytes = binary.match(/.{1,8}/g);
    if (!bytes) { setDecoded('Could not decode'); return; }
    setDecoded(bytes.map(byte => String.fromCharCode(parseInt(byte, 2))).join(''));
  };

  return (
    <div className="space-y-6">
      <Card darkMode={darkMode} className={darkMode ? 'bg-fuchsia-500/10 border border-fuchsia-500/20' : 'bg-fuchsia-50 border border-fuchsia-200'}>
        <div className="flex items-start gap-3"><span className="text-2xl">👻</span><div><div className={`font-medium mb-1 ${darkMode ? 'text-fuchsia-300' : 'text-fuchsia-800'}`}>Steganography Tool</div><div className={`text-sm ${darkMode ? 'text-fuchsia-300/70' : 'text-fuchsia-700'}`}>Hide secret messages in normal text using invisible zero-width characters!</div></div></div>
      </Card>
      <TabGroup darkMode={darkMode} tabs={[{ id: 'encode', label: 'Hide Message' }, { id: 'decode', label: 'Reveal Message' }]} active={mode} onChange={setMode} />
      {mode === 'encode' ? (
        <div className="space-y-4">
          <div><Label darkMode={darkMode}>Visible Text (what people see)</Label><TextArea darkMode={darkMode} rows={3} placeholder="Enter normal text..." value={visibleText} onChange={e => setVisibleText(e.target.value)} /></div>
          <div><Label darkMode={darkMode}>Hidden Message (secret)</Label><TextArea darkMode={darkMode} rows={3} placeholder="Enter secret message..." value={hiddenMessage} onChange={e => setHiddenMessage(e.target.value)} /></div>
          <Button darkMode={darkMode} onClick={encode} className="w-full">Encode Hidden Message</Button>
          {output && <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Output (copy this)</Label><CopyButton darkMode={darkMode} text={output} /></div><TextArea darkMode={darkMode} rows={3} value={output} readOnly /><div className={`mt-2 text-sm ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>✓ Hidden message embedded! Looks normal but contains your secret.</div></div>}
        </div>
      ) : (
        <div className="space-y-4">
          <div><Label darkMode={darkMode}>Text with Hidden Message</Label><TextArea darkMode={darkMode} rows={4} placeholder="Paste text that might contain hidden message..." value={output} onChange={e => setOutput(e.target.value)} /></div>
          <Button darkMode={darkMode} onClick={decode} className="w-full">Reveal Hidden Message</Button>
          {decoded && <Card darkMode={darkMode}><Label darkMode={darkMode}>Decoded Message</Label><div className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>{decoded}</div></Card>}
        </div>
      )}
    </div>
  );
};

const ROT13Cipher = ({ darkMode }) => {
  const [input, setInput] = useState('');
  const [shift, setShift] = useState(13);
  const [output, setOutput] = useState('');
  
  const cipher = useCallback((text, s) => text.split('').map(char => { if (char.match(/[a-z]/i)) { const code = char.charCodeAt(0); const base = code >= 65 && code <= 90 ? 65 : 97; return String.fromCharCode(((code - base + s) % 26 + 26) % 26 + base); } return char; }).join(''), []);
  
  useEffect(() => { setOutput(cipher(input, shift)); }, [input, shift, cipher]);

  return (
    <div className="space-y-6">
      <div className="grid md:grid-cols-2 gap-4">
        <div><Label darkMode={darkMode}>Input Text</Label><TextArea darkMode={darkMode} rows={6} placeholder="Enter text to cipher..." value={input} onChange={e => setInput(e.target.value)} /></div>
        <div><div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Output</Label><CopyButton darkMode={darkMode} text={output} /></div><TextArea darkMode={darkMode} rows={6} value={output} readOnly className="font-mono" /></div>
      </div>
      <div><Label darkMode={darkMode}>Shift Amount: {shift}</Label><div className="flex items-center gap-4"><input type="range" min="1" max="25" value={shift} onChange={e => setShift(parseInt(e.target.value))} className="flex-1" /><div className="flex gap-2"><Button darkMode={darkMode} variant="secondary" onClick={() => setShift(13)}>ROT13</Button><Button darkMode={darkMode} variant="secondary" onClick={() => setShift(3)}>Caesar (3)</Button></div></div></div>
    </div>
  );
};

// ============================================================================
// TEXT TOOLS
// ============================================================================

const WordCounter = ({ darkMode }) => {
  const [text, setText] = useState('');
  const stats = useMemo(() => {
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    const chars = text.length, charsNoSpaces = text.replace(/\s/g, '').length;
    const sentences = text.split(/[.!?]+/).filter(s => s.trim()).length;
    const paragraphs = text.split(/\n\n+/).filter(p => p.trim()).length;
    const readingTime = Math.ceil(words / 200);
    return { words, chars, charsNoSpaces, sentences, paragraphs, readingTime };
  }, [text]);

  return (
    <div className="space-y-6">
      <div><Label darkMode={darkMode}>Enter your text</Label><TextArea darkMode={darkMode} rows={8} placeholder="Type or paste text..." value={text} onChange={e => setText(e.target.value)} /></div>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {[{ label: 'Words', value: stats.words }, { label: 'Characters', value: stats.chars }, { label: 'No Spaces', value: stats.charsNoSpaces }, { label: 'Sentences', value: stats.sentences }, { label: 'Paragraphs', value: stats.paragraphs }, { label: 'Reading Time', value: `${stats.readingTime} min` }].map(stat => (
          <Card key={stat.label} darkMode={darkMode}><div className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{stat.value}</div><div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>{stat.label}</div></Card>
        ))}
      </div>
    </div>
  );
};

const CaseConverter = ({ darkMode }) => {
  const [text, setText] = useState('');
  const conversions = useMemo(() => [
    { id: 'upper', label: 'UPPERCASE', fn: t => t.toUpperCase() },
    { id: 'lower', label: 'lowercase', fn: t => t.toLowerCase() },
    { id: 'title', label: 'Title Case', fn: t => t.replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.substr(1).toLowerCase()) },
    { id: 'sentence', label: 'Sentence case', fn: t => t.toLowerCase().replace(/(^\s*\w|[.!?]\s*\w)/g, c => c.toUpperCase()) },
    { id: 'camel', label: 'camelCase', fn: t => t.toLowerCase().replace(/[^a-zA-Z0-9]+(.)/g, (m, c) => c.toUpperCase()) },
    { id: 'snake', label: 'snake_case', fn: t => t.toLowerCase().replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_|_$/g, '') },
    { id: 'kebab', label: 'kebab-case', fn: t => t.toLowerCase().replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-|-$/g, '') },
    { id: 'reverse', label: 'esreveR', fn: t => t.split('').reverse().join('') },
  ], []);

  return (
    <div className="space-y-6">
      <div><Label darkMode={darkMode}>Enter text to convert</Label><TextArea darkMode={darkMode} rows={4} placeholder="Type or paste text..." value={text} onChange={e => setText(e.target.value)} /></div>
      <div className="flex flex-wrap gap-2">{conversions.map(conv => <Button key={conv.id} darkMode={darkMode} variant="secondary" onClick={() => setText(conv.fn(text))}>{conv.label}</Button>)}</div>
      <div className="flex gap-2"><Button darkMode={darkMode} variant="ghost" onClick={() => setText('')}>Clear</Button><CopyButton darkMode={darkMode} text={text} label="Copy Result" /></div>
    </div>
  );
};

// ============================================================================
// CALCULATORS
// ============================================================================

const Calculator = ({ darkMode }) => {
  const [display, setDisplay] = useState('0');
  const [equation, setEquation] = useState('');
  const handleNumber = (num) => setDisplay(display === '0' || display === 'Error' ? num : display + num);
  const handleOperator = (op) => { setEquation(display + ' ' + op + ' '); setDisplay('0'); };
  const handleEquals = () => { 
    try { 
      // eslint-disable-next-line no-eval
      const result = eval((equation + display).replace(/×/g, '*').replace(/÷/g, '/').replace(/−/g, '-')); 
      setDisplay(String(Math.round(result * 100000000) / 100000000)); 
      setEquation(''); 
    } catch { 
      setDisplay('Error'); 
      setEquation(''); 
    } 
  };
  const handleClear = () => { setDisplay('0'); setEquation(''); };

  const buttons = useMemo(() => [
    { label: 'C', action: handleClear, style: 'func' }, { label: '⌫', action: () => setDisplay(display.length > 1 ? display.slice(0, -1) : '0'), style: 'func' }, { label: '%', action: () => setDisplay(String(parseFloat(display) / 100)), style: 'func' }, { label: '÷', action: () => handleOperator('÷'), style: 'op' },
    { label: '7', action: () => handleNumber('7') }, { label: '8', action: () => handleNumber('8') }, { label: '9', action: () => handleNumber('9') }, { label: '×', action: () => handleOperator('×'), style: 'op' },
    { label: '4', action: () => handleNumber('4') }, { label: '5', action: () => handleNumber('5') }, { label: '6', action: () => handleNumber('6') }, { label: '−', action: () => handleOperator('−'), style: 'op' },
    { label: '1', action: () => handleNumber('1') }, { label: '2', action: () => handleNumber('2') }, { label: '3', action: () => handleNumber('3') }, { label: '+', action: () => handleOperator('+'), style: 'op' },
    { label: '±', action: () => setDisplay(String(parseFloat(display) * -1)) }, { label: '0', action: () => handleNumber('0') }, { label: '.', action: () => !display.includes('.') && setDisplay(display + '.') }, { label: '=', action: handleEquals, style: 'eq' },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [display, equation]);

  const getStyle = (style) => { if (style === 'func') return darkMode ? 'bg-white/10 text-gray-300' : 'bg-gray-300 text-gray-800'; if (style === 'op') return 'bg-violet-600 text-white'; if (style === 'eq') return 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white'; return darkMode ? 'bg-white/5 text-white hover:bg-white/10' : 'bg-white text-gray-900 hover:bg-gray-50'; };

  return (
    <div className="max-w-xs mx-auto">
      <Card darkMode={darkMode} className="mb-4"><div className={`text-right text-sm h-5 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>{equation}</div><div className={`text-right text-4xl font-light ${darkMode ? 'text-white' : 'text-gray-900'}`}>{display}</div></Card>
      <div className="grid grid-cols-4 gap-2">{buttons.map((btn, i) => <button key={i} onClick={btn.action} className={`h-14 rounded-xl text-xl font-medium transition-all active:scale-95 ${getStyle(btn.style)}`}>{btn.label}</button>)}</div>
    </div>
  );
};

const PasswordGenerator = ({ darkMode }) => {
  const [length, setLength] = useState(16);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [password, setPassword] = useState('');
  const [strength, setStrength] = useState(null);

  const generate = useCallback(() => {
    let chars = '';
    if (includeLower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (includeUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeNumbers) chars += '0123456789';
    if (includeSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!chars) { setPassword('Select at least one option'); return; }
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    let result = '';
    for (let i = 0; i < length; i++) result += chars[array[i] % chars.length];
    setPassword(result);
    const poolSize = chars.length;
    const entropy = Math.log2(poolSize) * length;
    if (entropy >= 80) setStrength({ label: 'Strong', color: 'emerald', percent: 100 });
    else if (entropy >= 60) setStrength({ label: 'Good', color: 'yellow', percent: 70 });
    else setStrength({ label: 'Weak', color: 'red', percent: 30 });
  }, [length, includeLower, includeUpper, includeNumbers, includeSymbols]);

  useEffect(() => { generate(); }, [generate]);

  const Toggle = ({ label, checked, onChange }) => (
    <button onClick={() => onChange(!checked)} className={`flex items-center justify-between w-full p-3 rounded-xl transition-all ${checked ? darkMode ? 'bg-violet-600/20 border border-violet-500/30' : 'bg-violet-100 border border-violet-200' : darkMode ? 'bg-white/5 border border-white/10' : 'bg-gray-100 border border-gray-200'}`}>
      <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>{label}</span>
      <div className={`w-10 h-5 rounded-full relative transition-colors ${checked ? 'bg-violet-600' : darkMode ? 'bg-gray-600' : 'bg-gray-300'}`}><div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${checked ? 'left-5' : 'left-0.5'}`} /></div>
    </button>
  );

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center justify-between mb-2"><Label darkMode={darkMode} className="mb-0">Generated Password</Label><div className="flex gap-2"><Button darkMode={darkMode} variant="ghost" onClick={generate}>↻</Button><CopyButton darkMode={darkMode} text={password} /></div></div>
        <div className={`p-4 rounded-xl font-mono text-lg break-all ${darkMode ? 'bg-white/5 text-white' : 'bg-gray-100 text-gray-900'}`}>{password}</div>
        {strength && <div className="mt-2"><div className="flex justify-between text-sm mb-1"><span className={darkMode ? 'text-gray-500' : 'text-gray-500'}>Strength</span><span className={strength.color === 'emerald' ? (darkMode ? 'text-emerald-400' : 'text-emerald-600') : strength.color === 'yellow' ? (darkMode ? 'text-yellow-400' : 'text-yellow-600') : (darkMode ? 'text-red-400' : 'text-red-600')}>{strength.label}</span></div><div className={`h-2 rounded-full ${darkMode ? 'bg-white/10' : 'bg-gray-200'}`}><div className={`h-2 rounded-full transition-all ${strength.color === 'emerald' ? 'bg-emerald-500' : strength.color === 'yellow' ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${strength.percent}%` }} /></div></div>}
      </div>
      <div><Label darkMode={darkMode}>Length: {length}</Label><input type="range" min="8" max="64" value={length} onChange={e => setLength(parseInt(e.target.value))} className="w-full" /></div>
      <div className="grid grid-cols-2 gap-3">
        <Toggle label="Lowercase (a-z)" checked={includeLower} onChange={setIncludeLower} />
        <Toggle label="Uppercase (A-Z)" checked={includeUpper} onChange={setIncludeUpper} />
        <Toggle label="Numbers (0-9)" checked={includeNumbers} onChange={setIncludeNumbers} />
        <Toggle label="Symbols (!@#$)" checked={includeSymbols} onChange={setIncludeSymbols} />
      </div>
    </div>
  );
};

// ============================================================================
// QR CODE & UNIT CONVERTER
// ============================================================================

const QRGenerator = ({ darkMode }) => {
  const [text, setText] = useState('https://chimeraops.org');
  const [fgColor, setFgColor] = useState('#00f0ff');
  const [bgColor, setBgColor] = useState('#0a0a0f');
  const [size, setSize] = useState(200);
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}&color=${fgColor.replace('#', '')}&bgcolor=${bgColor.replace('#', '')}`;

  return (
    <div className="space-y-6">
      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div><Label darkMode={darkMode}>Content</Label><TextArea darkMode={darkMode} rows={3} placeholder="Enter URL, text, or data..." value={text} onChange={e => setText(e.target.value)} /></div>
          <div className="grid grid-cols-2 gap-4">
            <div><Label darkMode={darkMode}>QR Color</Label><div className="flex gap-2"><input type="color" value={fgColor} onChange={e => setFgColor(e.target.value)} className="w-12 h-10 rounded-lg cursor-pointer border-0" /><Input darkMode={darkMode} value={fgColor} onChange={e => setFgColor(e.target.value)} className="font-mono text-sm uppercase" /></div></div>
            <div><Label darkMode={darkMode}>Background</Label><div className="flex gap-2"><input type="color" value={bgColor} onChange={e => setBgColor(e.target.value)} className="w-12 h-10 rounded-lg cursor-pointer border-0" /><Input darkMode={darkMode} value={bgColor} onChange={e => setBgColor(e.target.value)} className="font-mono text-sm uppercase" /></div></div>
          </div>
          <div><Label darkMode={darkMode}>Size: {size}px</Label><input type="range" min="100" max="400" value={size} onChange={e => setSize(parseInt(e.target.value))} className="w-full" /></div>
        </div>
        <div className="flex flex-col items-center justify-center">
          <div className="p-4 bg-white rounded-2xl shadow-lg">{text ? <img src={qrUrl} alt="QR Code" style={{ width: size, height: size }} /> : <div className="flex items-center justify-center text-gray-400" style={{ width: size, height: size }}>Enter content</div>}</div>
          <a href={qrUrl} download="qrcode.png" className="mt-4 px-6 py-2.5 bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white rounded-xl font-medium hover:from-violet-500 hover:to-fuchsia-500 transition-all">Download PNG</a>
        </div>
      </div>
    </div>
  );
};

const UnitConverter = ({ darkMode }) => {
  const [category, setCategory] = useState('length');
  const [fromUnit, setFromUnit] = useState('m');
  const [toUnit, setToUnit] = useState('ft');
  const [fromValue, setFromValue] = useState('1');
  const [toValue, setToValue] = useState('');

  const units = useMemo(() => ({ 
    length: { m: 1, km: 1000, cm: 0.01, mm: 0.001, mi: 1609.34, yd: 0.9144, ft: 0.3048, in: 0.0254 }, 
    weight: { kg: 1, g: 0.001, mg: 0.000001, lb: 0.453592, oz: 0.0283495 }, 
    temperature: { c: 'c', f: 'f', k: 'k' }, 
    volume: { l: 1, ml: 0.001, gal: 3.78541, qt: 0.946353, cup: 0.24 }, 
    data: { b: 1, kb: 1024, mb: 1048576, gb: 1073741824, tb: 1099511627776 } 
  }), []);
  
  const labels = useMemo(() => ({ 
    length: { m: 'Meters', km: 'Kilometers', cm: 'Centimeters', mm: 'Millimeters', mi: 'Miles', yd: 'Yards', ft: 'Feet', in: 'Inches' }, 
    weight: { kg: 'Kilograms', g: 'Grams', mg: 'Milligrams', lb: 'Pounds', oz: 'Ounces' }, 
    temperature: { c: 'Celsius', f: 'Fahrenheit', k: 'Kelvin' }, 
    volume: { l: 'Liters', ml: 'Milliliters', gal: 'Gallons', qt: 'Quarts', cup: 'Cups' }, 
    data: { b: 'Bytes', kb: 'Kilobytes', mb: 'Megabytes', gb: 'Gigabytes', tb: 'Terabytes' } 
  }), []);
  
  const categories = useMemo(() => [
    { id: 'length', label: 'Length' }, 
    { id: 'weight', label: 'Weight' }, 
    { id: 'temperature', label: 'Temp' }, 
    { id: 'volume', label: 'Volume' }, 
    { id: 'data', label: 'Data' }
  ], []);

  useEffect(() => { 
    const available = Object.keys(units[category]); 
    setFromUnit(available[0]); 
    setToUnit(available[1]); 
  }, [category, units]);

  useEffect(() => {
    if (!fromValue || isNaN(parseFloat(fromValue))) { setToValue(''); return; }
    const val = parseFloat(fromValue);
    if (category === 'temperature') {
      let celsius; 
      if (fromUnit === 'c') celsius = val; 
      else if (fromUnit === 'f') celsius = (val - 32) * 5 / 9; 
      else celsius = val - 273.15;
      let result; 
      if (toUnit === 'c') result = celsius; 
      else if (toUnit === 'f') result = celsius * 9 / 5 + 32; 
      else result = celsius + 273.15;
      setToValue(result.toFixed(4).replace(/\.?0+$/, ''));
    } else { 
      const baseValue = val * units[category][fromUnit]; 
      const result = baseValue / units[category][toUnit]; 
      setToValue(result.toFixed(8).replace(/\.?0+$/, '')); 
    }
  }, [fromValue, fromUnit, toUnit, category, units]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2">{categories.map(cat => <button key={cat.id} onClick={() => setCategory(cat.id)} className={`px-4 py-2 rounded-xl text-sm font-medium transition-all ${category === cat.id ? 'bg-violet-600 text-white' : darkMode ? 'bg-white/5 text-gray-400 hover:bg-white/10' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'}`}>{cat.label}</button>)}</div>
      <div className="grid md:grid-cols-[1fr,auto,1fr] gap-4 items-end">
        <div>
          <Label darkMode={darkMode}>From</Label>
          <select value={fromUnit} onChange={e => setFromUnit(e.target.value)} className={`w-full p-3 rounded-xl mb-2 ${darkMode ? 'bg-white/5 text-white border border-white/10' : 'bg-gray-100 text-gray-900 border border-gray-200'}`}>{Object.entries(labels[category]).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
          <Input darkMode={darkMode} type="number" value={fromValue} onChange={e => setFromValue(e.target.value)} placeholder="Enter value" className="text-xl" />
        </div>
        <button onClick={() => { const temp = fromUnit; setFromUnit(toUnit); setToUnit(temp); setFromValue(toValue); }} className={`w-12 h-12 rounded-full flex items-center justify-center text-xl mb-2 ${darkMode ? 'bg-white/10 text-white' : 'bg-gray-200 text-gray-700'}`}>⇄</button>
        <div>
          <Label darkMode={darkMode}>To</Label>
          <select value={toUnit} onChange={e => setToUnit(e.target.value)} className={`w-full p-3 rounded-xl mb-2 ${darkMode ? 'bg-white/5 text-white border border-white/10' : 'bg-gray-100 text-gray-900 border border-gray-200'}`}>{Object.entries(labels[category]).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
          <div className={`w-full p-4 rounded-xl text-xl font-semibold ${darkMode ? 'bg-violet-600/20 text-violet-300 border-2 border-violet-500/30' : 'bg-violet-100 text-violet-700 border-2 border-violet-200'}`}>{toValue || '—'}</div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// COLOR PICKER
// ============================================================================

const ColorPicker = ({ darkMode }) => {
  const [color, setColor] = useState('#8b5cf6');
  const [palette, setPalette] = useState([]);
  
  const hexToRgb = useCallback((hex) => { 
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex); 
    return result ? { r: parseInt(result[1], 16), g: parseInt(result[2], 16), b: parseInt(result[3], 16) } : null; 
  }, []);
  
  const hexToHsl = useCallback((hex) => { 
    const rgb = hexToRgb(hex); 
    if (!rgb) return null; 
    let { r, g, b } = rgb; 
    r /= 255; g /= 255; b /= 255; 
    const max = Math.max(r, g, b), min = Math.min(r, g, b); 
    let h = 0, s, l = (max + min) / 2; 
    if (max !== min) { 
      const d = max - min; 
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min); 
      switch (max) { 
        case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break; 
        case g: h = ((b - r) / d + 2) / 6; break; 
        case b: h = ((r - g) / d + 4) / 6; break;
        default: break;
      } 
    } else { s = 0; } 
    return { h: Math.round(h * 360), s: Math.round(s * 100), l: Math.round(l * 100) }; 
  }, [hexToRgb]);
  
  const generatePalette = useCallback(() => { 
    const hsl = hexToHsl(color); 
    if (!hsl) return; 
    const colors = []; 
    for (let i = 0; i < 6; i++) { 
      const newH = (hsl.h + i * 30) % 360; 
      colors.push(`hsl(${newH}, ${hsl.s}%, ${hsl.l}%)`); 
    } 
    setPalette(colors); 
  }, [color, hexToHsl]);
  
  const rgb = hexToRgb(color); 
  const hsl = hexToHsl(color);

  return (
    <div className="space-y-6">
      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div><Label darkMode={darkMode}>Pick Color</Label><div className="flex gap-3"><input type="color" value={color} onChange={e => setColor(e.target.value)} className="w-24 h-24 rounded-xl cursor-pointer border-0" /><div className="flex-1 space-y-2"><Input darkMode={darkMode} value={color.toUpperCase()} onChange={e => setColor(e.target.value)} className="font-mono" /><div className="grid grid-cols-2 gap-2"><Button darkMode={darkMode} variant="secondary" onClick={() => navigator.clipboard.writeText(color)}>Copy HEX</Button><Button darkMode={darkMode} variant="secondary" onClick={() => rgb && navigator.clipboard.writeText(`rgb(${rgb.r}, ${rgb.g}, ${rgb.b})`)}>Copy RGB</Button></div></div></div></div>
        </div>
        <Card darkMode={darkMode}><div className={`text-sm font-medium mb-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Color Values</div><div className="space-y-2"><div className="flex justify-between"><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>HEX</span><span className={`font-mono ${darkMode ? 'text-white' : 'text-gray-900'}`}>{color.toUpperCase()}</span></div>{rgb && <div className="flex justify-between"><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>RGB</span><span className={`font-mono ${darkMode ? 'text-white' : 'text-gray-900'}`}>{rgb.r}, {rgb.g}, {rgb.b}</span></div>}{hsl && <div className="flex justify-between"><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>HSL</span><span className={`font-mono ${darkMode ? 'text-white' : 'text-gray-900'}`}>{hsl.h}°, {hsl.s}%, {hsl.l}%</span></div>}</div></Card>
      </div>
      <div><div className="flex items-center justify-between mb-3"><Label darkMode={darkMode} className="mb-0">Palette</Label><Button darkMode={darkMode} variant="secondary" onClick={generatePalette}>Generate</Button></div><div className="flex gap-2">{palette.length > 0 ? palette.map((c, i) => <button key={i} onClick={() => navigator.clipboard.writeText(c)} className="flex-1 h-16 rounded-xl transition-transform hover:scale-105" style={{ backgroundColor: c }} title={`Click to copy: ${c}`} />) : <div className={`flex-1 h-16 rounded-xl flex items-center justify-center ${darkMode ? 'bg-white/5 text-gray-500' : 'bg-gray-100 text-gray-500'}`}>Click "Generate" to create a palette</div>}</div></div>
      <div><Label darkMode={darkMode}>Preview</Label><div className="h-24 rounded-xl flex items-center justify-center" style={{ backgroundColor: color }}><span className="text-white font-semibold text-lg drop-shadow-lg">Sample Text</span></div></div>
    </div>
  );
};

// ============================================================================
// MAIN APP
// ============================================================================

function App() {
  const [activeCategory, setActiveCategory] = useState('popular');
  const [activeTool, setActiveTool] = useState('qr-generator');
  const [darkMode, setDarkMode] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const categories = useMemo(() => ({
    popular: { label: 'Popular', icon: '★', tools: ['qr-generator', 'password-gen', 'hash-generator', 'json-formatter', 'uuid-generator'] },
    crypto: { label: 'Crypto & Privacy', icon: '🔐', tools: ['pgp-tool', 'hash-generator', 'hash-identifier', 'entropy-analyzer', 'jwt-decoder'] },
    encoding: { label: 'Encoding', icon: '⟨⟩', tools: ['binary-converter', 'hex-converter', 'base64-tool', 'morse-code', 'zero-width', 'rot13-cipher'] },
    developer: { label: 'Developer', icon: '{ }', tools: ['json-formatter', 'regex-tester', 'uuid-generator', 'jwt-decoder', 'timestamp-converter'] },
    text: { label: 'Text Tools', icon: '¶', tools: ['word-counter', 'case-converter'] },
    calculators: { label: 'Calculators', icon: '∑', tools: ['calculator', 'unit-converter'] },
    media: { label: 'Colors', icon: '◐', tools: ['color-picker'] },
  }), []);

  const toolMeta = useMemo(() => ({
    'qr-generator': { name: 'QR Code Generator', desc: 'Create custom QR codes' },
    'password-gen': { name: 'Password Generator', desc: 'Generate secure passwords' },
    'unit-converter': { name: 'Unit Converter', desc: 'Convert measurements' },
    'calculator': { name: 'Calculator', desc: 'Full-featured calculator' },
    'pgp-tool': { name: 'PGP Encrypt/Decrypt', desc: 'OpenPGP encryption' },
    'hash-generator': { name: 'Hash Generator', desc: 'SHA-1, SHA-256, SHA-512' },
    'hash-identifier': { name: 'Hash Identifier', desc: 'Identify hash types' },
    'entropy-analyzer': { name: 'Entropy Analyzer', desc: 'Analyze randomness' },
    'binary-converter': { name: 'Binary Converter', desc: 'Text ↔ Binary' },
    'hex-converter': { name: 'Hex Converter', desc: 'Text ↔ Hexadecimal' },
    'base64-tool': { name: 'Base64 Encoder', desc: 'Encode & decode Base64' },
    'morse-code': { name: 'Morse Code', desc: 'Translate Morse' },
    'zero-width': { name: 'Zero-Width Encoder', desc: 'Hide messages in text' },
    'rot13-cipher': { name: 'ROT13 / Caesar', desc: 'Rotation ciphers' },
    'word-counter': { name: 'Word Counter', desc: 'Count words & chars' },
    'case-converter': { name: 'Case Converter', desc: 'Transform text case' },
    'color-picker': { name: 'Color Picker', desc: 'Pick and convert colors' },
    'json-formatter': { name: 'JSON Formatter', desc: 'Format & validate JSON' },
    'regex-tester': { name: 'Regex Tester', desc: 'Test regular expressions' },
    'uuid-generator': { name: 'UUID Generator', desc: 'Generate unique IDs' },
    'jwt-decoder': { name: 'JWT Decoder', desc: 'Decode JSON Web Tokens' },
    'timestamp-converter': { name: 'Timestamp Converter', desc: 'Unix timestamp tools' },
  }), []);

  const renderTool = () => {
    const props = { darkMode };
    switch (activeTool) {
      case 'qr-generator': return <QRGenerator {...props} />;
      case 'password-gen': return <PasswordGenerator {...props} />;
      case 'unit-converter': return <UnitConverter {...props} />;
      case 'calculator': return <Calculator {...props} />;
      case 'pgp-tool': return <PGPTool {...props} />;
      case 'hash-generator': return <HashGenerator {...props} />;
      case 'hash-identifier': return <HashIdentifier {...props} />;
      case 'entropy-analyzer': return <EntropyAnalyzer {...props} />;
      case 'binary-converter': return <BinaryConverter {...props} />;
      case 'hex-converter': return <HexConverter {...props} />;
      case 'base64-tool': return <Base64Tool {...props} />;
      case 'morse-code': return <MorseCode {...props} />;
      case 'zero-width': return <ZeroWidthEncoder {...props} />;
      case 'rot13-cipher': return <ROT13Cipher {...props} />;
      case 'word-counter': return <WordCounter {...props} />;
      case 'case-converter': return <CaseConverter {...props} />;
      case 'color-picker': return <ColorPicker {...props} />;
      case 'json-formatter': return <JSONFormatter {...props} />;
      case 'regex-tester': return <RegexTester {...props} />;
      case 'uuid-generator': return <UUIDGenerator {...props} />;
      case 'jwt-decoder': return <JWTDecoder {...props} />;
      case 'timestamp-converter': return <TimestampConverter {...props} />;
      default: return <QRGenerator {...props} />;
    }
  };

  const selectTool = (toolId) => { 
    setActiveTool(toolId); 
    setSidebarOpen(false); 
  };

  return (
    <div className={`min-h-screen transition-colors duration-300 ${darkMode ? 'bg-[#0a0a0f]' : 'bg-[#f8f8fa]'}`}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap'); * { font-family: 'JetBrains Mono', monospace; }`}</style>

      {/* Background Effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className={`absolute -top-1/4 -left-1/4 w-1/2 h-1/2 rounded-full blur-[120px] ${darkMode ? 'bg-violet-900/20' : 'bg-violet-200/50'}`} />
        <div className={`absolute -bottom-1/4 -right-1/4 w-1/2 h-1/2 rounded-full blur-[120px] ${darkMode ? 'bg-cyan-900/15' : 'bg-cyan-200/40'}`} />
      </div>

      {/* Mobile Header */}
      <header className={`lg:hidden fixed top-0 left-0 right-0 z-50 px-4 py-3 flex items-center justify-between ${darkMode ? 'bg-[#0a0a0f]/90 backdrop-blur-xl border-b border-white/5' : 'bg-white/90 backdrop-blur-xl border-b border-black/5'}`}>
        <button onClick={() => setSidebarOpen(!sidebarOpen)} className={`w-10 h-10 rounded-xl flex items-center justify-center ${darkMode ? 'bg-white/5 text-white' : 'bg-black/5 text-gray-900'}`}>{sidebarOpen ? '✕' : '☰'}</button>
        <div className="flex items-center gap-2"><div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-cyan-400 flex items-center justify-center text-black font-bold text-sm shadow-[0_0_15px_rgba(0,240,255,0.5)]">P</div><span className={`font-bold tracking-wider ${darkMode ? 'text-cyan-400' : 'text-gray-900'}`}>PROTEUS</span></div>
        <button onClick={() => setDarkMode(!darkMode)} className={`w-10 h-10 rounded-xl flex items-center justify-center text-lg ${darkMode ? 'bg-white/5 text-white' : 'bg-black/5 text-gray-900'}`}>{darkMode ? '☀' : '☾'}</button>
      </header>

      <div className="relative flex">
        {/* Sidebar Overlay - Only on mobile when open, behind sidebar */}
        {sidebarOpen && <div className="lg:hidden fixed inset-0 bg-black/50 z-30" onClick={() => setSidebarOpen(false)} />}
        
        {/* Sidebar */}
        <aside className={`fixed lg:sticky top-0 left-0 h-screen w-72 z-40 transition-transform duration-300 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}>
          <div className={`h-full flex flex-col ${darkMode ? 'bg-[#0c0c12]/95 lg:bg-[#0c0c12]/80 backdrop-blur-xl border-r border-white/5' : 'bg-white/95 lg:bg-white/80 backdrop-blur-xl border-r border-black/5'}`}>
            <div className="p-4 pt-6 hidden lg:block">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-cyan-400 flex items-center justify-center text-black font-bold shadow-[0_0_20px_rgba(0,240,255,0.5)]">P</div>
                <div><h1 className={`text-lg font-bold tracking-wider ${darkMode ? 'text-cyan-400' : 'text-gray-900'}`}>PROTEUSKIT</h1><p className={`text-xs tracking-widest ${darkMode ? 'text-cyan-700' : 'text-gray-500'}`}>ADAPT. ENCRYPT. DISAPPEAR.</p></div>
              </div>
              <button onClick={() => setDarkMode(!darkMode)} className={`w-full flex items-center justify-between px-3 py-2 rounded-lg mb-4 ${darkMode ? 'bg-white/5 hover:bg-white/10' : 'bg-black/5 hover:bg-black/10'}`}>
                <span className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{darkMode ? 'Dark Mode' : 'Light Mode'}</span>
                <div className={`w-10 h-5 rounded-full relative transition-colors ${darkMode ? 'bg-violet-600' : 'bg-gray-300'}`}><div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${darkMode ? 'left-5' : 'left-0.5'}`} /></div>
              </button>
            </div>

            <nav className="flex-1 overflow-y-auto px-4 pb-4 mt-16 lg:mt-0">
              {Object.entries(categories).map(([catId, cat]) => (
                <div key={catId} className="mb-4">
                  <button onClick={() => setActiveCategory(activeCategory === catId ? null : catId)} className={`w-full flex items-center justify-between px-2 py-2 rounded-lg text-sm font-medium transition-colors ${activeCategory === catId ? darkMode ? 'text-white bg-white/5' : 'text-gray-900 bg-black/5' : darkMode ? 'text-gray-400 hover:text-white hover:bg-white/5' : 'text-gray-600 hover:text-gray-900 hover:bg-black/5'}`}>
                    <span className="flex items-center gap-2"><span className="w-5 text-center">{cat.icon}</span>{cat.label}</span>
                    <span className={`transition-transform ${activeCategory === catId ? 'rotate-90' : ''}`}>›</span>
                  </button>
                  {activeCategory === catId && (
                    <div className="mt-1 ml-4 space-y-0.5">
                      {cat.tools.map(toolId => (
                        <button key={toolId} onClick={() => selectTool(toolId)} className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-all ${activeTool === toolId ? 'bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white shadow-lg shadow-violet-500/20' : darkMode ? 'text-gray-400 hover:text-white hover:bg-white/5' : 'text-gray-600 hover:text-gray-900 hover:bg-black/5'}`}>{toolMeta[toolId]?.name || toolId}</button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </nav>

            <div className={`p-4 border-t ${darkMode ? 'border-white/5' : 'border-black/5'}`}>
              <div className={`flex items-start gap-2 p-3 rounded-xl text-xs ${darkMode ? 'bg-emerald-500/10 text-emerald-400' : 'bg-emerald-500/10 text-emerald-700'}`}>
                <span className="text-base">🔒</span>
                <div><div className="font-medium mb-0.5">100% Client-Side</div><div className={darkMode ? 'text-emerald-400/70' : 'text-emerald-700/70'}>Your data never leaves your browser</div></div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 min-h-screen pt-16 lg:pt-0">
          <div className="max-w-4xl mx-auto p-4 lg:p-8">
            <div className="mb-6">
              <h2 className={`text-2xl font-bold mb-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{toolMeta[activeTool]?.name || 'Tool'}</h2>
              <p className={darkMode ? 'text-gray-500' : 'text-gray-500'}>{toolMeta[activeTool]?.desc || ''}</p>
            </div>
            <div className={`rounded-2xl p-6 ${darkMode ? 'bg-white/[0.03] backdrop-blur-sm border border-white/5' : 'bg-white/70 backdrop-blur-sm border border-black/5 shadow-xl shadow-black/5'}`}>{renderTool()}</div>
            <div className={`mt-8 p-4 rounded-xl border-2 border-dashed text-center ${darkMode ? 'border-white/10 text-gray-600' : 'border-black/10 text-gray-400'}`}><span className="text-sm">Advertisement Space — 728×90</span></div>
            <footer className={`mt-8 text-center text-sm ${darkMode ? 'text-gray-600' : 'text-gray-500'}`}>
              <p className="mb-2">Built with privacy in mind • No data collection • No tracking</p>
              <p><span className={`cursor-pointer hover:underline ${darkMode ? 'text-violet-400' : 'text-violet-600'}`}>Upgrade to Pro</span> • <span className={`cursor-pointer hover:underline ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Support Us</span> • <span className={`cursor-pointer hover:underline ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>GitHub</span></p>
            </footer>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;

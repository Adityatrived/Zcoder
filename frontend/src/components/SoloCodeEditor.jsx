import React, { useState, useEffect, useCallback, useRef } from "react";
import Editor from "@monaco-editor/react";
import axios from "axios";
import { LANGUAGE_VERSIONS, CODE_SNIPPETS } from "./constants";
import LanguageSelector from "./LanguageSelector";
import "./SoloCodeEditor.css";

export default function SoloCodeEditor() {
  const [code, setCode] = useState('');
  const [input, setInput] = useState('');
  const [language, setLanguage] = useState("cpp");
  const [output, setOutput] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [currentLine, setCurrentLine] = useState(1);
  const [currentColumn, setCurrentColumn] = useState(1);
  const [savedSnippets, setSavedSnippets] = useState([]);
  const [snippetName, setSnippetName] = useState("");
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [showSnippets, setShowSnippets] = useState(false);
  const [theme, setTheme] = useState("light");
  const [fontSize, setFontSize] = useState(14);
  const editorRef = useRef(null);

  // Load saved data from localStorage
  useEffect(() => {
    const loadData = () => {
      const savedSnippets = localStorage.getItem("codeSnippets");
      const savedTheme = localStorage.getItem("editorTheme");
      const savedFontSize = localStorage.getItem("editorFontSize");
      
      if (savedSnippets) setSavedSnippets(JSON.parse(savedSnippets));
      if (savedTheme) setTheme(savedTheme);
      if (savedFontSize) setFontSize(parseInt(savedFontSize));
    };
    
    loadData();
  }, []);

  // Save data to localStorage
  useEffect(() => {
    localStorage.setItem("codeSnippets", JSON.stringify(savedSnippets));
  }, [savedSnippets]);

  useEffect(() => {
    localStorage.setItem("editorTheme", theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem("editorFontSize", fontSize.toString());
  }, [fontSize]);

  // Set default snippet when language changes
  useEffect(() => {
    if (CODE_SNIPPETS[language]) {
      setCode(CODE_SNIPPETS[language]);
    }
  }, [language, setCode]);

  const runCode = useCallback(async () => {
    if (!code.trim()) {
      setOutput("No code to run");
      return;
    }

    setIsRunning(true);
    setOutput("Running...");
    
    try {
      const response = await axios.post(import.meta.env.VITE_JUDGE, {
        language,
        version: LANGUAGE_VERSIONS[language],
        files: [{ content: code.trim() }],
        stdin: input,
      });

      const result = response.data.run.output || "No output";
      setOutput(result);
    } catch (err) {
      const errorMsg = err.response?.data?.message || 
                      err.response?.data?.compile?.output ||
                      err.message ||
                      "Error running code";
      setOutput(`Error: ${errorMsg}`);
    } finally {
      setIsRunning(false);
    }
  }, [code, input, language]);

  const handleSaveSnippet = useCallback(() => {
    if (!snippetName.trim()) {
      alert("Please enter a snippet name");
      return;
    }
    
    const newSnippet = {
      id: Date.now(),
      name: snippetName.trim(),
      code: code,
      language,
      input: input,
      createdAt: new Date().toISOString(),
    };

    setSavedSnippets(prev => [...prev, newSnippet]);
    setSnippetName("");
    setShowSaveDialog(false);
  }, [snippetName, code, language, input]);

  const loadSnippet = useCallback((snippet) => {
    onChange(snippet.code);
    onInputChange(snippet.input);
    setLanguage(snippet.language);
    setShowSnippets(false);
  }, [setCode, setInput]);

  const deleteSnippet = useCallback((id) => {
    if (window.confirm("Are you sure you want to delete this snippet?")) {
      setSavedSnippets(prev => prev.filter(snippet => snippet.id !== id));
    }
  }, []);

  const clearOutput = useCallback(() => {
    setOutput("");
  }, []);

  const handleEditorMount = useCallback((editor, monaco) => {
    editorRef.current = editor;
    
    // Add keyboard shortcuts
    editor.addAction({
      id: "run-code",
      label: "Run Code",
      keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter],
      run: runCode,
    });

    // Track cursor position
    editor.onDidChangeCursorPosition((e) => {
      setCurrentLine(e.position.lineNumber);
      setCurrentColumn(e.position.column);
    });

    // Force editor to focus and ensure cursor is visible
    setTimeout(() => {
      editor.focus();
      editor.setPosition({ lineNumber: 1, column: 1 });
    }, 100);
  }, [runCode]);

  const toggleTheme = useCallback(() => {
    setTheme(prev => prev === "dark" ? "light" : "dark");
  }, []);

  const increaseFontSize = useCallback(() => {
    setFontSize(prev => Math.min(prev + 1, 24));
  }, []);

  const decreaseFontSize = useCallback(() => {
    setFontSize(prev => Math.max(prev - 1, 12));
  }, []);

  return (
    <div className={`editor-container ${theme}`}>
      <div className="editor-header">
        <div className="header-left">
          <div className="cursor-position">
            Line {currentLine}, Column {currentColumn}
          </div>
        </div>
        
        <div className="header-right">
          <div className="editor-settings">
            <button
              onClick={toggleTheme}
              className="theme-toggle"
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? "🌙" : "☀️"}
            </button>
            
            <div className="font-size-controls">
              <button
                onClick={decreaseFontSize}
                className="font-btn"
                title="Decrease font size"
              >
                A-
              </button>
              <span className="font-size">{fontSize}px</span>
              <button
                onClick={increaseFontSize}
                className="font-btn"
                title="Increase font size"
              >
                A+
              </button>
            </div>
          </div>

          <LanguageSelector language={language} setLanguage={setLanguage} />
          
          <div className="action-buttons">
            <button
              onClick={() => setShowSnippets(!showSnippets)}
              className="snippets-btn"
              title="View saved snippets"
            >
              📁 Snippets ({savedSnippets.length})
            </button>
            <button
              onClick={() => setShowSaveDialog(true)}
              className="save-btn"
              title="Save current code"
            >
              💾 Save
            </button>
            <button
              onClick={runCode}
              className={`run-btn ${isRunning ? "running" : ""}`}
              disabled={isRunning}
              title="Run code (Ctrl+Enter)"
            >
              {isRunning ? "⏳ Running..." : "▶️ Run"}
            </button>
          </div>
        </div>
      </div>

      {showSnippets && (
        <div className="snippets-panel">
          <div className="snippets-header">
            <h3>Saved Snippets</h3>
            <button
              onClick={() => setShowSnippets(false)}
              className="close-btn"
            >
              ✕
            </button>
          </div>
          
          {savedSnippets.length === 0 ? (
            <p className="no-snippets">No snippets saved yet</p>
          ) : (
            <div className="snippets-grid">
              {savedSnippets.map((snippet) => (
                <div key={snippet.id} className="snippet-card">
                  <div className="snippet-header">
                    <h4 className="snippet-title">{snippet.name}</h4>
                    <button
                      onClick={() => deleteSnippet(snippet.id)}
                      className="delete-snippet-btn"
                      title="Delete snippet"
                    >
                      🗑️
                    </button>
                  </div>
                  <div className="snippet-meta">
                    <span className="snippet-lang">{snippet.language}</span>
                    <span className="snippet-date">
                      {new Date(snippet.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="snippet-preview">
                    <code>{snippet.code.substring(0, 100)}...</code>
                  </div>
                  <button
                    onClick={() => loadSnippet(snippet)}
                    className="load-snippet-btn"
                  >
                    Load Snippet
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="editor-main">
        <Editor
          height="1000px"
          language={language}
          theme={theme === "dark" ? "vs-dark" : "vs"}
          value={code}
          onChange={setCode}
          onMount={handleEditorMount}
          loading={<div className="editor-loading">Loading editor...</div>}
          options={{
            fontSize,
            automaticLayout: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            renderWhitespace: "boundary",
            trimAutoWhitespace: true,
            bracketPairColorization: { enabled: true },
            // Fixed cursor options
            cursorBlinking: "blink",
            cursorSmoothCaretAnimation: "off",
            cursorStyle: "line",
            cursorWidth: 2,
            hideCursorInOverviewRuler: false,
            // Better scrolling and rendering
            smoothScrolling: false,
            lineNumbers: "on",
            glyphMargin: true,
            folding: true,
            wordWrap: "on",
            contextmenu: true,
            mouseWheelZoom: true,
            lineNumbersMinChars: 3,
            renderLineHighlight: "line",
            cursorSurroundingLines: 3,
            // Fixed suggestion options
            suggest: {
              preview: true,
              showIcons: true,
              fontSize: fontSize,
              maxVisibleSuggestions: 8,
              showInlineDetails: true,
              showStatusBar: false,
              filterGraceful: true,
              snippetsPreventQuickSuggestions: false,
            },
            quickSuggestions: {
              other: true,
              comments: false,
              strings: false
            },
            suggestOnTriggerCharacters: true,
            acceptSuggestionOnEnter: "on",
            acceptSuggestionOnCommitCharacter: true,
            // Better selection and highlighting
            selectionHighlight: true,
            occurrencesHighlight: true,
            overviewRulerLanes: 2,
            fixedOverflowWidgets: false,
            padding: { top: 10, bottom: 10 },
            // Auto features
            autoClosingBrackets: "always",
            autoClosingQuotes: "always",
            autoIndent: "full",
            formatOnType: true,
            formatOnPaste: true,
            // Performance optimizations
            disableLayerHinting: false,
            disableMonospaceOptimizations: false,
            // Ensure proper rendering
            renderControlCharacters: false,
            renderFinalNewline: "on",
            rulers: [],
            showFoldingControls: "mouseover",
            showUnused: true,
            // Widget positioning
            hover: {
              enabled: true,
              delay: 300,
              sticky: true
            },
            parameterHints: {
              enabled: true,
              cycle: false
            }
          }}
        />
      </div>

      <div className="io-section">
        <div className="input-panel">
          <div className="panel-header">
            <h3>Input</h3>
            <button
              onClick={() => onInputChange("")}
              className="clear-btn"
              title="Clear input"
            >
              Clear
            </button>
          </div>
          <textarea
            className="input-textarea"
            rows="6"
            placeholder="Enter input for your program..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            style={{ fontSize: `${fontSize}px` }}
          />
        </div>

        <div className="output-panel">
          <div className="panel-header">
            <h3>Output</h3>
            <button
              onClick={clearOutput}
              className="clear-btn"
              title="Clear output"
            >
              Clear
            </button>
          </div>
          <pre 
            className={`output-content ${isRunning ? "running" : ""}`}
            style={{ fontSize: `${fontSize}px` }}
          >
            {output || "Output will appear here..."}
          </pre>
        </div>
      </div>

      {showSaveDialog && (
        <div className="modal-overlay" onClick={() => setShowSaveDialog(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Save Code Snippet</h3>
              <button
                onClick={() => setShowSaveDialog(false)}
                className="modal-close"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <input
                type="text"
                placeholder="Enter snippet name..."
                value={snippetName}
                onChange={(e) => setSnippetName(e.target.value)}
                className="snippet-name-input"
                autoFocus
                maxLength={50}
              />
            </div>
            <div className="modal-actions">
              <button 
                onClick={handleSaveSnippet} 
                className="confirm-btn"
                disabled={!snippetName.trim()}
              >
                Save Snippet
              </button>
              <button
                onClick={() => setShowSaveDialog(false)}
                className="cancel-btn"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}  
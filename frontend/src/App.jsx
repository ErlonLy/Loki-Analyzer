import React, { useState, useEffect, useMemo } from 'react';
import { 
  ShieldAlert, 
  Gamepad2, 
  Binary, 
  Hash, 
  Search, 
  FileCode, 
  Lock, 
  Layers, 
  ExternalLink,
  Activity,
  AlertTriangle,
  FolderOpen,
  Folder,
  Code2,
  Clock,
  CheckCircle2,
  SlidersHorizontal,
  ChevronDown,
  ChevronRight,
  Download,
  RefreshCw,
  Play,
  Cpu,
  FileSearch,
  Sparkles,
  Terminal,
  ShieldCheck,
  FolderSync,
  List,
  GitBranch,
  File,
  Eye
} from 'lucide-react';

const isTauri = typeof window !== 'undefined' && Boolean(window.__TAURI_INTERNALS__);

async function tauriInvoke(cmd, args = {}) {
  if (!isTauri) return null;
  const { invoke } = await import('@tauri-apps/api/core');
  return await invoke(cmd, args);
}

const mockReport = {
  app_name: "Overwatch",
  target_path: "D:\\Overwatch",
  target_type: "Game Application / Suite",
  scan_time: "2026-09-30 02:15:00",
  scan_duration_ms: 1385,
  total_files_scanned: 1185,
  binary_files_analyzed: 31,
  game_engine: "Overwatch Engine (Blizzard Proprietary)",
  anticheats: [
    {
      detected: true,
      name: "Blizzard Warden / Overwatch Guard",
      vendor: "Blizzard Entertainment",
      version: "v2.12 (Overwatch 2)",
      driver_file: "None (User-Mode Virtualized & Dynamic Reloc)",
      service_name: "Battle.net Service",
      protection_type: "In-Memory Virtualized Dispatcher & Integrity Scanner",
      evidence: [
        "Encrypted loader module detected: 'Overwatch_loader.dll'",
        "Specialized encrypted PE section found: '.eid'",
        "Dynamic runtime integrity validation signature: '.eidsig'"
      ]
    }
  ],
  protectors_detected: ["Blizzard Overwatch Loader / Guard (Warden)"],
  protections_found: ["Blizzard Protection Module", "Encrypted .eid section"],
  compilers_detected: ["Microsoft Visual C/C++"],
  languages_detected: ["C / C++"],
  middlewares_detected: ["DirectX", "Bink Video", "Vulkan", "AMD FidelityFX"],
  crypto_algorithms: ["AES (Rijndael S-Box)", "SHA-256 (Hash Constants)", "ChaCha20 / Poly1305", "CRC-32 (IEEE Table)"],
  summary_stats: {
    total_executables: 6,
    total_dlls: 25,
    total_drivers: 0,
    packed_count: 2,
    high_entropy_count: 3,
    average_entropy: 6.84,
    max_entropy: 8.0
  },
  files: [
    {
      path: "D:\\Overwatch\\_retail_\\Overwatch.exe",
      filename: "Overwatch.exe",
      relative_path: "_retail_\\Overwatch.exe",
      size_bytes: 64992976,
      sha256: "cee2e2149d5466164bb25d074ec9926502d9c121cf5a8acd573b78c71302fc12",
      format: "PE32+ (64-bit EXE)",
      architecture: "x86_64",
      is_64bit: true,
      is_dotnet: false,
      is_driver: false,
      is_signed: true,
      subsystem: "Windows GUI",
      entry_point: 5747888,
      overall_entropy: 7.76,
      compiler: "Microsoft Visual C/C++",
      linker: "Microsoft Linker",
      possible_language: "C / C++",
      protectors: ["Blizzard Overwatch Loader / Guard (Warden)"],
      detections: [
        {
          category: "Protector",
          name: "Blizzard Protection Module",
          version: "Overwatch 2",
          details: "Encrypted .eid section and Overwatch_loader.dll dynamic dispatch protection",
          confidence: 100
        }
      ],
      sections: [
        { name: ".text", virtual_address: 4096, virtual_size: 48917123, raw_size: 48917504, entropy: 8.0, characteristics: 1610612768, is_executable: true, is_writable: false },
        { name: ".rdata", virtual_address: 48922624, virtual_size: 9453256, raw_size: 9453568, entropy: 6.29, characteristics: 1073741888, is_executable: false, is_writable: false }
      ],
      imports_count: 1,
      imported_dlls: ["Overwatch_loader.dll"],
      exports_count: 76,
      suspicious_imports: [],
      crypto_constants: ["AES (Rijndael S-Box)", "SHA-256 (Hash Constants)", "ChaCha20 / Poly1305", "CRC-32 (IEEE Table)"]
    },
    {
      path: "D:\\Overwatch\\_retail_\\Overwatch_loader.dll",
      filename: "Overwatch_loader.dll",
      relative_path: "_retail_\\Overwatch_loader.dll",
      size_bytes: 37013712,
      sha256: "9f824773cbb7b81fcae127393d2568ab305417852c03831b01a141b7d52a20e4",
      format: "DLL",
      architecture: "x86_64",
      is_64bit: true,
      is_dotnet: false,
      is_driver: false,
      is_signed: true,
      subsystem: "Windows GUI",
      entry_point: 12480,
      overall_entropy: 7.91,
      compiler: "Microsoft Visual C/C++",
      linker: "Microsoft Linker",
      possible_language: "C / C++",
      protectors: ["Blizzard Overwatch Loader / Guard (Warden)"],
      detections: [],
      sections: [],
      imports_count: 24,
      imported_dlls: ["KERNEL32.dll"],
      exports_count: 4,
      suspicious_imports: [],
      crypto_constants: ["AES (Rijndael S-Box)"]
    },
    {
      path: "D:\\Overwatch\\_retail_\\BlizzardBrowser\\BlizzardBrowser.exe",
      filename: "BlizzardBrowser.exe",
      relative_path: "_retail_\\BlizzardBrowser\\BlizzardBrowser.exe",
      size_bytes: 2282704,
      sha256: "592990272d142fb7546c6e2cd7cd703df6d6d30ef4793a641d4298e250a1045a",
      format: "PE32+ (64-bit EXE)",
      architecture: "x86_64",
      is_64bit: true,
      is_dotnet: false,
      is_driver: false,
      is_signed: true,
      subsystem: "Windows GUI",
      entry_point: 1381316,
      overall_entropy: 6.52,
      compiler: "Microsoft Visual C/C++",
      linker: "Microsoft Linker",
      possible_language: "C / C++",
      protectors: [],
      detections: [],
      sections: [],
      imports_count: 330,
      imported_dlls: ["libcef.dll"],
      exports_count: 2,
      suspicious_imports: [],
      crypto_constants: []
    }
  ]
};

// Helper to build a hierarchical tree from file list
function buildFileTree(files) {
  const root = {
    name: "Raiz",
    path: "",
    children: {},
    files: [],
    totalFiles: 0,
    hasProtected: false
  };

  for (const file of files) {
    const normPath = file.relative_path.replace(/\\/g, '/');
    const parts = normPath.split('/');
    let current = root;
    current.totalFiles++;
    if ((file.protectors && file.protectors.length > 0) || file.overall_entropy >= 7.2) {
      current.hasProtected = true;
    }

    // Traverse directory segments
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!current.children[part]) {
        current.children[part] = {
          name: part,
          path: parts.slice(0, i + 1).join('/'),
          children: {},
          files: [],
          totalFiles: 0,
          hasProtected: false
        };
      }
      current = current.children[part];
      current.totalFiles++;
      if ((file.protectors && file.protectors.length > 0) || file.overall_entropy >= 7.2) {
        current.hasProtected = true;
      }
    }

    current.files.push(file);
  }

  return root;
}

// Recursive Tree Node Item Component
function TreeNodeItem({ node, currentPath, onSelectFolder, onSelectFile, expandedFolders, toggleExpand, level = 0 }) {
  const isExpanded = expandedFolders.has(node.path);
  const isSelected = currentPath === node.path;
  const childFolderKeys = Object.keys(node.children);
  const hasChildren = childFolderKeys.length > 0;

  return (
    <div className="select-none text-xs">
      {/* Folder Row */}
      <div 
        className={`flex items-center gap-1.5 py-1.5 px-2 rounded-lg cursor-pointer transition-colors group ${
          isSelected 
            ? 'bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30' 
            : 'hover:bg-white/5 text-gray-300'
        }`}
        style={{ paddingLeft: `${level * 14 + 8}px` }}
        onClick={() => onSelectFolder(node.path)}
      >
        {hasChildren ? (
          <button 
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              toggleExpand(node.path);
            }}
            className="p-0.5 hover:text-white text-gray-500 rounded"
          >
            {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        ) : (
          <span className="w-3.5" />
        )}

        {isExpanded ? (
          <FolderOpen className="w-4 h-4 text-amber-400 shrink-0" />
        ) : (
          <Folder className="w-4 h-4 text-amber-500/80 shrink-0" />
        )}

        <span className="truncate flex-1 font-mono">{node.name}</span>

        {node.hasProtected && (
          <span className="w-2 h-2 rounded-full bg-amber-400 shrink-0 shadow-[0_0_8px_rgba(245,158,11,0.8)]" title="Contém arquivos protegidos ou alta entropia" />
        )}

        <span className="text-[10px] text-gray-500 font-mono px-1.5 py-0.2 rounded bg-black/40 border border-white/5">
          {node.totalFiles}
        </span>
      </div>

      {/* Expanded Child Folders */}
      {isExpanded && (
        <div>
          {childFolderKeys.map((key) => (
            <TreeNodeItem
              key={key}
              node={node.children[key]}
              currentPath={currentPath}
              onSelectFolder={onSelectFolder}
              onSelectFile={onSelectFile}
              expandedFolders={expandedFolders}
              toggleExpand={toggleExpand}
              level={level + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const initialReport = (typeof window !== 'undefined' && window.__LOKI_REPORT__) ? window.__LOKI_REPORT__ : (isTauri ? null : mockReport);

  const [view, setView] = useState(initialReport ? 'DASHBOARD' : 'LAUNCHER');
  const [report, setReport] = useState(initialReport);
  const [targetPathInput, setTargetPathInput] = useState('');
  
  // Scanning state & animated progress bar
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('Iniciando varredura...');
  const [scanningTarget, setScanningTarget] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  // Dashboard filtering & inspection
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [filterType, setFilterType] = useState('ALL');

  // Tree View State
  const [viewMode, setViewMode] = useState('TREE'); // 'TREE' or 'FLAT'
  const [selectedFolder, setSelectedFolder] = useState(''); // "" = root
  const [expandedFolders, setExpandedFolders] = useState(new Set(['', '_retail_']));

  // Update window/document title dynamically to match the application name
  useEffect(() => {
    if (report && report.app_name) {
      document.title = `${report.app_name} - Loki Analyzer`;
    } else {
      document.title = `Loki Analyzer v2.0`;
    }
  }, [report]);

  // Listen to Tauri progress events
  useEffect(() => {
    let unlisten = null;
    if (isTauri) {
      import('@tauri-apps/api/event').then(({ listen }) => {
        listen('scan_progress', (event) => {
          if (event.payload) {
            setProgress(event.payload.percent || 0);
            setStatusMessage(event.payload.message || '');
          }
        }).then(u => { unlisten = u; });
      });
    }
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const handlePickFolder = async () => {
    try {
      setErrorMessage('');
      const selected = await tauriInvoke('pick_folder');
      if (selected) {
        startScan(selected);
      }
    } catch (err) {
      setErrorMessage(String(err));
    }
  };

  const handlePickFile = async () => {
    try {
      setErrorMessage('');
      const selected = await tauriInvoke('pick_file');
      if (selected) {
        startScan(selected);
      }
    } catch (err) {
      setErrorMessage(String(err));
    }
  };

  const startScan = async (path) => {
    if (!path || !path.trim()) return;
    setScanningTarget(path);
    setView('SCANNING');
    setProgress(15);
    setStatusMessage('Indexando diretórios e localizando todos os arquivos...');
    setErrorMessage('');

    const interval = setInterval(() => {
      setProgress(prev => (prev < 90 ? prev + 2 : prev));
    }, 250);

    try {
      const result = await tauriInvoke('run_scan', { path: path.trim() });
      clearInterval(interval);
      setProgress(100);
      setStatusMessage('Varredura completa!');
      setTimeout(() => {
        setReport(result);
        setSelectedFolder('');
        setView('DASHBOARD');
      }, 500);
    } catch (err) {
      clearInterval(interval);
      setErrorMessage(String(err));
      setView('LAUNCHER');
    }
  };

  const handleOpenBrowser = async () => {
    if (!report) return;
    try {
      await tauriInvoke('open_report_in_browser', { report });
    } catch (err) {
      alert("Erro ao abrir no navegador: " + err);
    }
  };

  const handleExportHtml = async () => {
    if (!report) return;
    try {
      const savedPath = await tauriInvoke('save_report_html_dialog', { report });
      if (savedPath) {
        alert("Relatório salvo com sucesso em:\n" + savedPath);
      }
    } catch (err) {
      alert("Erro ao salvar relatório: " + err);
    }
  };

  // Build the hierarchical tree structure
  const fileTree = useMemo(() => {
    return buildFileTree(report?.files || []);
  }, [report?.files]);

  const toggleExpandFolder = (folderPath) => {
    setExpandedFolders(prev => {
      const next = new Set(prev);
      if (next.has(folderPath)) {
        next.delete(folderPath);
      } else {
        next.add(folderPath);
      }
      return next;
    });
  };

  // Filter files based on search, filter type, and active folder in tree mode
  const filteredFiles = useMemo(() => {
    return ((report && report.files) || []).filter(f => {
      const normPath = f.relative_path.replace(/\\/g, '/');

      // If in Tree Mode and a specific folder is selected, filter by that folder
      if (viewMode === 'TREE' && selectedFolder !== '') {
        const folderPrefix = selectedFolder + '/';
        const isInFolder = normPath === selectedFolder || normPath.startsWith(folderPrefix);
        if (!isInFolder) return false;
      }

      // Search query
      const matchesSearch = f.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            normPath.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            (f.protectors || []).some(p => p.toLowerCase().includes(searchTerm.toLowerCase())) ||
                            f.possible_language.toLowerCase().includes(searchTerm.toLowerCase());
      if (!matchesSearch) return false;

      // Type filters
      const fname = (f.filename || '').toLowerCase();
      const fmt = (f.format || '').toUpperCase();

      if (filterType === 'EXE') {
        return fname.endsWith('.exe') || fmt.includes('EXE');
      }
      if (filterType === 'DLL') {
        return fname.endsWith('.dll') || fmt.includes('DLL');
      }
      if (filterType === 'SYS') {
        return fname.endsWith('.sys') || f.is_driver || fmt.includes('SYS') || fmt.includes('DRIVER');
      }
      if (filterType === 'PROTECTED') {
        return (f.protectors && f.protectors.length > 0) || f.overall_entropy >= 7.2;
      }
      if (filterType === 'HIGH_ENTROPY') {
        return f.overall_entropy >= 7.2;
      }

      return true;
    });
  }, [report?.files, viewMode, selectedFolder, searchTerm, filterType]);

  return (
    <div className="min-h-screen bg-[#08090c] text-[#f3f4f6] px-4 py-8 max-w-7xl mx-auto selection:bg-amber-500/30 selection:text-amber-200 font-sans">

      {/* VIEW: LAUNCHER / APP PICKER */}
      {view === 'LAUNCHER' && (
        <div className="flex flex-col items-center justify-center min-h-[80vh] max-w-3xl mx-auto text-center">
          <div className="relative mb-6">
            <div className="w-24 h-24 rounded-3xl bg-gradient-to-tr from-amber-500 via-yellow-400 to-amber-200 flex items-center justify-center shadow-2xl shadow-amber-500/30 ring-4 ring-amber-400/20 mx-auto">
              <ShieldAlert className="w-14 h-14 text-black" />
            </div>
            <span className="absolute -bottom-2 -right-2 px-3 py-0.5 rounded-full text-xs font-black uppercase tracking-widest bg-amber-400 text-black shadow-lg">
              v2.0
            </span>
          </div>

          <h1 className="text-4xl md:text-5xl font-black tracking-tight bg-gradient-to-r from-amber-400 via-yellow-200 to-white bg-clip-text text-transparent">
            Loki Analyzer
          </h1>
          <p className="text-gray-400 mt-2 text-base md:text-lg max-w-xl">
            Analisador Forense Completo de Binários, Anti-Cheats (Kernel Ring 0 & Ring 3), Motores de Jogo e Árvore de Diretórios.
          </p>

          {errorMessage && (
            <div className="w-full mt-4 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Action Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full mt-8">
            <button
              onClick={handlePickFolder}
              className="group p-8 rounded-2xl bg-[#0f1117] hover:bg-[#141720] border border-white/10 hover:border-amber-500/50 transition-all duration-300 shadow-xl hover:shadow-amber-500/10 text-left flex flex-col justify-between cursor-pointer"
            >
              <div>
                <div className="w-12 h-12 rounded-xl bg-amber-500/10 group-hover:bg-amber-500/20 border border-amber-500/30 flex items-center justify-center mb-5 text-amber-400 group-hover:scale-110 transition-transform">
                  <FolderOpen className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold text-white group-hover:text-amber-300 transition-colors">
                  Escanear Pasta Completa
                </h3>
                <p className="text-sm text-gray-400 mt-2 leading-relaxed">
                  Varre recursivamente todas as subpastas, executáveis, drivers, bibliotecas, scripts e assets do jogo.
                </p>
              </div>
              <div className="mt-6 flex items-center gap-2 text-xs font-semibold text-amber-400">
                <span>Selecionar Diretório</span>
                <ChevronDown className="w-4 h-4 -rotate-90 group-hover:translate-x-1 transition-transform" />
              </div>
            </button>

            <button
              onClick={handlePickFile}
              className="group p-8 rounded-2xl bg-[#0f1117] hover:bg-[#141720] border border-white/10 hover:border-amber-500/50 transition-all duration-300 shadow-xl hover:shadow-amber-500/10 text-left flex flex-col justify-between cursor-pointer"
            >
              <div>
                <div className="w-12 h-12 rounded-xl bg-amber-500/10 group-hover:bg-amber-500/20 border border-amber-500/30 flex items-center justify-center mb-5 text-amber-400 group-hover:scale-110 transition-transform">
                  <Binary className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold text-white group-hover:text-amber-300 transition-colors">
                  Escanear Arquivo Único
                </h3>
                <p className="text-sm text-gray-400 mt-2 leading-relaxed">
                  Inspecione individualmente qualquer .EXE, .DLL, Driver .SYS ou arquivo com análise profunda de seções e IAT.
                </p>
              </div>
              <div className="mt-6 flex items-center gap-2 text-xs font-semibold text-amber-400">
                <span>Escolher Binário</span>
                <ChevronDown className="w-4 h-4 -rotate-90 group-hover:translate-x-1 transition-transform" />
              </div>
            </button>
          </div>

          {/* Direct Input & Quick Presets */}
          <div className="w-full mt-8 p-6 rounded-2xl bg-[#0f1117]/80 border border-white/10 text-left">
            <label className="text-xs uppercase font-bold tracking-wider text-gray-400 flex items-center gap-2 mb-2">
              <Terminal className="w-4 h-4 text-amber-400" />
              Ou insira o caminho direto:
            </label>
            <div className="flex gap-3">
              <input
                type="text"
                value={targetPathInput}
                onChange={(e) => setTargetPathInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && startScan(targetPathInput)}
                placeholder="Ex: D:\Overwatch ou C:\Games\DeltaForce"
                className="flex-1 bg-black/40 border border-white/10 focus:border-amber-500/50 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-amber-500 font-mono"
              />
              <button
                onClick={() => startScan(targetPathInput)}
                disabled={!targetPathInput.trim()}
                className="px-6 py-3 rounded-xl bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:pointer-events-none text-black font-bold text-sm flex items-center gap-2 transition-all cursor-pointer shadow-lg shadow-amber-500/20"
              >
                <Play className="w-4 h-4 fill-black" />
                Escanear
              </button>
            </div>

            <div className="flex items-center gap-2 mt-4 text-xs text-gray-400">
              <span>Alvo rápido de teste:</span>
              <button
                onClick={() => {
                  setTargetPathInput('D:\\Overwatch');
                  startScan('D:\\Overwatch');
                }}
                className="px-2.5 py-1 rounded-md bg-white/5 hover:bg-amber-500/20 text-gray-300 hover:text-amber-300 border border-white/10 transition-colors font-mono cursor-pointer"
              >
                D:\Overwatch
              </button>
            </div>
          </div>
        </div>
      )}

      {/* VIEW: SCANNING / ANIMATED CYBERPUNK LOADING BAR */}
      {view === 'SCANNING' && (
        <div className="flex flex-col items-center justify-center min-h-[75vh] max-w-2xl mx-auto text-center">
          <div className="relative mb-8">
            <div className="w-20 h-20 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center relative shadow-[0_0_50px_rgba(245,158,11,0.2)]">
              <ShieldAlert className="w-10 h-10 text-amber-400 animate-pulse" />
              <div className="absolute inset-0 rounded-2xl border border-amber-400/40 animate-ping opacity-25" />
            </div>
          </div>

          <h2 className="text-2xl md:text-3xl font-bold text-white mb-2">
            Analisando Aplicação & Subdiretórios
          </h2>
          <p className="text-sm font-mono text-amber-300/80 bg-amber-500/10 px-4 py-1.5 rounded-full border border-amber-500/20 mb-8 max-w-lg truncate">
            {scanningTarget}
          </p>

          {/* Animated Neon Progress Bar */}
          <div className="w-full bg-[#0f1117] p-6 rounded-2xl border border-white/10 shadow-2xl relative overflow-hidden">
            <div className="flex justify-between items-center text-sm font-bold mb-3">
              <span className="text-gray-300 flex items-center gap-2">
                <Activity className="w-4 h-4 text-amber-400 animate-spin" />
                {statusMessage}
              </span>
              <span className="font-mono text-amber-400 text-base">{progress}%</span>
            </div>

            <div className="w-full h-4 bg-black/60 rounded-full overflow-hidden p-0.5 border border-white/10">
              <div
                className="h-full rounded-full bg-gradient-to-r from-amber-500 via-yellow-400 to-amber-300 transition-all duration-300 shadow-[0_0_20px_rgba(245,158,11,0.6)] relative"
                style={{ width: `${progress}%` }}
              >
                <div className="absolute inset-0 bg-white/20 animate-pulse" />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2 mt-6 text-xs text-gray-500 text-left font-mono">
              <div className={`p-2.5 rounded-lg border ${progress >= 30 ? 'border-amber-500/30 bg-amber-500/5 text-amber-300' : 'border-white/5 bg-black/20'}`}>
                1. Mapeamento & Subpastas
              </div>
              <div className={`p-2.5 rounded-lg border ${progress >= 60 ? 'border-amber-500/30 bg-amber-500/5 text-amber-300' : 'border-white/5 bg-black/20'}`}>
                2. Anti-Cheat & Engines
              </div>
              <div className={`p-2.5 rounded-lg border ${progress >= 90 ? 'border-amber-500/30 bg-amber-500/5 text-amber-300' : 'border-white/5 bg-black/20'}`}>
                3. Entropia & Criptografia
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW: DASHBOARD */}
      {view === 'DASHBOARD' && report && (
        <div>
          {/* Top Main Title Banner & Actions */}
          <header className="flex flex-col md:flex-row items-start md:items-center justify-between pb-6 mb-8 border-b border-white/10 gap-4">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-amber-500 via-yellow-400 to-amber-200 flex items-center justify-center shadow-lg shadow-amber-500/25 ring-2 ring-amber-400/30 shrink-0">
                <ShieldAlert className="w-8 h-8 text-black" />
              </div>
              <div>
                <div className="flex items-center gap-3 flex-wrap">
                  <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-amber-400 via-yellow-200 to-white bg-clip-text text-transparent">
                    {report.app_name || "Loki Analyzer"}
                  </h1>
                  <span className="px-3 py-1 text-xs font-bold uppercase tracking-wider rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    Relatório de Análise
                  </span>
                </div>
                <p className="text-sm text-gray-400 mt-1 flex items-center gap-2 flex-wrap">
                  <FolderOpen className="w-4 h-4 text-gray-500 shrink-0" />
                  <span className="font-mono text-gray-300 text-xs sm:text-sm break-all">{report.target_path}</span>
                  <span className="text-xs text-gray-500 flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" /> {report.scan_duration_ms}ms
                  </span>
                </p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-3 w-full md:w-auto">
              <button
                onClick={() => setView('LAUNCHER')}
                className="px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 hover:text-white text-xs font-bold flex items-center gap-2 transition-all cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
                Nova Análise
              </button>

              {isTauri && (
                <>
                  <button
                    onClick={handleOpenBrowser}
                    className="px-4 py-2.5 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-300 text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-lg shadow-amber-500/10"
                  >
                    <ExternalLink className="w-4 h-4" />
                    Abrir no Navegador
                  </button>
                  <button
                    onClick={handleExportHtml}
                    className="px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 hover:text-white text-xs font-bold flex items-center gap-2 transition-all cursor-pointer"
                  >
                    <Download className="w-4 h-4" />
                    Exportar HTML
                  </button>
                </>
              )}
            </div>
          </header>

          {/* Anti-Cheat Hero Banner */}
          {report.anticheats && report.anticheats.length > 0 ? (
            <div className="mb-8 rounded-2xl bg-gradient-to-r from-red-950/40 via-amber-950/20 to-black border-2 border-red-500/40 p-6 shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
                <ShieldAlert className="w-64 h-64 text-red-500" />
              </div>
              <div className="relative z-10">
                <div className="flex items-center gap-2.5 text-red-400 font-bold tracking-widest text-xs uppercase mb-2">
                  <ShieldAlert className="w-5 h-5 text-red-400 animate-pulse" />
                  SISTEMA DE SEGURANÇA / ANTI-CHEAT DETECTADO
                </div>
                {report.anticheats.map((ac, idx) => (
                  <div key={idx} className="mt-3">
                    <div className="flex flex-wrap items-baseline gap-3">
                      <h2 className="text-2xl font-black text-white">{ac.name}</h2>
                      {ac.version && (
                        <span className="px-2.5 py-0.5 rounded-md text-xs font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                          {ac.version}
                        </span>
                      )}
                      <span className="text-xs text-gray-400 font-mono">Vendor: {ac.vendor}</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-white/10 text-sm">
                      <div>
                        <span className="text-gray-400 block text-xs uppercase font-semibold">Tipo de Proteção / Camada</span>
                        <p className="text-gray-200 mt-0.5 font-medium">{ac.protection_type}</p>
                      </div>
                      <div>
                        <span className="text-gray-400 block text-xs uppercase font-semibold">Módulo de Driver / Serviço</span>
                        <p className="text-gray-200 mt-0.5 font-mono text-xs">{ac.driver_file || ac.service_name}</p>
                      </div>
                    </div>

                    {ac.evidence && ac.evidence.length > 0 && (
                      <div className="mt-4 pt-3 border-t border-white/5">
                        <span className="text-xs font-semibold text-gray-400 block mb-2">Evidências e Artefatos Identificados:</span>
                        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                          {ac.evidence.map((ev, i) => (
                            <li key={i} className="flex items-center gap-2 text-amber-200/90 bg-amber-500/10 px-3 py-1.5 rounded-lg border border-amber-500/20 font-mono">
                              <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                              <span className="truncate">{ev}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="mb-8 rounded-2xl bg-[#0f1117] border border-white/10 p-6 flex items-center gap-4">
              <ShieldCheck className="w-10 h-10 text-emerald-400 shrink-0" />
              <div>
                <h3 className="text-lg font-bold text-white">Nenhum Anti-Cheat Conhecido Detectado</h3>
                <p className="text-sm text-gray-400 mt-0.5">
                  Não foram identificadas assinaturas de Anti-Cheats de Kernel (Ring 0) ou scanners de integridade de terceiros.
                </p>
              </div>
            </div>
          )}

          {/* 4 HIGH-VISIBILITY METRIC CARDS */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {/* Card 1: Proteções / Packers */}
            <div className="p-5 rounded-2xl bg-[#0f1117] border border-white/10 shadow-lg relative overflow-hidden flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-400">Proteções / Packers</span>
                  <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    <Lock className="w-5 h-5" />
                  </div>
                </div>
                <div className="text-lg font-black text-white">
                  {report.protectors_detected && report.protectors_detected.length > 0 ? (
                    <div className="space-y-1">
                      {report.protectors_detected.map((p, i) => (
                        <div key={i} className="text-amber-300 font-bold text-sm bg-amber-500/10 px-2.5 py-1 rounded-md border border-amber-500/20 inline-block mr-1 mb-1">
                          {p}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-400 text-sm font-semibold">Nenhuma Proteção DiE</span>
                  )}
                </div>
              </div>
              <span className="text-xs text-gray-500 mt-4 block">VMProtect, Themida, UPX, Denuvo</span>
            </div>

            {/* Card 2: Motor / Engine */}
            <div className="p-5 rounded-2xl bg-[#0f1117] border border-white/10 shadow-lg relative overflow-hidden flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-400">Motor de Jogo</span>
                  <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    <Gamepad2 className="w-5 h-5" />
                  </div>
                </div>
                <div className="text-lg font-black text-white">
                  {report.game_engine ? (
                    <span className="text-cyan-300 text-sm font-bold bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/20 inline-block">
                      {report.game_engine}
                    </span>
                  ) : (
                    <span className="text-gray-400 text-sm font-semibold">Engine Desconhecida / Nativo</span>
                  )}
                </div>
              </div>
              <span className="text-xs text-gray-500 mt-4 block">Unreal, Unity, Overwatch, Godot, Source</span>
            </div>

            {/* Card 3: Possível Linguagem */}
            <div className="p-5 rounded-2xl bg-[#0f1117] border border-white/10 shadow-lg relative overflow-hidden flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-400">Possível Linguagem</span>
                  <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    <Code2 className="w-5 h-5" />
                  </div>
                </div>
                <div className="text-lg font-black text-white">
                  {report.languages_detected && report.languages_detected.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {report.languages_detected.map((lang, i) => (
                        <span key={i} className="text-purple-300 font-bold text-xs bg-purple-500/10 px-2.5 py-1 rounded-md border border-purple-500/20">
                          {lang}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-400 text-sm font-semibold">C / C++ (Nativo)</span>
                  )}
                </div>
              </div>
              <span className="text-xs text-gray-500 mt-4 block">C++, Rust, Go, C# (.NET), Python, Lua</span>
            </div>

            {/* Card 4: Criptografia Identificada */}
            <div className="p-5 rounded-2xl bg-[#0f1117] border border-white/10 shadow-lg relative overflow-hidden flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-400">Criptografia Identificada</span>
                  <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <Hash className="w-5 h-5" />
                  </div>
                </div>
                <div className="text-lg font-black text-white">
                  {report.crypto_algorithms && report.crypto_algorithms.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {report.crypto_algorithms.map((c, i) => (
                        <span key={i} className="text-emerald-300 font-mono text-xs bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                          {c.split(' ')[0]}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-400 text-sm font-semibold">Nenhuma Constante S-Box</span>
                  )}
                </div>
              </div>
              <span className="text-xs text-gray-500 mt-4 block">AES, SHA-256, ChaCha20, MD5, CRC32</span>
            </div>
          </div>

          {/* Quick Summary Stats Bar (Interactive) */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 mb-8">
            <div 
              onClick={() => setFilterType('ALL')}
              className={`p-3.5 rounded-xl bg-[#0f1117] border transition-all cursor-pointer ${filterType === 'ALL' ? 'border-amber-500/60 shadow-lg shadow-amber-500/10' : 'border-white/5 hover:border-amber-500/40'}`}
            >
              <span className="text-[11px] font-semibold text-gray-400 uppercase block">Total Arquivos</span>
              <span className="text-xl font-black text-white">{report.files?.length ?? 0}</span>
            </div>
            <div 
              onClick={() => setFilterType(filterType === 'EXE' ? 'DLL' : 'EXE')}
              className={`p-3.5 rounded-xl bg-[#0f1117] border transition-all cursor-pointer ${filterType === 'EXE' || filterType === 'DLL' ? 'border-amber-500/60 shadow-lg shadow-amber-500/10' : 'border-white/5 hover:border-amber-500/40'}`}
            >
              <span className="text-[11px] font-semibold text-gray-400 uppercase block">Binários / DLLs</span>
              <span className="text-xl font-black text-white">{report.binary_files_analyzed ?? 0}</span>
            </div>
            <div 
              onClick={() => setFilterType('SYS')}
              className={`p-3.5 rounded-xl bg-[#0f1117] border transition-all cursor-pointer ${filterType === 'SYS' ? 'border-amber-500/60 shadow-lg shadow-amber-500/10' : 'border-white/5 hover:border-amber-500/40'}`}
            >
              <span className="text-[11px] font-semibold text-gray-400 uppercase block">Drivers Kernel</span>
              <span className="text-xl font-black text-white">{report.summary_stats?.total_drivers ?? 0}</span>
            </div>
            <div 
              onClick={() => setFilterType('PROTECTED')}
              className={`p-3.5 rounded-xl bg-[#0f1117] border transition-all cursor-pointer ${filterType === 'PROTECTED' ? 'border-amber-500/60 shadow-lg shadow-amber-500/10' : 'border-white/5 hover:border-amber-500/40'}`}
            >
              <span className="text-[11px] font-semibold text-gray-400 uppercase block">Arquivos Protegidos</span>
              <span className="text-xl font-black text-amber-400">{report.summary_stats?.packed_count ?? 0}</span>
            </div>
            <div 
              onClick={() => setFilterType('HIGH_ENTROPY')}
              className={`p-3.5 rounded-xl bg-[#0f1117] border transition-all cursor-pointer ${filterType === 'HIGH_ENTROPY' ? 'border-amber-500/60 shadow-lg shadow-amber-500/10' : 'border-white/5 hover:border-amber-500/40'}`}
            >
              <span className="text-[11px] font-semibold text-gray-400 uppercase block">Alta Entropia (&gt;7.2)</span>
              <span className="text-xl font-black text-amber-400">{report.summary_stats?.high_entropy_count ?? 0}</span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#0f1117] border border-white/5">
              <span className="text-[11px] font-semibold text-gray-400 uppercase block">Entropia Média</span>
              <span className="text-xl font-black text-white">{report.summary_stats?.average_entropy ?? 0.0}</span>
            </div>
          </div>

          {/* Search, Filter & View Mode Bar */}
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 mb-4">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-gray-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Pesquisar arquivo, extensão, proteção, linguagem..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-[#0f1117] border border-white/10 focus:border-amber-500/50 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 font-mono"
              />
            </div>

            {/* View Mode Toggle: Tree vs Flat List */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center bg-[#0f1117] p-1 rounded-xl border border-white/10">
                <button
                  onClick={() => setViewMode('TREE')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                    viewMode === 'TREE' 
                      ? 'bg-amber-500 text-black shadow-md shadow-amber-500/20' 
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <GitBranch className="w-3.5 h-3.5" />
                  Árvore de Pastas
                </button>
                <button
                  onClick={() => setViewMode('FLAT')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                    viewMode === 'FLAT' 
                      ? 'bg-amber-500 text-black shadow-md shadow-amber-500/20' 
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <List className="w-3.5 h-3.5" />
                  Lista Geral ({report.files?.length || 0})
                </button>
              </div>

              {/* Type Filters */}
              <div className="flex items-center gap-1 overflow-x-auto text-xs font-semibold">
                <button
                  onClick={() => setFilterType('ALL')}
                  className={`px-2.5 py-1.5 rounded-lg border transition-all cursor-pointer ${filterType === 'ALL' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm' : 'bg-[#0f1117] text-gray-400 border-white/10 hover:border-white/20'}`}
                >
                  Todos
                </button>
                <button
                  onClick={() => setFilterType('EXE')}
                  className={`px-2.5 py-1.5 rounded-lg border transition-all cursor-pointer ${filterType === 'EXE' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm' : 'bg-[#0f1117] text-gray-400 border-white/10 hover:border-white/20'}`}
                >
                  EXEs
                </button>
                <button
                  onClick={() => setFilterType('DLL')}
                  className={`px-2.5 py-1.5 rounded-lg border transition-all cursor-pointer ${filterType === 'DLL' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm' : 'bg-[#0f1117] text-gray-400 border-white/10 hover:border-white/20'}`}
                >
                  DLLs
                </button>
                <button
                  onClick={() => setFilterType('SYS')}
                  className={`px-2.5 py-1.5 rounded-lg border transition-all cursor-pointer ${filterType === 'SYS' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm' : 'bg-[#0f1117] text-gray-400 border-white/10 hover:border-white/20'}`}
                >
                  Drivers
                </button>
                <button
                  onClick={() => setFilterType('PROTECTED')}
                  className={`px-2.5 py-1.5 rounded-lg border transition-all cursor-pointer ${filterType === 'PROTECTED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm' : 'bg-[#0f1117] text-gray-400 border-white/10 hover:border-white/20'}`}
                >
                  Protegidos
                </button>
              </div>
            </div>
          </div>

          {/* MAIN EXPLORER: TREE + TABLE OR FLAT TABLE */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            
            {/* Left Column: Interactive File Tree (When viewMode === 'TREE') */}
            {viewMode === 'TREE' && (
              <div className="lg:col-span-4 bg-[#0f1117] border border-white/10 rounded-2xl p-4 shadow-xl flex flex-col max-h-[750px] overflow-hidden">
                <div className="flex items-center justify-between pb-3 mb-2 border-b border-white/10">
                  <span className="text-xs uppercase font-bold tracking-wider text-gray-400 flex items-center gap-1.5">
                    <FolderOpen className="w-4 h-4 text-amber-400" />
                    Árvore de Diretórios
                  </span>
                  <button
                    onClick={() => setSelectedFolder('')}
                    className="text-[11px] text-amber-400 hover:text-amber-300 font-mono cursor-pointer"
                  >
                    Ver Tudo ({report.files?.length || 0})
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto pr-1 space-y-0.5">
                  <TreeNodeItem
                    node={fileTree}
                    currentPath={selectedFolder}
                    onSelectFolder={setSelectedFolder}
                    onSelectFile={setSelectedFile}
                    expandedFolders={expandedFolders}
                    toggleExpand={toggleExpandFolder}
                  />
                </div>
              </div>
            )}

            {/* Right Column: Files Table */}
            <div className={`${viewMode === 'TREE' ? 'lg:col-span-8' : 'lg:col-span-12'} bg-[#0f1117] border border-white/10 rounded-2xl overflow-hidden shadow-2xl flex flex-col`}>
              {/* Breadcrumb / Active Folder Header */}
              {viewMode === 'TREE' && (
                <div className="px-4 py-3 bg-black/40 border-b border-white/10 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 text-gray-400 font-mono truncate">
                    <Folder className="w-4 h-4 text-amber-400 shrink-0" />
                    <button 
                      onClick={() => setSelectedFolder('')} 
                      className={`hover:text-amber-300 cursor-pointer ${selectedFolder === '' ? 'text-amber-300 font-bold' : ''}`}
                    >
                      Raiz
                    </button>
                    {selectedFolder && selectedFolder.split('/').map((seg, i, arr) => {
                      const subPath = arr.slice(0, i + 1).join('/');
                      const isLast = i === arr.length - 1;
                      return (
                        <React.Fragment key={subPath}>
                          <span className="text-gray-600">/</span>
                          <button
                            onClick={() => setSelectedFolder(subPath)}
                            className={`hover:text-amber-300 cursor-pointer ${isLast ? 'text-amber-300 font-bold' : ''}`}
                          >
                            {seg}
                          </button>
                        </React.Fragment>
                      );
                    })}
                  </div>
                  <span className="text-[11px] text-gray-400 font-mono shrink-0">
                    {filteredFiles.length} {filteredFiles.length === 1 ? 'arquivo' : 'arquivos'}
                  </span>
                </div>
              )}

              {/* Table */}
              <div className="overflow-x-auto max-h-[700px] overflow-y-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="sticky top-0 bg-[#0c0d12] z-10">
                    <tr className="border-b border-white/10 text-gray-400 uppercase text-[11px] font-bold tracking-wider">
                      <th className="py-3 px-4">Arquivo</th>
                      <th className="py-3 px-4">Formato / Tam</th>
                      <th className="py-3 px-4">Entropia</th>
                      <th className="py-3 px-4">Linguagem</th>
                      <th className="py-3 px-4">Proteção / Assinatura</th>
                      <th className="py-3 px-4 text-right">Ação</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {filteredFiles.map((file, idx) => {
                      const isHighEntropy = file.overall_entropy >= 7.2;
                      const hasProtector = file.protectors && file.protectors.length > 0;
                      const isExe = file.format.includes('EXE');
                      const isDll = file.format.includes('DLL');

                      return (
                        <tr key={idx} className="hover:bg-white/[0.02] transition-colors group">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2.5">
                              {isExe ? (
                                <Binary className="w-4 h-4 text-amber-400 shrink-0" />
                              ) : isDll ? (
                                <Binary className="w-4 h-4 text-cyan-400 shrink-0" />
                              ) : (
                                <FileCode className="w-4 h-4 text-gray-500 shrink-0" />
                              )}
                              <div className="truncate max-w-xs">
                                <span className="font-bold text-white group-hover:text-amber-300 transition-colors block truncate">
                                  {file.filename}
                                </span>
                                <span className="text-[10px] text-gray-500 font-mono block truncate" title={file.relative_path}>
                                  {file.relative_path}
                                </span>
                              </div>
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <div>
                              <span className="px-1.5 py-0.5 rounded bg-white/5 text-gray-300 font-mono text-[10px] block truncate">
                                {file.format}
                              </span>
                              <span className="text-gray-500 font-mono text-[10px]">
                                {(file.size_bytes / 1024 < 1024) 
                                  ? `${(file.size_bytes / 1024).toFixed(1)} KB` 
                                  : `${(file.size_bytes / (1024 * 1024)).toFixed(2)} MB`}
                              </span>
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <span className={`font-mono font-bold text-[11px] ${isHighEntropy ? 'text-amber-400' : 'text-gray-300'}`}>
                                {file.overall_entropy.toFixed(2)}
                              </span>
                              <div className="w-12 h-1.5 bg-black/60 rounded-full overflow-hidden border border-white/10 hidden sm:block">
                                <div
                                  className={`h-full rounded-full ${isHighEntropy ? 'bg-amber-400' : 'bg-cyan-500'}`}
                                  style={{ width: `${(file.overall_entropy / 8.0) * 100}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <span className="text-purple-300 font-semibold bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20 text-[10px]">
                              {file.possible_language || "Nativo"}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            {hasProtector ? (
                              <span className="text-amber-300 font-bold bg-amber-500/15 px-2 py-0.5 rounded border border-amber-500/30 text-[10px]">
                                {file.protectors[0]}
                              </span>
                            ) : isHighEntropy ? (
                              <span className="text-amber-400/90 text-[10px] font-mono">Alta Entropia (&gt;7.2)</span>
                            ) : (
                              <span className="text-gray-500 text-[10px]">{file.is_signed ? 'Assinado' : 'Padrão'}</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => setSelectedFile(file)}
                              className="px-2.5 py-1 rounded-md bg-white/5 hover:bg-amber-500/20 text-gray-300 hover:text-amber-300 border border-white/10 hover:border-amber-500/30 font-semibold transition-all cursor-pointer text-[11px]"
                            >
                              Inspecionar
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                    {filteredFiles.length === 0 && (
                      <tr>
                        <td colSpan="6" className="text-center py-12 text-gray-500">
                          Nenhum arquivo encontrado nesta pasta ou com este filtro.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* MODAL: FILE INSPECTION MODAL */}
      {selectedFile && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f1117] border border-white/20 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
            <div className="p-6 border-b border-white/10 flex items-center justify-between sticky top-0 bg-[#0f1117] z-10">
              <div className="flex items-center gap-3">
                <Binary className="w-6 h-6 text-amber-400" />
                <div>
                  <h3 className="text-lg font-bold text-white">{selectedFile.filename}</h3>
                  <p className="text-xs font-mono text-gray-400 truncate max-w-lg">{selectedFile.path}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedFile(null)}
                className="w-8 h-8 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 flex items-center justify-center text-gray-400 hover:text-white cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* File Metadata Overview */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                  <span className="text-gray-500 block mb-1">Tamanho</span>
                  <span className="font-mono text-white font-bold">{(selectedFile.size_bytes / (1024 * 1024)).toFixed(2)} MB</span>
                </div>
                <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                  <span className="text-gray-500 block mb-1">Entropia Total</span>
                  <span className="font-mono text-amber-400 font-bold">{selectedFile.overall_entropy.toFixed(2)} / 8.0</span>
                </div>
                <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                  <span className="text-gray-500 block mb-1">Linguagem / Compilador</span>
                  <span className="font-semibold text-purple-300">{selectedFile.possible_language}</span>
                </div>
                <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                  <span className="text-gray-500 block mb-1">Assinatura Digital</span>
                  <span className={`font-semibold ${selectedFile.is_signed ? 'text-emerald-400' : 'text-gray-400'}`}>
                    {selectedFile.is_signed ? 'Válida (Assinado)' : 'Não Assinado'}
                  </span>
                </div>
              </div>

              {/* SHA-256 */}
              <div className="p-3 rounded-xl bg-black/40 border border-white/5 text-xs">
                <span className="text-gray-500 block mb-1">Hash SHA-256</span>
                <span className="font-mono text-gray-300 select-all break-all">{selectedFile.sha256}</span>
              </div>

              {/* Sections Table with Entropy */}
              {selectedFile.sections && selectedFile.sections.length > 0 && (
                <div>
                  <h4 className="text-xs uppercase font-bold tracking-wider text-gray-400 mb-3 flex items-center gap-2">
                    <Layers className="w-4 h-4 text-amber-400" />
                    Seções PE e Entropia de Shannon
                  </h4>
                  <div className="border border-white/10 rounded-xl overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-black/50 text-gray-400 border-b border-white/10 text-[11px] font-bold">
                        <tr>
                          <th className="p-2.5">Nome</th>
                          <th className="p-2.5">Endereço Virtual</th>
                          <th className="p-2.5">Tamanho Raw</th>
                          <th className="p-2.5">Entropia</th>
                          <th className="p-2.5">Flags</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 font-mono">
                        {selectedFile.sections.map((sec, i) => (
                          <tr key={i} className="hover:bg-white/[0.02]">
                            <td className="p-2.5 font-bold text-white">{sec.name}</td>
                            <td className="p-2.5 text-gray-400">0x{sec.virtual_address.toString(16).toUpperCase()}</td>
                            <td className="p-2.5 text-gray-400">{sec.raw_size.toLocaleString()} B</td>
                            <td className="p-2.5">
                              <span className={`font-bold ${sec.entropy >= 7.2 ? 'text-amber-400' : 'text-gray-300'}`}>
                                {sec.entropy.toFixed(2)}
                              </span>
                            </td>
                            <td className="p-2.5">
                              <div className="flex gap-1 text-[10px]">
                                {sec.is_executable && <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300">EXEC</span>}
                                {sec.is_writable && <span className="px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-300">WRITE</span>}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Cryptographic Constants & Suspicious APIs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {selectedFile.crypto_constants && selectedFile.crypto_constants.length > 0 && (
                  <div className="p-4 rounded-xl bg-black/40 border border-white/10">
                    <h5 className="font-bold text-emerald-400 mb-2 flex items-center gap-1.5">
                      <Hash className="w-4 h-4" /> Constantes Criptográficas Detectadas
                    </h5>
                    <ul className="space-y-1">
                      {selectedFile.crypto_constants.map((c, i) => (
                        <li key={i} className="font-mono text-gray-300">• {c}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {selectedFile.imported_dlls && selectedFile.imported_dlls.length > 0 && (
                  <div className="p-4 rounded-xl bg-black/40 border border-white/10">
                    <h5 className="font-bold text-cyan-400 mb-2 flex items-center gap-1.5">
                      <Binary className="w-4 h-4" /> Módulos & DLLs Importadas ({selectedFile.imported_dlls.length})
                    </h5>
                    <div className="max-h-32 overflow-y-auto font-mono text-gray-300 space-y-1">
                      {selectedFile.imported_dlls.map((dll, i) => (
                        <div key={i}>• {dll}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="p-4 border-t border-white/10 bg-black/40 flex justify-end">
              <button
                onClick={() => setSelectedFile(null)}
                className="px-5 py-2 rounded-xl bg-white/10 hover:bg-white/20 text-white font-bold text-xs cursor-pointer transition-colors"
              >
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

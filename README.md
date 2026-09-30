# ⚡ Loki Analyzer v2.0

![Loki Analyzer](ico.ico)

**Loki Analyzer** é uma ferramenta de alta performance para análise estática e engenharia reversa de jogos e softwares Windows, desenvolvida do zero em **Rust**, com inteligência e assinaturas baseadas no **Detect It Easy (DiE)** e um dashboard interativo moderno em **React + Tailwind CSS**.

Diferente de scanners convencionais, o Loki Analyzer processa milhares de arquivos em paralelo (usando todos os núcleos da CPU), inspeciona cabeçalhos PE reais, detecta packers, proteções virtuais, módulos de criptografia, e identifica os principais **Anti-Cheats a nível de Kernel (Ring 0) e User-Mode (Ring 3)**.

---

## 🚀 Principais Recursos

- 🏎️ **Motor em Rust Multithread (Rayon)**: Varredura de pastas de jogos pesados (como Overwatch, Delta Force, Valorant) em menos de 1 segundo.
- 🛡️ **Detecção Especializada de Anti-Cheats**:
  - **Tencent ACE (Anti-Cheat Expert)**: drivers `.sys`, serviços, módulos base.
  - **Riot Vanguard**: driver de boot `vgk.sys`, serviço `vgc.exe`.
  - **Easy Anti-Cheat (EAC / EOS)**: módulos integrados e drivers de proteção.
  - **BattlEye**: drivers `BEDaisy.sys`, clientes e launchers.
  - **Blizzard Warden / Overwatch Loader**: módulo de proteção e seções encriptadas (`.eid`).
  - **Denuvo Anti-Cheat & Anti-Tamper (DRM)**, **XIGNCODE3**, **miHoYo/HoYoverse Guard**, etc.
- 🔍 **Inspeção PE Completa (Estilo DiE)**:
  - Detecção de **VMProtect**, **Themida / WinLicense**, **UPX**, **Denuvo**.
  - Cálculo de Entropia de Shannon (global e por seção) sem risco de estouro de memória (OOM).
  - Tabela de seções PE, permissões de memória (EXEC/WRITE), IAT e detecção de APIs de debug suspeitas.
  - Mapeamento de Linguagens de Programação (**C/C++**, **Rust**, **Golang**, **C#/.NET**).
  - Algoritmos criptográficos reais: AES S-Box, SHA-256, SHA-1, MD5, ChaCha20, CRC-32.
- 📊 **Dashboard Web em React Embutido**:
  - Exporta um relatório HTML único e independente (`relatorio_loki.html`) com tema escuro Cyberpunk, filtros rápidos, busca instantânea e modal de inspeção.

---

## 🛠️ Como Usar

### 1. Modo Interativo
Basta dar dois cliques no executável:
```bash
loki_analyzer.exe
```
O programa abrirá o seletor nativo do Windows para você escolher uma pasta de jogo ou um arquivo executável/driver. Assim que a análise terminar, o relatório abrirá automaticamente no seu navegador.

### 2. Linha de Comando / Atalho
Você pode passar o caminho direto ou arrastar e soltar (drag & drop) a pasta/arquivo sobre o `.exe`:
```bash
loki_analyzer.exe "D:\Overwatch"
loki_analyzer.exe "C:\Caminho\Do\Aplicativo.exe"
```

---

## 📦 Compilação a partir do Código Fonte

**Pré-requisitos:**
- Rust 1.80+ (`cargo`)
- Node.js 20+ e `npm`

**Passos:**
1. Compile o dashboard web (React):
   ```bash
   cd frontend
   npm install
   npm run build
   cd ..
   ```
2. Compile o executável Rust:
   ```bash
   cargo build --release
   ```
O executável final estará disponível em:
`target/release/loki_analyzer.exe` (único binário nativo de ~1.2 MB, sem dependências externas).

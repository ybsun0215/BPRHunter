# Shadow Tokens: Uncovering the Broken Permission Revocation Vulnerability in Intelligent Connected Vehicles

<table>
  <tr>
    <td align="center" width="50%">
      <img src="./threat_model.png" width="90%"/><br/>
      <b>Threat Model</b>
    </td>
    <td align="center" width="50%">
      <img src="./framework.png" width="100%"/><br/>
      <b>Framework</b>
    </td>
  </tr>
</table>

## 📋 Overview
When a user revokes a permission, for example unbinding a vehicle, the ICV cloud platform should invalidate the related token immediately. This stops the token from accessing protected resources. If a permission has been revoked but the server still accepts the original token, this creates a **Broken Permission Revocation (BPR)** vulnerability. BPRHunter is designed to detect this type of vulnerability.


---

## 🔗 Architecture

BPRHunter runs as a three-stage pipeline. Each stage reads its inputs from disk, writes its outputs to disk, and hands off to the next stage.

| Stage | Input | Output |
|---|---|---|
| **TDG Construction** | HAR traffic | `auth_tokens.csv`, `refresh_tokens.csv`, `exchange_tokens.csv`, `tdg.json` |
| **VF Logic Inference** | HAR traffic, smali bytecode | `output/vfs/<domain>/update_vf.py`, `_chat_histories.json` |
| **BPR Detection** | `tdg.json`, HAR traffic, VF scripts | `output/testcases/<token>.json`, `output/results/<token>.json` |

---

## 🚀 Quick Start

### ✅ Prerequisites

- Python 3.8+
- API key

### 📦 Install

```bash
pip install -r requirements.txt
```

### ⚙️ Configure

Set your API key, then review `config.py`.
Recently, we found that DeepSeek seems to offer a higher cost-performance ratio. Therefore, we use DeepSeek's models by default.

```python
HAR_FILE      = "input/traffic/demo.har"   # path to your HAR capture
SMALI_DIR     = "input/smali/targetapp"    # root of smali package tree
API_BASE_URL  = "https://api.deepseek.com"
MODEL         = "deepseek-v4-pro"          # inference (reasoning)
CODEGEN_MODEL = "deepseek-v4-flash"        # code generation (stable)
DEMO_MODE     = True                       # mock HTTP — no real network calls
```

### ▶️ Run

```bash
# All three stages
python main.py

# Specific stages
python main.py --stages 1 2   # TDG + VF inference
python main.py --stages 3     # BPR detection (needs prior Stage 1 & 2 output)
```

---

## ⚠️ Demo

The HAR traffic and smali bytecode included in this repository have been anonymized:

- 🌐 All hostnames use the placeholder `apigateway.target-platform.example.com`.
- 📦 All Java package names use the placeholder `com.example.*`.
- 🔑 All credentials use the placeholder values `PLACEHOLDER_ACCESS` / `PLACEHOLDER_SECRET`.
- ✅ No real API keys, secrets, or identifying information are present.

The demo data exists solely to illustrate the pipeline. Since we don't have permission to test against a live target, Stage 3 runs in demo mode (`DEMO_MODE = True`): HTTP requests are intercepted and the original HAR response is returned for every request.

To run against a real target, set `DEMO_MODE = False`, provide real inputs, and point `config.py` at genuine traffic and smali.

import os

# ---------------------------------------------------------------------------
# Paths — project layout
# ---------------------------------------------------------------------------


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HAR_FILE = os.path.join(BASE_DIR, "input", "traffic", "demo.har")

SMALI_DIR = os.path.join(BASE_DIR, "input", "smali", "targetapp")

# ---------------------------------------------------------------------------
# Stage 1 output — TDG Construction
# ---------------------------------------------------------------------------

TDG_DIR            = os.path.join(BASE_DIR, "output", "tdg")
AUTH_TOKEN_CSV     = os.path.join(TDG_DIR, "auth_tokens.csv")
REFRESH_TOKEN_CSV  = os.path.join(TDG_DIR, "refresh_tokens.csv")
EXCHANGE_TOKEN_CSV = os.path.join(TDG_DIR, "exchange_tokens.csv")
TDG_PATH           = os.path.join(TDG_DIR, "tdg.json")

# ---------------------------------------------------------------------------
# Stage 2 output — VF Logic Inference
# ---------------------------------------------------------------------------

VF_DIR = os.path.join(BASE_DIR, "output", "vfs")

# ---------------------------------------------------------------------------
# Stage 3 output — BRP Detection
# ---------------------------------------------------------------------------

TESTCASES_DIR = os.path.join(BASE_DIR, "output", "testcases")
RESULTS_DIR   = os.path.join(BASE_DIR, "output", "results")

# ---------------------------------------------------------------------------
# Token / field filtering  (shared by Stages 1 and 2)
# ---------------------------------------------------------------------------

MIN_ALNUM_LENGTH = 8
SKIP_METHODS     = {"CONNECT", "OPTIONS", "HEAD", "TRACE"}
TIMING_TOLERANCE = 1.0  # seconds; used when matching request timestamps

SKIP_FIELD_NAMES = {
    "host", "content-type", "content-length",
    "accept", "accept-encoding", "accept-language",
    "user-agent", "connection", "origin", "referer",
    "x-requested-with", "cache-control", "param", "device", "type",
    "sec-fetch-site", "mode", "path", "sec-fetch-dest", "time",
    "sec-ch-ua", "id", "mobile", "sec-ch-ua-platform",
    "upgrade-insecure-requests",
}

# ---------------------------------------------------------------------------
# LLM API  (used by Stage 2)
# ---------------------------------------------------------------------------

API_BASE_URL = "https://api.deepseek.com"


API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

MODEL = "xxx"

CODEGEN_MODEL = "xxx"

LLM_TIMEOUT = 300

LLM_CALL_DELAY = 1.5

REASONING_EFFORT = "xhigh"

# ---------------------------------------------------------------------------
# Stage 2 iteration limits
# ---------------------------------------------------------------------------

MAX_INFERENCE_ITERATIONS = 50

MAX_VERIFY_ITERATIONS = 10

MANUAL_VFS = None

# ---------------------------------------------------------------------------
# Stage 3 HTTP settings
# ---------------------------------------------------------------------------

HTTP_TIMEOUT = 10

HTTP_VERIFY_SSL = True

HTTP_PROXIES = None

# ---------------------------------------------------------------------------
# Stage 3 chain execution
# ---------------------------------------------------------------------------

MAX_CHAIN_DEPTH = 10

# ---------------------------------------------------------------------------
# Demo mode  (--demo flag)
# ---------------------------------------------------------------------------

DEMO_MODE = True

# ---------------------------------------------------------------------------
# Stage 3 response comparison
# ---------------------------------------------------------------------------

MODEL_PATH = os.path.join(BASE_DIR, "model", "all-MiniLM-L6-v2")  # To be entered

SIMILARITY_THRESHOLD = 0.90

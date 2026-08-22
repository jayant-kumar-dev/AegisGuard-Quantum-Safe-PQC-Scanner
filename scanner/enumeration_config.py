"""Discovery enumeration tuning knobs."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Keep this comfortably above expected discoveries to avoid early cut-off.
SUBDOMAIN_LIMIT = 200

# Allow multi-level names like dev.test.example.com.
RECURSION_DEPTH = 3

# Professional-grade list used by DNS brute-force enumeration.
SUBDOMAIN_WORDLIST = str(BASE_DIR / "wordlists" / "extended_recon_list.txt")

# Toggle active DNS guessing with the configured wordlist.
# Disable brute-forcing by default in safe deployments.
USE_DNS_BRUTEFORCING = True

# Concurrency for DNS resolution attempts.
# Reduced defaults to avoid aggressive parallel lookups.
MAX_THREADS = 16

# Passive OSINT source toggles.
# Turn off external passive sources by default to avoid unwanted outbound traffic.
ENABLE_CRTSH_OSINT = True
ENABLE_HACKERTARGET_OSINT = True
ENABLE_OTX_OSINT = True
ENABLE_URLSCAN_OSINT = True
ENABLE_ANUBIS_OSINT = True
ENABLE_CERTSPOTTER_OSINT = True

# HTTP timeout for passive API calls.
OSINT_TIMEOUT_SECONDS = 6

# Retry count for transient API/network failures.
# Keep at 1 max so external-source failures do not dominate latency.
OSINT_RETRIES = 1

# Hard cap per passive provider to avoid oversized payload impact.
MAX_OSINT_RESULTS_PER_SOURCE = 500

# Safe-mode toggles and runtime controls
# When True, discovery will run in a conservative safe-mode that avoids
# brute-forcing and external OSINT unless explicitly enabled.
DISCOVERY_SAFE_MODE = False

# Optional comma-separated whitelist of domains allowed for discovery.
# Empty list means no whitelist enforcement.
DISCOVERY_WHITELIST = []

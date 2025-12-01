import os

# ====================== Ollama Configuration ========================= #
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://detector-ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_TEMPERATURE = float(os.getenv('OLLAMA_TEMPERATURE', '0.1'))

# ==================== PostgreSQL Configuration ======================== #
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'postgres')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'security_inc')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'user123')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'password123')

# ==================== Log Preprocessing Configuration ================== #
LOG_DIR = os.getenv('LOG_INPUT_PATH', '/aggregated_logs')
LOG_INPUT_PATH = os.getenv('LOG_INPUT_PATH', '/aggregated_logs')
LOG_FILENAME = os.getenv('LOG_FILENAME','aggregated-20251201-9.ndjson') 
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '10'))  # seconds
RATE_LIMIT_DELAY = float(os.getenv('RATE_LIMIT_DELAY', '1.0'))  # seconds between analyses

# ============================== LLM PROMPTS ============================= #
SYSTEM_LOG_PROMPT = """You are an expert system log security analyst. Analyze this log for security events.

LOG: {log_message}

SEVERITY LEVELS:
- CRITICAL: Active attacks, privilege escalation, root compromise, system breaches
- HIGH: Multiple failed authentication attempts, suspicious sudo usage, unauthorized access
- MEDIUM: Unusual activity requiring investigation, potential reconnaissance
- LOW: Minor anomalies in normal operations
- INFO: Normal system operations with monitoring value

INSTRUCTIONS:
1. Extract ALL relevant information from the log
2. Assess security implications
3. Assign appropriate severity level
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)

OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "hostname": "server hostname from log, or null",
  "service": "service name (sshd, sudo, systemd, kernel, etc), or null",
  "user": "username if present, or null",
  "source_ip": "source IP address if present, or null",
  "event_type": "failed_login|privilege_escalation|system_error|normal",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief security assessment (1-2 sentences)"
}}

REMEMBER: Return ONLY the JSON object, nothing else."""

WEB_LOG_PROMPT = """You are an expert web security analyst. Analyze this HTTP access log for threats.

LOG: {log_message}

THREAT ASSESSMENT:
- CRITICAL: SQL injection with UNION/SELECT, RCE attempts, admin panel brute force, sensitive file access
- HIGH: XSS with script tags, directory traversal (../, /etc/passwd), coordinated scanning, exploitation attempts
- MEDIUM: Suspicious patterns, reconnaissance attempts, unusual request patterns
- LOW: Minor anomalies in normal traffic, isolated suspicious requests
- INFO: Normal traffic (search bots like Googlebot, legitimate browsing, static resources)

INSTRUCTIONS:
1. Identify attack patterns in the request
2. Extract client IP, method, path, status code
3. Assess threat level realistically
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)

OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "source_ip": "client IP address from log",
  "method": "HTTP method (GET, POST, etc)",
  "path": "requested URL path",
  "status_code": status_code_as_integer,
  "attack_type": "sql_injection|xss|path_traversal|admin_scan|brute_force|normal",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief threat assessment (1-2 sentences)"
}}

REMEMBER: Return ONLY the JSON object, nothing else."""

# ============================= Prompt Selection ============================== #
def get_prompt_for_log_type(log_type: str) -> str:
    """
    Get the appropriate prompt template based on log type
    
    Args:
        log_type: Type of log (system, web, application)
    
    Returns:
        Prompt template string
    """
    prompts = {
        'system': SYSTEM_LOG_PROMPT,
        'web': WEB_LOG_PROMPT,
    }

    return prompts.get(log_type, SYSTEM_LOG_PROMPT)



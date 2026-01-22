import json
import time
import requests
import glob
import os
from pathlib import Path
from postgre_store import PostgresStorage
import config

def wait_for_ollama():
    print("Waiting for Ollama...")

    for attempt in range(60):
        try:
            HOST = os.getenv("OLLAMA_HOST")
            PORT = os.getenv("OLLAMA_PORT")
            response = requests.get(f"http://{HOST}:{PORT}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                if any(config.OLLAMA_MODEL in m['name'] for m in models):
                    print(f"✓ Ollama ready with {config.OLLAMA_MODEL}")
                    return True
        except:
            pass
        
        print(f" Attempt {attempt + 1 }/60...")
        time.sleep(2)

    print("Ollama timeout")
    return False

def analyzer(log_message: str, log_type: str):
    prompt_template = config.get_prompt_for_log_type(log_type)
    prompt = prompt_template.format(log_message = log_message)

    try:
        response = requests.post(
            f"{config.OLLAMA_HOST}/api/generate",
            json={
                "model": config.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "temperature": config.OLLAMA_TEMPERATURE
            },
            timeout=config.OLLAMA_TIMEOUT
        )

        if response.status_code != 200:
            print(f"  ✗ Ollama HTTP {response.status_code}")
            return None
        
        result = response.json()
        llm_output = result.get('response', '').strip()

        # Clean markdown code blocks if present
        if '```json' in llm_output:
            llm_output = llm_output.split('```json')[1].split('```')[0].strip()
        elif '```' in llm_output:
            llm_output = llm_output.split('```')[1].split('```')[0].strip()
        
        # Parse JSON
        return json.loads(llm_output)
    except json.JSONDecodeError as e:
        print(f"  ✗ Invalid JSON from LLM: {e}")
        return None
    except Exception as e:
        print(f"  ✗ Ollama error: {e}")
        return None
    
def find_latest_log_file():
    pattern = os.path.join(config.LOG_DIR, 'aggregated*.ndjson')
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key = os.path.getctime)

def tail_file(db: PostgresStorage, log_file: str):
    if not os.path.exists(log_file):
        print(f"⚠ File not found: {log_file}")
        return 0
    
    print(f"Processing: {os.path.basename(log_file)}")
    processed = 0

    with open(log_file, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()

            if line:
                try:
                    log_entry = json.loads(line)
                    message = log_entry.get('message', '')
                    log_type = log_entry.get('fields', {}).get('log_type', 'unknown')
                    
                    if not message:
                        continue
                    analysis = analyzer(message, log_type)

                    if analysis:
                        severity = analysis.get('severity', 'UNKNOWN')

                        incident_id = db.store_anomaly(log_entry, analysis)
                        if incident_id:
                            print(f" Stored as incident #{incident_id}\n")

                    time.sleep(config.RATE_LIMIT_DELAY)

                except json.JSONDecodeError:
                    print(f"Invalid JSON line")
                except Exception as e:
                    print(f"Error processing log: {e}")
            else:
                time.sleep(1)

def main():
    if not wait_for_ollama():
        return
    print("\n Waiting for PostgreSQL...")
    time.sleep(5)

    try:
        db = PostgresStorage()
    except Exception as e:
        print(f"Failed to initialize DB:{e}")
        return
    
    try:
        log_file = find_latest_log_file()

        if not log_file:
            print(f"\n No log files found in {config.LOG_DIR}")
            print("Waiting for logs...")

            while not log_file:
                time.sleep(config.POLL_INTERVAL)
                log_file = find_latest_log_file()
        print(f"Found log file: {os.path.basename(log_file)}\n")

        tail_file(db, log_file)
    except KeyboardInterrupt:
        print("\n\n Stopping analysis...")
    except Exception as e:
        print(f"\n Fatal error: {e}")
    finally:
        db.close()
        print("Shutdown complete")

if __name__ == "__main__":

    main()

#!/usr/bin/env python3
"""
Santa osquery Extension
Provides tables for Santa rules and decisions on macOS
"""

import os
import re
import json
import sqlite3
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

import osquery

SANTA_DB_PATH = "/var/db/santa/rules.db"
SANTA_LOG_PATH = "/var/db/santa/santa.log"
SANTACTL_PATH = "/usr/local/bin/santactl"
LOG_ENTRY_PREFACE = "santad: "


class SantaRulesTable(osquery.TablePlugin):
    """
    osquery table for Santa rules
    """
    def name(self):
        return "santa_rules"

    def columns(self):
        return [
            osquery.TableColumn(name="shasum", type=osquery.STRING),
            osquery.TableColumn(name="state", type=osquery.STRING),
            osquery.TableColumn(name="type", type=osquery.STRING),
            osquery.TableColumn(name="custom_message", type=osquery.STRING),
        ]

    def generate(self, context):
        # Copy Santa DB to a temporary location (Santa keeps the DB locked)
        rows = []
        if not os.path.exists(SANTA_DB_PATH):
            return rows

        temp_db_path = ""
        try:
            # Create a temporary file
            temp_fd, temp_db_path = tempfile.mkstemp(suffix='.db')
            os.close(temp_fd)
            
            # Copy Santa DB to temp location
            shutil.copy2(SANTA_DB_PATH, temp_db_path)
            
            # Query the rules
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT shasum, state, type, custommsg FROM rules;")
            
            for shasum, state, type_val, custom_msg in cursor.fetchall():
                row = {}
                row["shasum"] = shasum
                row["state"] = "allowlist" if state == 1 else "denylist"
                row["type"] = "binary" if type_val == 1 else "certificate"
                row["custom_message"] = custom_msg or ""
                rows.append(row)
                
            conn.close()
        
        except Exception as e:
            osquery.logging.warning(f"Error accessing Santa rules: {str(e)}")
        
        finally:
            # Clean up temp file
            if temp_db_path and os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
        
        return rows
    
    def insert(self, context, query_data):
        """Add a new rule to Santa's database"""
        try:
            shasum = query_data.get("shasum", "")
            state = query_data.get("state", "")
            rule_type = query_data.get("type", "")
            custom_message = query_data.get("custom_message", "")
            
            if not shasum or not state or not rule_type:
                return [{"status": "failure", "message": "Missing required fields"}]
            
            if len(shasum) != 64 or not re.match(r'^[0-9a-f]+$', shasum):
                return [{"status": "failure", "message": "Invalid shasum format"}]
            
            # Build santactl command
            cmd = [SANTACTL_PATH, "rule", "--sha256", shasum]
            
            # Handle state (with backward compatibility)
            if state in ["allowlist", "whitelist"]:
                cmd.extend(["--allowlist", "--whitelist"])
            elif state in ["denylist", "blacklist"]:
                cmd.extend(["--denylist", "--blacklist"])
            else:
                return [{"status": "failure", "message": "Invalid state value"}]
            
            # Handle rule type
            if rule_type == "certificate":
                cmd.append("--certificate")
            elif rule_type != "binary":
                return [{"status": "failure", "message": "Invalid type value"}]
            
            # Add custom message if provided
            if custom_message:
                cmd.extend(["--message", custom_message])
            
            # Run santactl command
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if proc.returncode != 0:
                return [{"status": "failure", "message": proc.stderr or proc.stdout}]
            
            return [{"status": "success"}]
            
        except Exception as e:
            return [{"status": "failure", "message": str(e)}]
    
    def delete(self, context, query_data):
        """Remove a rule from Santa's database"""
        try:
            shasum = query_data.get("shasum", "")
            rule_type = query_data.get("type", "")
            
            if not shasum or not rule_type:
                return [{"status": "failure", "message": "Missing required fields"}]
            
            # Build santactl command
            cmd = [SANTACTL_PATH, "rule", "--remove", "--sha256", shasum]
            
            # Handle rule type
            if rule_type == "certificate":
                cmd.append("--certificate")
            elif rule_type != "binary":
                return [{"status": "failure", "message": "Invalid type value"}]
            
            # Run santactl command
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if proc.returncode != 0:
                return [{"status": "failure", "message": proc.stderr or proc.stdout}]
            
            return [{"status": "success"}]
            
        except Exception as e:
            return [{"status": "failure", "message": str(e)}]


def extract_log_values(line):
    """Extract values from a Santa log line"""
    values = {}
    
    # Extract timestamp
    timestamp_match = re.search(r'\[(.*?)\]', line)
    if timestamp_match:
        values["timestamp"] = timestamp_match.group(1)
        
    # Skip if not a santad log entry
    if LOG_ENTRY_PREFACE not in line:
        return values
    
    # Extract key=value pairs
    prefix_pos = line.find(LOG_ENTRY_PREFACE) + len(LOG_ENTRY_PREFACE)
    remaining = line[prefix_pos:]
    
    # Parse key-value pairs
    for pair in re.finditer(r'(\w+)=([^|]+)(?:\||$)', remaining):
        key, value = pair.groups()
        values[key.strip()] = value.strip()
    
    return values


class SantaDecisionsTable(osquery.TablePlugin):
    """Base class for Santa decisions tables"""
    def __init__(self, decision_type):
        self.decision_type = decision_type
        super().__init__()
    
    def columns(self):
        return [
            osquery.TableColumn(name="timestamp", type=osquery.STRING),
            osquery.TableColumn(name="path", type=osquery.STRING),
            osquery.TableColumn(name="shasum", type=osquery.STRING),
            osquery.TableColumn(name="reason", type=osquery.STRING),
        ]
    
    def generate(self, context):
        rows = []
        
        try:
            # Read current log file
            if not os.path.exists(SANTA_LOG_PATH):
                return rows
            
            with open(SANTA_LOG_PATH, 'r') as f:
                for line in f:
                    # Filter by decision type
                    if f"decision={self.decision_type}" not in line:
                        continue
                    
                    values = extract_log_values(line)
                    if not values:
                        continue
                    
                    row = {
                        "timestamp": values.get("timestamp", ""),
                        "path": values.get("path", ""),
                        "shasum": values.get("sha256", ""),
                        "reason": values.get("reason", ""),
                    }
                    rows.append(row)
            
            # Process archived logs
            log_dir = Path(SANTA_LOG_PATH).parent
            for i in range(10):  # Check up to 10 archived logs
                archive_path = log_dir / f"{Path(SANTA_LOG_PATH).name}.{i}.gz"
                if not archive_path.exists():
                    break
                
                # Use subprocess to read gzipped file
                try:
                    proc = subprocess.run(
                        ["gunzip", "-c", str(archive_path)],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if proc.returncode == 0:
                        for line in proc.stdout.splitlines():
                            if f"decision={self.decision_type}" not in line:
                                continue
                            
                            values = extract_log_values(line)
                            if not values:
                                continue
                            
                            row = {
                                "timestamp": values.get("timestamp", ""),
                                "path": values.get("path", ""),
                                "shasum": values.get("sha256", ""),
                                "reason": values.get("reason", ""),
                            }
                            rows.append(row)
                except Exception as e:
                    osquery.logging.warning(f"Error processing archive {archive_path}: {str(e)}")
        
        except Exception as e:
            osquery.logging.warning(f"Error accessing Santa logs: {str(e)}")
        
        return rows


class SantaAllowedDecisionsTable(SantaDecisionsTable):
    """osquery table for Santa allowed decisions"""
    def __init__(self):
        super().__init__("ALLOW")
    
    def name(self):
        return "santa_allowed_decisions"


class SantaDeniedDecisionsTable(SantaDecisionsTable):
    """osquery table for Santa denied decisions"""
    def __init__(self):
        super().__init__("DENY")
    
    def name(self):
        return "santa_denied_decisions"


@osquery.register_plugin
def main():
    return [
        SantaRulesTable(),
        SantaAllowedDecisionsTable(),
        SantaDeniedDecisionsTable(),
    ]


if __name__ == "__main__":
    # Create the extension and start it
    server = osquery.ExtensionManager()
    server.run()
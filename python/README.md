# Python Santa Osquery Extension

This is a Python implementation of an osquery extension for interfacing with Santa on macOS. Santa is a binary authorization system for macOS that monitors process executions and determines whether to allow or deny them.

## Features

This extension provides three tables:

1. `santa_rules`: Lists and manages the allow/deny rules in Santa's database
2. `santa_allowed_decisions`: Shows execution events that Santa allowed
3. `santa_denied_decisions`: Shows execution events that Santa denied

## Requirements

- Python 3.6+
- Santa installed on macOS
- osquery installed on macOS
- Python packages: `osquery`, `pyosquery`, `sqlite3`

## Installation

1. Install required Python packages:

```bash
pip install osquery pyosquery
```

2. Make the extension executable:

```bash
chmod +x santa_extension.py
```

3. Register the extension with osquery:

```bash
# Method 1: Start osqueryi with the extension
osqueryi --extension=/path/to/santa_extension.py

# Method 2: Load it into osqueryd via autoload
mkdir -p /etc/osquery/extensions
cp santa_extension.py /etc/osquery/extensions/
chmod +x /etc/osquery/extensions/santa_extension.py
```

## Usage

### Querying Santa Rules

```sql
-- List all Santa rules
SELECT * FROM santa_rules;

-- Find specific rules
SELECT * FROM santa_rules WHERE state = 'denylist' AND type = 'binary';
```

### Managing Rules

To add a new rule:

```sql
INSERT INTO santa_rules (shasum, state, type, custom_message)
VALUES (
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 
  'allowlist',
  'binary',
  'Allowed by IT department'
);
```

To remove a rule:

```sql
DELETE FROM santa_rules WHERE 
  shasum = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' AND
  type = 'binary';
```

### Viewing Santa Decisions

```sql
-- View recent allowed executions
SELECT * FROM santa_allowed_decisions ORDER BY timestamp DESC LIMIT 10;

-- View recent denied executions
SELECT * FROM santa_denied_decisions ORDER BY timestamp DESC LIMIT 10;

-- Find executions of a specific binary
SELECT * FROM santa_denied_decisions
WHERE shasum = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
```

## Terminology

This extension uses newer allowlist/denylist terminology but maintains compatibility with older whitelist/blacklist terminology used by some versions of Santa:

- `allowlist` (formerly `whitelist`): Rules that explicitly allow execution
- `denylist` (formerly `blacklist`): Rules that explicitly deny execution

## Troubleshooting

- Make sure Santa is properly installed and configured
- Verify the extension has proper permissions to read Santa's database and logs
- Check osquery's extension log for errors:
  ```bash
  tail -f /var/log/osquery/osquery.results.log
  ```

## Credits

This extension is based on the original C++ Santa extension for osquery created by Trail of Bits, but rewritten in Python for easier maintenance and compatibility with newer osquery versions.
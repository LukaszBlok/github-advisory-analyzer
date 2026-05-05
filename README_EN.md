# GitHub Advisory Database Analyzer

A Python script for statistical analysis of security vulnerabilities from the GitHub Advisory Database. The program processes advisory JSON files and generates statistics on the number of vulnerabilities grouped by year and CWE type, along with a list of the most affected packages.

## Project Structure

```
pythonProject1/
├── main.py                     # Main analysis script
├── advisory-database-main/     # Cloned GitHub Advisory Database repository
├── wyniki.json                 # Sample output file with analysis results
```

## Requirements

- Python 3.7+
- No external dependencies (standard library only: `json`, `os`, `pathlib`, `collections`, `argparse`)

## Input Data

The program requires access to a cloned [GitHub Advisory Database](https://github.com/github/advisory-database) repository. The repository contains JSON files describing vulnerabilities in the following structure:

An example file from the dataset is available at:
https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/05/GHSA-4hhq-j3xw-wj89/GHSA-4hhq-j3xw-wj89.json

```
advisory-database/
└── advisories/
    └── github-reviewed/
        ├── 2017/
        ├── 2018/
        ...
        └── 2024/
```

## Usage

```bash
python main.py <repo_path> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `repo_path` | Path to the cloned advisory-database repository (required) |
| `--top N` | Number of top packages to display per CWE (default: 10) |
| `--year YEAR` | Analyze only a specific year (e.g. 2023) |
| `--output FILE` | Save results to a JSON file |

### Examples

Analyze all years:
```bash
python main.py ./advisory-database-main
```

Analyze only the year 2023:
```bash
python main.py ./advisory-database-main --year 2023
```

Analyze and save results to a JSON file, showing top 5 packages:
```bash
python main.py ./advisory-database-main --output results.json --top 5
```

## How It Works

1. Reads JSON files from the `advisories/github-reviewed/` directory
2. Extracts from each file:
   - Publication year (field `published`)
   - CWE identifiers (field `database_specific.cwe_ids`)
   - Affected package name (field `affected[0].package`)
3. Groups statistics by the schema: **year -> CWE -> vulnerability count + package list**
4. Vulnerabilities without an assigned CWE are categorized as `UNKNOWN`
5. Displays results on the console and optionally exports to JSON

## JSON Output Format

```json
{
  "2023": {
    "CWE-79": {
      "total_vulnerabilities": 150,
      "top_packages": [
        {"package": "npm:example-pkg", "vulnerabilities": 12},
        ...
      ]
    },
    "UNKNOWN": {
      "total_vulnerabilities": 45,
      "top_packages": [...]
    }
  }
}
```

## Diagnostic Output

The program prints detailed diagnostic information during execution:
- Repository path and directory availability
- Available years in the database
- Number of JSON files found
- Processing progress (every 1000 files)
- Summary: number of successfully processed and skipped files with reasons for skipping

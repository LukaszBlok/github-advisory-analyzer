# Analiza GitHub Advisory Database

Skrypt Python do statystycznej analizy podatności bezpieczenstwa z repozytorium GitHub Advisory Database. Program przetwarza pliki JSON i generuje statystyki liczby podatnosci w podziale na lata i typy CWE, wraz z lista najbardziej podatnych pakietow.

## Struktura projektu

```
pythonProject1/
├── main.py                     # Glowny skrypt analizujacy
├── advisory-database-main/     # Sklonowane repozytorium GitHub Advisory Database
├── wyniki.json                 # Przykladowy plik z wynikami analizy
```

## Wymagania

- Python 3.7+
- Brak zewnetrznych zaleznosci (tylko biblioteki standardowe: `json`, `os`, `pathlib`, `collections`, `argparse`)

## Dane wejsciowe

Program wymaga dostepu do sklonowanego repozytorium [GitHub Advisory Database](https://github.com/github/advisory-database). Repozytorium zawiera pliki JSON z opisami podatnosci w strukturze:

Przykladowy plik z datasetu dostepny jest pod adresem:
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

## Uzycie

```bash
python main.py <sciezka_do_repozytorium> [opcje]
```

### Argumenty

| Argument | Opis |
|---|---|
| `repo_path` | Sciezka do sklonowanego repozytorium advisory-database (wymagany) |
| `--top N` | Liczba top pakietow do wyswietlenia na CWE (domyslnie: 10) |
| `--year ROK` | Analizuj tylko wybrany rok (np. 2023) |
| `--output PLIK` | Zapisz wyniki do pliku JSON |

### Przyklady

Analiza wszystkich lat:
```bash
python main.py ./advisory-database-main
```

Analiza tylko roku 2023:
```bash
python main.py ./advisory-database-main --year 2023
```

Analiza z zapisem wynikow do pliku JSON i top 5 pakietow:
```bash
python main.py ./advisory-database-main --output wyniki.json --top 5
```

## Dzialanie programu

1. Wczytuje pliki JSON z katalogu `advisories/github-reviewed/`
2. Z kazdego pliku wyciaga:
   - Rok publikacji (pole `published`)
   - Identyfikatory CWE (pole `database_specific.cwe_ids`)
   - Nazwe dotkniетego pakietu (pole `affected[0].package`)
3. Grupuje statystyki wedlug schematu: **rok -> CWE -> liczba podatnosci + lista pakietow**
4. Podatnosci bez przypisanego CWE sa kategoryzowane jako `UNKNOWN`
5. Wyswietla wyniki na konsoli i opcjonalnie eksportuje do JSON

## Format wyjscia JSON

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

## Informacje diagnostyczne

Program wyswietla szczegolowe informacje diagnostyczne podczas dzialania:
- Sciezka i dostepnosc katalogu
- Dostepne lata w bazie
- Liczba znalezionych plikow JSON
- Postep przetwarzania (co 1000 plikow)
- Podsumowanie: liczba przetworzonych, pominiętych plikow i przyczyny pominiecia

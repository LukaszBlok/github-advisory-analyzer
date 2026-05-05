"""
Analiza GitHub Advisory Database - statystyka podatności per rok per typ CWE
"""

import json
import os
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
import argparse


def load_advisory(file_path: Path) -> Dict:
    """Wczytuje pojedynczy advisory JSON"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Błąd wczytywania {file_path}: {e}")
        return None


def extract_package_name(advisory: Dict) -> str:
    """Wyciąga nazwę pakietu z advisory"""
    if not advisory:
        return None

    affected = advisory.get('affected', [])
    if not affected:
        return None

    package = affected[0].get('package', {})
    ecosystem = package.get('ecosystem', '')
    name = package.get('name', '')

    if ecosystem and name:
        return f"{ecosystem}:{name}"
    elif name:
        return name

    return None


def extract_cwe_ids(advisory: Dict) -> List[str]:
    """Wyciąga CWE ID z advisory"""
    if not advisory:
        return []

    # Pobiera listę CWE z database_specific.cwe_ids
    cwe_ids = advisory.get('database_specific', {}).get('cwe_ids', [])

    return cwe_ids if cwe_ids else []


def extract_year(advisory: Dict) -> int:
    """Wyciąga rok publikacji advisory"""
    if not advisory:
        return None

    published = advisory.get('published')
    if published:
        return int(published[:4])

    return None


def analyze_advisories(repo_path: str, target_year: Optional[int] = None) -> Dict:
    """
    Główna funkcja analizująca advisories

    Jeśli podano target_year, skanuje tylko katalog tego roku

    Zwraca strukturę:
    {
        2022: {
            'CWE-502': {
                'count': 10,
                'packages': Counter({'pkg1': 5, 'pkg2': 3, ...})
            },
            ...
        },
        ...
    }
    """

    github_reviewed_path = Path(repo_path) / "advisories" / "github-reviewed"

    print("=" * 80)
    print("DEBUG - DIAGNOSTYKA")
    print("=" * 80)
    print(f"DEBUG: Ścieżka do analizy: {github_reviewed_path}")
    print(f"DEBUG: Czy katalog istnieje: {github_reviewed_path.exists()}")

    if target_year:
        print(f"DEBUG: Skanowanie tylko roku {target_year}")

    if not github_reviewed_path.exists():
        print(f"\nBŁĄD: Katalog nie istnieje!")
        print(f"Sprawdź czy ścieżka jest poprawna:")
        print(f"  {repo_path}")
        raise FileNotFoundError(f"Katalog {github_reviewed_path} nie istnieje!")

    # Sprawdza zawartość katalogu
    subdirs = [d for d in github_reviewed_path.iterdir() if d.is_dir()]
    print(f"DEBUG: Podkatalogi w github-reviewed: {len(subdirs)}")
    if subdirs:
        all_years = sorted([d.name for d in subdirs])
        print(f"DEBUG: Dostępne lata: {all_years}")

    # Jeśli podano rok, skanuje tylko ten katalog
    if target_year:
        year_path = github_reviewed_path / str(target_year)
        if not year_path.exists():
            print(f"\nBŁĄD: Katalog dla roku {target_year} nie istnieje!")
            print(f"Sprawdź czy rok {target_year} jest dostępny w repozytorium.")
            return {}

        scan_paths = [year_path]
        print(f"DEBUG: Skanowanie tylko katalogu: {year_path}")
    else:
        scan_paths = [github_reviewed_path]
        print(f"DEBUG: Skanowanie wszystkich lat...")

    # Znajduje pliki JSON do skanowania
    all_json_files = []
    for scan_path in scan_paths:
        all_json_files.extend(list(scan_path.rglob("*.json")))

    print(f"DEBUG: Znaleziono plików JSON do przetworzenia: {len(all_json_files)}")

    if len(all_json_files) == 0:
        print("\nBŁĄD: Nie znaleziono żadnych plików JSON!")
        print("Sprawdź czy repozytorium zostało poprawnie sklonowane.")
        return {}

    # Testuje pierwszy plik
    print(f"\nDEBUG: Testuję pierwszy plik...")
    print(f"DEBUG: Przykładowy plik: {all_json_files[0]}")

    test_advisory = load_advisory(all_json_files[0])
    print(f"DEBUG: Czy wczytano: {test_advisory is not None}")

    if test_advisory:
        test_year = extract_year(test_advisory)
        test_package = extract_package_name(test_advisory)
        test_cwes = extract_cwe_ids(test_advisory)

        print(f"DEBUG: Rok: {test_year}")
        print(f"DEBUG: Pakiet: {test_package}")
        print(f"DEBUG: CWE: {test_cwes}")

        if not test_year:
            print("UWAGA: Nie można wyciągnąć roku z pliku!")
        if not test_package:
            print("UWAGA: Nie można wyciągnąć nazwy pakietu!")
        if not test_cwes:
            print("UWAGA: Brak CWE w pliku (zostanie oznaczony jako UNKNOWN)")

    print("\n" + "=" * 80)
    print("ROZPOCZYNAM ANALIZĘ")
    print("=" * 80)

    # Struktura: rok -> CWE -> {'count': int, 'packages': Counter}
    stats = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'packages': Counter()}))

    total_files = 0
    processed_files = 0
    skipped_no_year = 0
    skipped_no_package = 0
    skipped_wrong_year = 0

    print("Skanowanie plików advisory...")

    # Iteruje przez wszystkie znalezione pliki JSON
    for json_file in all_json_files:
        total_files += 1

        if total_files % 1000 == 0:
            print(
                f"Przetworzono {total_files} plików... (sukces: {processed_files}, pominięto: {total_files - processed_files})")

        advisory = load_advisory(json_file)
        if not advisory:
            continue

        year = extract_year(advisory)
        if not year:
            skipped_no_year += 1
            continue

        # Dodatkowa weryfikacja roku
        if target_year and year != target_year:
            skipped_wrong_year += 1
            continue

        package = extract_package_name(advisory)
        if not package:
            skipped_no_package += 1
            continue

        cwe_ids = extract_cwe_ids(advisory)
        if not cwe_ids:
            # Jeśli brak CWE, kategoryzuje jako "UNKNOWN"
            cwe_ids = ['UNKNOWN']

        for cwe_id in cwe_ids:
            stats[year][cwe_id]['count'] += 1
            stats[year][cwe_id]['packages'][package] += 1

        processed_files += 1

    print(f"\n{'=' * 80}")
    print("PODSUMOWANIE PRZETWARZANIA")
    print(f"{'=' * 80}")
    print(f"Łącznie plików: {total_files}")
    print(f"Pomyślnie przetworzonych: {processed_files}")
    print(f"Pominięto (brak roku): {skipped_no_year}")
    print(f"Pominięto (brak pakietu): {skipped_no_package}")
    if skipped_wrong_year > 0:
        print(f"Pominięto (zły rok w pliku): {skipped_wrong_year}")

    if processed_files == 0:
        print("\nBŁĄD: Nie przetworzono żadnych plików pomyślnie!")
        print("Sprawdź strukturę plików JSON w repozytorium.")

    return dict(stats)


def print_statistics(stats: Dict, top_n: int = 10):
    """Wyświetla statystyki w czytelnym formacie"""

    if not stats:
        print("\nBrak danych do wyświetlenia!")
        return

    print("\n" + "=" * 80)
    print("STATYSTYKI PODATNOŚCI - GITHUB ADVISORY DATABASE")
    print("=" * 80)

    for year in sorted(stats.keys()):
        print(f"\n{'=' * 80}")
        print(f"ROK: {year}")
        print(f"{'=' * 80}")

        year_data = stats[year]

        # Sortuje CWE po liczbie wystąpień
        sorted_cwes = sorted(
            year_data.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )

        for cwe_id, cwe_data in sorted_cwes:
            count = cwe_data['count']
            packages = cwe_data['packages']

            print(f"\n{cwe_id}: {count} podatności")
            print(f"{'-' * 80}")

            # Top N najbardziej podatnych projektów dla tego CWE
            top_packages = packages.most_common(top_n)

            if top_packages:
                print(f"Top {len(top_packages)} najbardziej podatnych projektów:")
                for i, (pkg, pkg_count) in enumerate(top_packages, 1):
                    print(f"  {i:2d}. {pkg:50s} - {pkg_count:3d} podatności")
            else:
                print("  Brak danych o projektach")


def export_to_json(stats: Dict, output_file: str, top_n: int = 10):
    """Eksportuje statystyki do pliku JSON"""

    export_data = {}

    for year in sorted(stats.keys()):
        year_data = stats[year]
        export_data[str(year)] = {}

        # Sortuje CWE po liczbie wystąpień
        sorted_cwes = sorted(
            year_data.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )

        for cwe_id, cwe_data in sorted_cwes:
            count = cwe_data['count']
            packages = cwe_data['packages']

            top_packages = [
                {"package": pkg, "vulnerabilities": cnt}
                for pkg, cnt in packages.most_common(top_n)
            ]

            export_data[str(year)][cwe_id] = {
                "total_vulnerabilities": count,
                "top_packages": top_packages
            }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    print(f"\nWyeksportowano dane do: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Analiza GitHub Advisory Database - statystyki podatności'
    )
    parser.add_argument(
        'repo_path',
        help='Ścieżka do sklonowanego repozytorium advisory-database'
    )
    parser.add_argument(
        '--top',
        type=int,
        default=10,
        help='Liczba top projektów do wyświetlenia (domyślnie: 10)'
    )
    parser.add_argument(
        '--output',
        help='Plik wyjściowy JSON (opcjonalnie)'
    )
    parser.add_argument(
        '--year',
        type=int,
        help='Analizuj tylko konkretny rok'
    )

    args = parser.parse_args()

    print("=" * 80)
    print("ANALIZA GITHUB ADVISORY DATABASE")
    print("=" * 80)
    print(f"Ścieżka repozytorium: {args.repo_path}")
    print(f"Top projektów: {args.top}")
    if args.year:
        print(f"Filtruj rok: {args.year}")
    if args.output:
        print(f"Plik wyjściowy: {args.output}")
    print("=" * 80)

    # Przekazuje target_year do funkcji analizującej
    stats = analyze_advisories(args.repo_path, target_year=args.year)

    if args.year and not stats:
        print(f"\nUWAGA: Brak danych dla roku {args.year}")

    print_statistics(stats, top_n=args.top)

    if args.output:
        export_to_json(stats, args.output, top_n=args.top)

    # Podsumowanie końcowe
    if stats:
        print(f"\n{'=' * 80}")
        print("PODSUMOWANIE KOŃCOWE")
        print(f"{'=' * 80}")
        total_years = len(stats)
        total_cwes = sum(len(year_data) for year_data in stats.values())
        total_vulnerabilities = sum(
            cwe_data['count']
            for year_data in stats.values()
            for cwe_data in year_data.values()
        )

        print(f"Przeanalizowane lata: {total_years}")
        print(f"Unikalne CWE: {total_cwes}")
        print(f"Łączna liczba podatności: {total_vulnerabilities}")
    else:
        print(f"\n{'=' * 80}")
        print("Brak wyników do wyświetlenia")
        print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
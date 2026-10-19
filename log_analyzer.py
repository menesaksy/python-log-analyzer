#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter

SYSLOG_SSHD_PREFIX = r"^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]: "
FAILED_PASSWORD_PATTERN = re.compile(
    SYSLOG_SSHD_PREFIX
    + r"Failed password for .+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2$"
)
ACCEPTED_PASSWORD_PATTERN = re.compile(
    SYSLOG_SSHD_PREFIX
    + r"Accepted password for .+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2$"
)


def _is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def count_failed_attempts(lines):
    counts = Counter()
    for line in lines:
        match = FAILED_PASSWORD_PATTERN.search(line.rstrip())
        if not match:
            continue
        ip = match.group("ip")
        if _is_valid_ip(ip):
            counts[ip] += 1
    return counts


def analyze(lines, threshold):
    failed_counts = Counter()
    breached = set()
    for line in lines:
        stripped = line.rstrip()
        failed = FAILED_PASSWORD_PATTERN.search(stripped)
        if failed:
            ip = failed.group("ip")
            if _is_valid_ip(ip):
                failed_counts[ip] += 1
            continue
        accepted = ACCEPTED_PASSWORD_PATTERN.search(stripped)
        if accepted:
            ip = accepted.group("ip")
            if _is_valid_ip(ip) and failed_counts[ip] >= threshold:
                breached.add(ip)
    return failed_counts, breached


def build_report(counts, threshold, breached_ips=frozenset()):
    return [
        {
            "ip": ip,
            "attempts": attempts,
            "suspicious": attempts >= threshold,
            "breach": ip in breached_ips,
        }
        for ip, attempts in counts.most_common()
    ]


def print_report(report, threshold):
    if not report:
        print("Başarısız giriş denemesi bulunamadı.")
        return

    print(f"{'IP ADRESİ':<20}{'DENEME SAYISI':<15}{'DURUM'}")
    print("-" * 50)
    for row in report:
        if row["breach"]:
            status = "OLASI İHLAL"
        elif row["suspicious"]:
            status = "ŞÜPHELİ"
        else:
            status = "normal"
        print(f"{row['ip']:<20}{row['attempts']:<15}{status}")

    suspicious_count = sum(1 for row in report if row["suspicious"])
    print("-" * 50)
    print(
        f"Toplam {len(report)} benzersiz IP, "
        f"{suspicious_count} şüpheli IP (eşik: {threshold})"
    )


def write_csv(report, output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "attempts", "suspicious", "breach"])
        writer.writeheader()
        writer.writerows(report)
    print(f"Rapor '{output_path}' dosyasına yazıldı.")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="SSH/auth.log dosyasındaki başarısız giriş denemelerini IP'ye göre sayar ve şüpheli IP'leri raporlar."
    )
    parser.add_argument("logfile", help="Analiz edilecek log dosyasının yolu")
    parser.add_argument(
        "-t", "--threshold", type=int, default=5,
        help="Şüpheli sayılmak için gereken minimum başarısız deneme sayısı (varsayılan: 5)",
    )
    parser.add_argument(
        "-o", "--output", help="Sonucu CSV dosyasına da yaz (opsiyonel)"
    )
    args = parser.parse_args()

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            counts, breached = analyze(f, args.threshold)
    except FileNotFoundError:
        print(f"Hata: '{args.logfile}' dosyası bulunamadı.", file=sys.stderr)
        sys.exit(1)
    except IsADirectoryError:
        print(f"Hata: '{args.logfile}' bir dosya değil, dizin.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Hata: '{args.logfile}' okuma izni yok.", file=sys.stderr)
        sys.exit(1)

    report = build_report(counts, args.threshold, breached)
    print_report(report, args.threshold)

    if args.output and report:
        write_csv(report, args.output)


if __name__ == "__main__":
    main()

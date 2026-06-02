import subprocess
import json
import os
import sys

REMEDIATION = {
    "CVE-2021-44228": (
        "Log4Shell (CVE-2021-44228): Log4j 버전을 2.17.0 이상으로 즉시 업데이트하고, "
        "JJNDI Lookup 기능을 비활성화할 것."
    ),
    "CVE-2017-7494": (
        "SambaCry (CVE-2017-7494): Samba 버전을 4.6.4 이상으로 패치하고, "
        "smb.conf 파일에서 'nt pipe support = no' 로 설정할 것."
    ),
    "CVE-2018-15473": (
        "SSH User Enumeration (CVE-2018-15473): OpenSSH 버전을 7.7 이상으로 업데이트하고, "
        "불필요한 SSH 포트를 방화벽에서 차단할 것."
    ),
}


def run_step(cmd, step_name):
    print(f"[*] {step_name} 시작: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] {step_name} 실패 (returncode={result.returncode})")
        if result.stderr:
            print(f"    stderr: {result.stderr.strip()}")
        sys.exit(1)
    print(f"[+] {step_name} 완료")


def check_output_file(path, step_name):
    if not os.path.exists(path):
        print(f"[!] {step_name}: 출력 파일이 존재하지 않습니다 → {path}")
        sys.exit(1)
    if os.path.getsize(path) == 0:
        print(f"[!] {step_name}: 출력 파일이 비어 있습니다 → {path}")
        sys.exit(1)
    print(f"[+] 출력 파일 확인: {path}")


def step1_subfinder(domain):
    cmd = ["subfinder", "-d", domain, "-silent", "-o", "subdomains.txt"]
    run_step(cmd, "1단계: Subfinder (서브도메인 탐색)")
    check_output_file("subdomains.txt", "1단계 Subfinder")


def step2_naabu():
    cmd = ["naabu", "-list", "subdomains.txt", "-silent", "-o", "ports.txt"]
    run_step(cmd, "2단계: Naabu (포트 스캔)")
    check_output_file("ports.txt", "2단계 Naabu")


def step3_nuclei():
    cmd = [
        "nuclei",
        "-list", "ports.txt",
        "-t", "custom_templates/",
        "-json",
        "-o", "nuclei_result.json",
        "-silent",
    ]
    run_step(cmd, "3단계: Nuclei (취약점 스캔)")
    check_output_file("nuclei_result.json", "3단계 Nuclei")


def step4_report():
    print("[*] 4단계: 결과 파싱 및 리포트 생성")

    results = []
    with open("nuclei_result.json", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[!] JSON 파싱 오류 (라인 무시): {e}")

    if not results:
        print("[!] nuclei_result.json 에서 파싱된 결과가 없습니다.")
        sys.exit(1)

    report_lines = ["[Nuclei 취약점 스캔 결과 리포트]", "=" * 60]

    for item in results:
        info = item.get("info", {})
        name = info.get("name", "N/A")
        severity = info.get("severity", "N/A")
        matched_at = item.get("matched-at", "N/A")

        report_lines.append(f"\n취약점 이름 : {name}")
        report_lines.append(f"심각도     : {severity}")
        report_lines.append(f"탐지 위치  : {matched_at}")

        for cve_id, guidance in REMEDIATION.items():
            if cve_id.upper() in str(item).upper():
                report_lines.append(f"조치 방법  : {guidance}")
                break

    report_lines.append("\n" + "=" * 60)
    report_text = "\n".join(report_lines)

    with open("report.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    print(report_text)
    print("[+] 4단계 완료: report.txt 저장됨")


def main():
    if len(sys.argv) != 2:
        print(f"사용법: python {sys.argv[0]} <target domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"[*] ASM 파이프라인 시작 → 대상: {domain}")

    step1_subfinder(domain)
    step2_naabu()
    step3_nuclei()
    step4_report()

    print("\n[*] 모든 단계 완료. 결과: report.txt")


if __name__ == "__main__":
    main()

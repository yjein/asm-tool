# ASM Scanner

Docker 테스트베드 기반 CVE 취약점 자동화 탐지 도구

## 파이프라인

```
Docker → Subfinder → Naabu → Nmap → CVE 탐지 (Nuclei + Python) → Report
```

취약 서버를 구동한 뒤 서브도메인 탐색 → 포트 스캔 → 서비스 버전 탐지 → 취약점 판정 → PoC 검증 → 리포트 출력 순으로 자동 실행된다.

## 코드 구조

```
scanners/
  detect.py       — CVE별 탐지 로직 (Nuclei + Python fallback)
  nmap_scan.py    — nmap 서비스 버전 탐지 및 취약 버전 판별
  portscan.py     — 포트 스캔 및 배너 그랩
  poc.py          — CVE별 PoC 모듈
  config.py       — 탐지 대상 및 조치 정보
custom_templates/ — Nuclei YAML 룰 (CVE별 직접 작성)
gui/              — PyQt5 기반 GUI
gui_main.py       — GUI 진입점
scanner.py        — CLI 진입점
```

## 요구사항

- Python 3.10+
- Docker Desktop
- [Nmap](https://nmap.org/download.html) 설치
- [Nuclei](https://github.com/projectdiscovery/nuclei/releases) — `nuclei_3.x.x_windows_amd64.zip` 압축 해제 후 `nuclei.exe`를 `nuclei_bin/` 폴더에 넣기
- (선택) Subfinder, Naabu — 서브도메인·포트 스캔 바이너리도 동일하게 `nuclei_bin/`에 넣기

## 설치

```bash
pip install rich impacket paramiko PyQt5
```

## 실행

**1. Docker 컨테이너 시작**

```bash
docker-compose up -d
```

**2. GUI 실행**

```bash
python gui_main.py
```

**2-1. CLI 실행 (선택)**

```bash
python scanner.py
```

스캔 완료 후 `scan_results/report.html`에 보고서가 생성된다.

## 탐지 대상

| CVE            | 취약점                  | 기본 포트 |
| -------------- | ----------------------- | --------- |
| CVE-2021-44228 | Log4Shell (Apache Solr) | 8080      |
| CVE-2017-7494  | SambaCry                | 4445      |
| CVE-2018-15473 | OpenSSH 사용자 열거     | 2222      |

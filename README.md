# CVE Scanner

Docker 테스트베드 기반 CVE 취약점 자동화 탐지 도구

## 요구사항

- Python 3.10+
- Docker Desktop
- [Nuclei](https://github.com/projectdiscovery/nuclei/releases) — `nuclei_3.x.x_windows_amd64.zip` 다운로드 후 압축 해제, `nuclei.exe`를 `nuclei_bin/` 폴더에 넣기

## 설치

```bash
pip install rich impacket paramiko
```

## 실행

**1. Docker 컨테이너 시작**

```bash
docker-compose up -d
```

**2. 스캐너 실행**

```bash
python scanner.py
```

메뉴에서 스캔할 취약점을 선택하고 대상 주소를 입력한다.  
스캔 완료 후 `scan_results/report.html`에 보고서가 생성된다.

## 탐지 대상

| CVE            | 취약점                  | 기본 포트 |
| -------------- | ----------------------- | --------- |
| CVE-2021-44228 | Log4Shell (Apache Solr) | 8080      |
| CVE-2017-7494  | SambaCry                | 4445      |
| CVE-2018-15473 | OpenSSH 사용자 열거     | 2222      |

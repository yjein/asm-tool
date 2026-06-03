TARGETS = {
    "1": {"cve": "CVE-2021-44228", "name": "Log4Shell",            "severity": "CRITICAL", "default": "http://localhost:8080"},
    "2": {"cve": "CVE-2017-7494",  "name": "SambaCry",             "severity": "HIGH",     "default": "localhost:4445"},
    "3": {"cve": "CVE-2018-15473", "name": "SSH User Enumeration", "severity": "MEDIUM",   "default": "localhost:2222"},
}

REMEDIATION = {
    "CVE-2021-44228": [
        "Log4j 2.17.0 이상으로 즉시 업데이트",
        "log4j2.formatMsgNoLookups=true 시스템 속성 설정",
        "JNDI Lookup 기능 비활성화",
        "WAF에서 ${jndi: 패턴 차단 규칙 추가",
    ],
    "CVE-2017-7494": [
        "Samba 4.6.4 이상으로 패치",
        "smb.conf에 'nt pipe support = no' 추가",
        "불필요한 공유 비활성화",
        "방화벽에서 445 포트 외부 접근 차단",
    ],
    "CVE-2018-15473": [
        "OpenSSH 7.7 이상으로 업데이트",
        "fail2ban 등 무차별 대입 방지 적용",
        "SSH 포트 방화벽 차단",
        "공개키 인증만 허용 (PasswordAuthentication no)",
    ],
}

SEV_COLOR = {"CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}

CVE_DESCRIPTIONS = {
    "CVE-2021-44228": "Apache Solr에 내장된 Log4j 2.14.1의 JNDI Lookup 기능을 통해 원격 코드 실행이 가능한 취약점",
    "CVE-2017-7494":  "Samba 3.5.0~4.6.3에서 쓰기 가능한 공유에 악성 라이브러리를 업로드하여 원격 코드 실행이 가능한 취약점",
    "CVE-2018-15473": "OpenSSH 7.7 이하에서 공개키 인증 응답 차이를 이용해 유효한 사용자 계정을 열거할 수 있는 취약점",
}

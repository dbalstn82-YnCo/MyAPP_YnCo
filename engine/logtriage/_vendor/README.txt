LogTriage 동봉 순수 Python 패키지 (자원정보 XLSX 읽기용)
- openpyxl 3.1.5 (MIT)  - et_xmlfile 2.0.0 (MIT)  - defusedxml 0.7.1 (PSF) — openpyxl 이 XML 폭탄 방어에 사용
시스템에 openpyxl 이 설치되어 있으면 그것을 우선 사용하고, 없을 때만 이 폴더를 sys.path 에 추가한다(logtriage/inventory.py).

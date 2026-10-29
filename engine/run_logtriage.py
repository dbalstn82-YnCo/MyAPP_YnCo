"""PyInstaller 엔트리포인트 — 로컬(exe) 배포판."""
import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()   # 12차 병렬 해석: exe 가 작업자로 다시 뜨면 여기서 작업만 하고 끝난다(창·서버를 띄우지 않음)
    from logtriage.cli import main
    sys.exit(main())

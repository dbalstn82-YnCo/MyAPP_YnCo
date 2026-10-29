-- LogTriage — PostgreSQL 초기화 (install.sh 가 postgres 슈퍼유저로 실행, 비밀번호는 __PASSWORD__ 치환)
-- 이미 있으면 건너뛴다(재실행 안전).
DO $$
BEGIN
   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'logtriage') THEN
      CREATE ROLE logtriage LOGIN PASSWORD '__PASSWORD__';
   ELSE
      ALTER ROLE logtriage WITH PASSWORD '__PASSWORD__';
   END IF;
END
$$;
SELECT 'CREATE DATABASE logtriage OWNER logtriage ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'logtriage') \gexec
GRANT ALL PRIVILEGES ON DATABASE logtriage TO logtriage;
-- 테이블(incidents, events)은 앱이 첫 기동 때 CREATE TABLE IF NOT EXISTS 로 만든다 (logtriage/storage.py)

# occm-apply-server

마스토돈(Mastodon) 서버에서 **총괄 계정 권한 신청**을 자동으로 받기 위한 웹 서버입니다.

사용자가 웹 폼을 통해 마스토돈 아이디와 권한 유형(커뮤니티 총괄/커뮤니티 스탭)을 제출하면, 서버가 마스토돈 API를 통해 계정 존재 여부와 기존 권한을 검증한 뒤 신청 목록에 추가합니다. 관리자는 별도 페이지에서 신청 내역을 확인하고 관리할 수 있습니다.

## 주요 기능

- 마스토돈 아이디 기반 권한 신청 폼
- 마스토돈 API 연동으로 계정 존재 여부 및 기존 권한 자동 검증
- 관리자 로그인을 통한 신청 목록 조회 및 삭제
- [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/) 캡차 지원 (선택)
- Flask-Limiter 기반 요청 속도 제한 (Redis 지원)

## 설정

### 1. 의존성 설치

```bash
pip install -r requirements.txt
```

### 2. 환경 변수 설정

`.env.sample` 파일을 `.env`로 복사한 뒤 값을 수정합니다.

```bash
cp .env.sample .env
```

#### 필수 설정

| 변수 | 설명 |
|------|------|
| `ADMIN_PASSWORD` | 관리자 페이지 접속 비밀번호 (`ADMIN_PASSWORD` 또는 `ADMIN_PASSWORD_HASH` 중 하나 필수) |
| `SECRET_KEY` | Flask 세션 암호화 키 (아래 명령으로 생성 가능) |

```bash
# SECRET_KEY 생성
python3 -c "import secrets; print(secrets.token_hex(32))"
```

> **비밀번호 해시 직접 설정**: 평문 대신 `ADMIN_PASSWORD_HASH`에 해시값을 직접 설정할 수도 있습니다.
> ```bash
> python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))"
> ```

#### 선택 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `FILE_PATH` | `pending.txt` | 신청 목록 저장 파일 경로 |
| `MASTODON_DOMAIN` | `occm.cc` | 마스토돈 서버 도메인 |
| `SERVER_NAME_KO` | `자커마스` | 서버 표시 이름 |
| `TURNSTILE_SITE_KEY` | _(빈 값)_ | Cloudflare Turnstile 사이트 키 |
| `TURNSTILE_SECRET_KEY` | _(빈 값)_ | Cloudflare Turnstile 시크릿 키 |
| `REDIS_URL` | `memory://` | Redis 연결 URL (프로덕션에서 권장) |
| `SESSION_TIMEOUT_MINUTES` | `60` | 관리자 세션 타임아웃 (분) |

## 구동 방법

### 개발 서버

```bash
python app.py
```

기본적으로 `http://0.0.0.0:5000` 에서 실행됩니다.

### Gunicorn (프로덕션)

```bash
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

| 옵션 | 설명 |
|------|------|
| `-w 4` | 워커 프로세스 수 (CPU 코어 수 × 2 + 1 권장) |
| `-b 127.0.0.1:5000` | 바인드 주소 및 포트 |

> **참고**: 다중 워커를 사용하는 경우 rate limiting이 워커 간 공유되려면 `REDIS_URL`을 설정해야 합니다.

## 리버스 프록시 설정

프로덕션 환경에서는 Apache 또는 Nginx를 리버스 프록시로 사용하는 것을 권장합니다.

- [Apache 설정 예시](examples/apache.conf)
- [Nginx 설정 예시](examples/nginx.conf)

## 라이선스

[CC0 1.0 Universal](LICENSE)

from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix
import threading
import os
import secrets
from datetime import datetime
import requests
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)

# Get real ip from header
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# 파일 쓰기 충돌 방지를 위한 Lock 객체
file_lock = threading.Lock()

# .env 설정 로드
FILE_PATH = os.environ.get('FILE_PATH', 'pending.txt')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
TURNSTILE_SITE_KEY = os.environ.get('TURNSTILE_SITE_KEY', '')
TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')

app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

OCCM_DOMAIN_SUFFIX = '@occm.cc'

# REDIS_URL: Redis 연결 URL (rate limiting용). 미설정시 in-memory 스토리지 사용.
# 프로덕션 환경에서는 반드시 Redis URL을 설정하세요 (예: redis://:password@localhost:6379).
# in-memory 스토리지는 다중 인스턴스 환경에서 rate limit이 공유되지 않습니다.
REDIS_URL = os.environ.get('REDIS_URL', 'memory://')

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=REDIS_URL,
    default_limits=[],
)


def verify_turnstile(token, remote_ip=None):
    """Turnstile 토큰 검증. 키 미설정시 항상 True 반환."""
    if not TURNSTILE_SECRET_KEY:
        return True
    try:
        data = {'secret': TURNSTILE_SECRET_KEY, 'response': token}
        if remote_ip:
            data['remoteip'] = remote_ip
        resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data=data,
            timeout=5
        )
        return resp.json().get('success', False)
    except requests.exceptions.RequestException:
        return False


def is_admin_logged_in():
    return session.get('admin_logged_in') is True


@app.errorhandler(429)
def ratelimit_handler(e):
    return """
    <script>
        alert('요청이 너무 많습니다. 5분 후 다시 시도해주세요.');
        window.history.back();
    </script>
    """, 429


@app.route('/apply-admin/', methods=['GET'])
def index():
    return render_template('index.html', turnstile_site_key=TURNSTILE_SITE_KEY)


@app.route('/apply-admin/submit', methods=['POST'])
@limiter.limit("10 per 5 minutes")
def submit():
    # Turnstile 검증
    if TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY:
        token = request.form.get('cf-turnstile-response', '')
        if not verify_turnstile(token, request.remote_addr):
            return """
            <script>
                alert('보안 인증에 실패했습니다. 다시 시도해주세요.');
                window.history.back();
            </script>
            """

    raw_user_id = request.form.get('mastodon_id', '').strip()
    role_type = request.form.get('role_type', '').strip()

    valid_roles = ['커뮤니티 총괄', '커뮤니티 스탭']
    if role_type not in valid_roles:
        return """
        <script>
            alert('올바른 신청 유형을 선택해주세요.');
            window.history.back();
        </script>
        """

    if not raw_user_id:
        return """
        <script>
            alert('ID를 입력해주세요.');
            window.history.back();
        </script>
        """

    # mastodon_id 정규화 (맨 앞 @ 삭제)
    user_id = raw_user_id.lstrip('@')

    # 아이디@occm.cc 형태면 @occm.cc 삭제
    if user_id.lower().endswith(OCCM_DOMAIN_SUFFIX):
        user_id = user_id[:-len(OCCM_DOMAIN_SUFFIX)]

    # 이메일 형태 등록 제한 (@ 포함 여부 체크)
    if '@' in user_id:
        return """
        <script>
            alert('이메일 형태의 아이디는 등록할 수 없습니다.');
            window.history.back();
        </script>
        """

    # 아이디 중복 등록 제한
    is_duplicate = False
    with file_lock:
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('] ')
                    existing_rest = parts[1].strip() if len(parts) > 1 else line.strip()
                    existing_id = existing_rest.split('|')[0].strip()
                    if existing_id == user_id:
                        is_duplicate = True
                        break

    if is_duplicate:
        return """
        <script>
            alert('이미 신청된 아이디입니다.');
            window.history.back();
        </script>
        """

    # Mastodon API를 이용한 존재 여부 및 역할 검증
    lookup_url = f"https://occm.cc/api/v1/accounts/lookup?acct={user_id}"

    try:
        response = requests.get(lookup_url, timeout=5)

        # 404 Not Found인 경우 (존재하지 않는 아이디)
        if response.status_code == 404:
            return """
            <script>
                alert('자커마스 서버에 존재하지 않는 아이디입니다.\\n아이디를 다시 확인해주세요.');
                window.history.back();
            </script>
            """

        if response.status_code == 200:
            account_data = response.json()
            roles = account_data.get('roles', [])
            if any(role.get('name') == '커뮤니티 총괄' for role in roles):
                return """
                <script>
                    alert('이미 커뮤니티 총괄 권한이 있습니다.');
                    window.history.back();
                </script>
                """
        elif response.status_code != 404:
            return """
            <script>
                alert('아이디 조회 중 오류가 발생했습니다.\\n잠시 후 다시 시도해주세요.');
                window.history.back();
            </script>
            """

    except requests.exceptions.RequestException as e:
        # 네트워크 오류 등 발생 시
        return f"""
        <script>
            alert('서버와 통신 중 오류가 발생했습니다.\\n잠시 후 다시 시도해주세요.\\n({str(e)})');
            window.history.back();
        </script>
        """

    # 검증 통과 시 저장 로직 수행
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {user_id}|{role_type}\n"

    with file_lock:
        with open(FILE_PATH, 'a', encoding='utf-8') as f:
            f.write(log_entry)

    return """
    <script>
        alert('신청이 완료되었습니다.');
        window.location.href = '/apply-admin/';
    </script>
    """


@app.route('/apply-admin/admin-login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        # Turnstile 검증
        if TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY:
            token = request.form.get('cf-turnstile-response', '')
            if not verify_turnstile(token, request.remote_addr):
                error = '보안 인증에 실패했습니다. 다시 시도해주세요.'

        if error is None:
            password = request.form.get('password', '')
            if ADMIN_PASSWORD and password == ADMIN_PASSWORD:
                session['admin_logged_in'] = True
                return redirect(url_for('listman'))
            else:
                error = '비밀번호가 올바르지 않습니다.'

    return render_template('admin_login.html', error=error, turnstile_site_key=TURNSTILE_SITE_KEY)


@app.route('/apply-admin/logout', methods=['POST'])
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))


# 관리자 경로
@app.route('/apply-admin/listman', methods=['GET'])
def listman():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    data_list = []

    with file_lock:
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    parts = line.split('] ')
                    if len(parts) > 1:
                        rest = parts[1].strip()
                        id_parts = rest.split('|', 1)
                        extracted_id = id_parts[0].strip()
                        extracted_role = id_parts[1].strip() if len(id_parts) > 1 else ''
                        data_list.append({'full_text': line, 'id': extracted_id, 'role': extracted_role})
                    else:
                        data_list.append({'full_text': line, 'id': line, 'role': ''})

    return render_template('admin.html', items=data_list)


# 삭제 시 줄 번호(index)가 아닌 ID 기준으로 삭제
@app.route('/apply-admin/delete/<string:target_id>', methods=['POST'])
def delete_item(target_id):
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))

    with file_lock:
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                parts = line.strip().split('] ')
                if len(parts) > 1:
                    rest = parts[1].strip()
                    current_id = rest.split('|')[0].strip()
                    if current_id == target_id:
                        continue

                new_lines.append(line)

            with open(FILE_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

    return redirect(url_for('listman'))


@app.route('/apply-admin/check-my-ip', methods=['GET'])
@limiter.limit("100 per 5 minutes")
def check_my_ip():
    return {'ip': request.remote_addr}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

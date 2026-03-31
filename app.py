APP_VERSION = '1.0.0'

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import os
import re
import secrets
from datetime import datetime, timedelta
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
TURNSTILE_SITE_KEY = os.environ.get('TURNSTILE_SITE_KEY', '')
TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')

# 관리자 비밀번호: ADMIN_PASSWORD_HASH(해시)가 설정되어 있으면 우선 사용,
# 없으면 ADMIN_PASSWORD(평문)를 런타임에 해싱하여 사용
_admin_password_hash = os.environ.get('ADMIN_PASSWORD_HASH', '')
_admin_password_plain = os.environ.get('ADMIN_PASSWORD', '')
if _admin_password_hash:
    ADMIN_PASSWORD_HASH = _admin_password_hash
elif _admin_password_plain:
    ADMIN_PASSWORD_HASH = generate_password_hash(_admin_password_plain)
else:
    ADMIN_PASSWORD_HASH = ''

app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# 세션 타임아웃 설정 (기본 60분)
app.permanent_session_lifetime = timedelta(
    minutes=int(os.environ.get('SESSION_TIMEOUT_MINUTES', '60'))
)

MASTODON_DOMAIN = os.environ.get('MASTODON_DOMAIN', 'occm.cc')
SERVER_NAME_KO = os.environ.get('SERVER_NAME_KO', '자커마스')
OCCM_DOMAIN_SUFFIX = f'@{MASTODON_DOMAIN}'

# 마스토돈 사용자명 검증 정규식 (영문, 숫자, 밑줄, 마침표, 1~30자)
MASTODON_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.]{1,30}$')

# REDIS_URL: Redis 연결 URL (rate limiting용). 미설정시 in-memory 스토리지 사용.
# 프로덕션 환경에서는 반드시 Redis URL을 설정하세요 (예: redis://:password@localhost:6379).
# in-memory 스토리지는 다중 인스턴스 환경에서 rate limit이 공유되지 않습니다.
REDIS_URL = os.environ.get('REDIS_URL', 'memory://')

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=REDIS_URL,
    default_limits=[],
    headers_enabled=True,
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
    return jsonify({'success': False, 'message': '요청이 너무 많습니다. 5분 후 다시 시도해주세요.'}), 429


@app.route('/apply-admin/', methods=['GET'])
def index():
    return render_template('index.html', turnstile_site_key=TURNSTILE_SITE_KEY, mastodon_domain=MASTODON_DOMAIN, server_name=SERVER_NAME_KO, app_version=APP_VERSION)


@app.route('/apply-admin/submit', methods=['POST'])
@limiter.limit("10 per 5 minutes")
def submit():
    # Turnstile 검증
    if TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY:
        token = request.form.get('cf-turnstile-response', '')
        if not verify_turnstile(token, request.remote_addr):
            return jsonify({'success': False, 'message': '보안 인증에 실패했습니다. 다시 시도해주세요.'}), 400

    raw_user_id = request.form.get('mastodon_id', '').strip()
    role_type = request.form.get('role_type', '').strip()

    valid_roles = ['커뮤니티 총괄', '커뮤니티 스탭']
    if role_type not in valid_roles:
        return jsonify({'success': False, 'message': '올바른 신청 유형을 선택해주세요.'}), 400

    if not raw_user_id:
        return jsonify({'success': False, 'message': 'ID를 입력해주세요.'}), 400

    # mastodon_id 정규화 (맨 앞 @ 삭제)
    user_id = raw_user_id.lstrip('@')

    # 아이디@도메인 형태면 @도메인 삭제
    if user_id.lower().endswith(OCCM_DOMAIN_SUFFIX):
        user_id = user_id[:-len(OCCM_DOMAIN_SUFFIX)]

    # 사용자명 형식 검증 (@ 포함 여부 체크 및 정규식 검증)
    if '@' in user_id:
        return jsonify({'success': False, 'message': '이메일 형태의 아이디는 등록할 수 없습니다.'}), 400

    if not MASTODON_USERNAME_RE.match(user_id):
        return jsonify({'success': False, 'message': '올바른 마스토돈 아이디 형식이 아닙니다.'}), 400

    # Mastodon API를 이용한 존재 여부 및 역할 검증
    lookup_url = f"https://{MASTODON_DOMAIN}/api/v1/accounts/lookup?acct={user_id}"

    try:
        response = requests.get(lookup_url, timeout=5)

        # 404 Not Found인 경우 (존재하지 않는 아이디)
        if response.status_code == 404:
            return jsonify({'success': False, 'message': f'{SERVER_NAME_KO} 서버에 존재하지 않는 아이디입니다.\n아이디를 다시 확인해주세요.'}), 404

        if response.status_code == 200:
            account_data = response.json()
            roles = account_data.get('roles', [])
            if any(role.get('name') == role_type for role in roles):
                return jsonify({'success': False, 'message': f'이미 {role_type} 권한이 있습니다.'}), 409
        elif response.status_code != 404:
            return jsonify({'success': False, 'message': '아이디 조회 중 오류가 발생했습니다.\n잠시 후 다시 시도해주세요.'}), 502

    except requests.exceptions.RequestException:
        # 네트워크 오류 등 발생 시
        return jsonify({'success': False, 'message': '서버와 통신 중 오류가 발생했습니다.\n잠시 후 다시 시도해주세요.'}), 502

    # 검증 통과 시 중복 확인 + 저장을 단일 Lock 내에서 수행 (레이스 컨디션 방지)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {user_id}|{role_type}\n"

    with file_lock:
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('] ')
                    existing_rest = parts[1].strip() if len(parts) > 1 else line.strip()
                    existing_id = existing_rest.split('|')[0].strip()
                    if existing_id == user_id:
                        return jsonify({'success': False, 'message': '이미 신청된 아이디입니다.'}), 409

        with open(FILE_PATH, 'a', encoding='utf-8') as f:
            f.write(log_entry)

    return jsonify({'success': True, 'message': '신청이 완료되었습니다.'})


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
            if ADMIN_PASSWORD_HASH and check_password_hash(ADMIN_PASSWORD_HASH, password):
                session.permanent = True
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
                        timestamp_part = parts[0] + ']'
                        rest = parts[1].strip()
                        id_parts = rest.split('|', 1)
                        extracted_id = id_parts[0].strip()
                        extracted_role = id_parts[1].strip() if len(id_parts) > 1 else ''
                        display_text = f"{timestamp_part} {extracted_id}"
                        data_list.append({'full_text': line, 'display_text': display_text, 'id': extracted_id, 'role': extracted_role})
                    else:
                        data_list.append({'full_text': line, 'display_text': line, 'id': line, 'role': ''})

    return render_template('admin.html', items=data_list, mastodon_domain=MASTODON_DOMAIN)


# 목록 데이터 JSON API
@app.route('/apply-admin/listman-data', methods=['GET'])
def listman_data():
    if not is_admin_logged_in():
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401

    data_list = []

    with file_lock:
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    parts = line.split('] ')
                    if len(parts) > 1:
                        timestamp_part = parts[0] + ']'
                        rest = parts[1].strip()
                        id_parts = rest.split('|', 1)
                        extracted_id = id_parts[0].strip()
                        extracted_role = id_parts[1].strip() if len(id_parts) > 1 else ''
                        display_text = f"{timestamp_part} {extracted_id}"
                        data_list.append({'display_text': display_text, 'id': extracted_id, 'role': extracted_role})
                    else:
                        data_list.append({'display_text': line, 'id': line, 'role': ''})

    return jsonify({'success': True, 'items': data_list})


# 삭제 시 줄 번호(index)가 아닌 ID 기준으로 삭제
@app.route('/apply-admin/delete/<string:target_id>', methods=['POST'])
def delete_item(target_id):
    if not is_admin_logged_in():
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401

    with file_lock:
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            new_lines = []
            found = False
            for line in lines:
                parts = line.strip().split('] ')
                if len(parts) > 1:
                    rest = parts[1].strip()
                    current_id = rest.split('|')[0].strip()
                    if current_id == target_id:
                        found = True
                        continue

                new_lines.append(line)

            with open(FILE_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

            if found:
                return jsonify({'success': True, 'message': f'{target_id} 항목이 삭제되었습니다.'})
            else:
                return jsonify({'success': False, 'message': '해당 항목을 찾을 수 없습니다.'}), 404

    return jsonify({'success': False, 'message': '파일이 존재하지 않습니다.'}), 404


@app.route('/apply-admin/check-my-ip', methods=['GET'])
@limiter.limit("100 per 5 minutes")
def check_my_ip():
    return {'ip': request.remote_addr}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

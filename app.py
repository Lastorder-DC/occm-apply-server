from flask import Flask, request, render_template, redirect, url_for, session
import threading
import os
import secrets
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# 파일 쓰기 충돌 방지를 위한 Lock 객체
file_lock = threading.Lock()

# .env 설정 로드
FILE_PATH = os.environ.get('FILE_PATH', 'pending.txt')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
TURNSTILE_SITE_KEY = os.environ.get('TURNSTILE_SITE_KEY', '')
TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')

app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

OCCM_DOMAIN_SUFFIX = '@occm.cc'


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


@app.route('/apply-admin/', methods=['GET'])
def index():
    return render_template('index.html', turnstile_site_key=TURNSTILE_SITE_KEY)


@app.route('/apply-admin/submit', methods=['POST'])
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
                    existing = parts[1].strip() if len(parts) > 1 else line.strip()
                    if existing == user_id:
                        is_duplicate = True
                        break

    if is_duplicate:
        return """
        <script>
            alert('이미 신청된 아이디입니다.');
            window.history.back();
        </script>
        """

    # WebFinger를 이용한 존재 여부 검증
    target_url = f"https://occm.cc/.well-known/webfinger?resource=acct:{user_id}@occm.cc"

    try:
        response = requests.get(target_url, timeout=5)

        # 404 Not Found인 경우 (존재하지 않는 아이디)
        if response.status_code == 404:
            return """
            <script>
                alert('자커마스 서버에 존재하지 않는 아이디입니다.\\n아이디를 다시 확인해주세요.');
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
    log_entry = f"[{timestamp}] {user_id}\n"

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
                        extracted_id = parts[1].strip()
                        data_list.append({'full_text': line, 'id': extracted_id})
                    else:
                        data_list.append({'full_text': line, 'id': line})

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
                    current_id = parts[1].strip()
                    if current_id == target_id:
                        continue

                new_lines.append(line)

            with open(FILE_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

    return redirect(url_for('listman'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

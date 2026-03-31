from flask import Flask, request, render_template, redirect, url_for
import threading
import os
from datetime import datetime
import requests

app = Flask(__name__)

# 파일 쓰기 충돌 방지를 위한 Lock 객체
file_lock = threading.Lock()
FILE_PATH = 'pending.txt'

# 1. 모든 경로 앞에 /apply-admin 추가
@app.route('/apply-admin/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/apply-admin/submit', methods=['POST'])
def submit():
    raw_user_id = request.form.get('mastodon_id', '').strip()

    # [수정] ID 미입력 시 alert 띄우고 뒤로 가기
    if not raw_user_id:
        return """
        <script>
            alert('ID를 입력해주세요.');
            window.history.back();
        </script>
        """

    # mastodon_id 정규화 (맨 앞 @ 삭제)
    user_id = raw_user_id.lstrip('@')

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

# 2. 관리자 경로를 /listman으로 변경
@app.route('/apply-admin/listman', methods=['GET'])
def listman():
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

# 3. 삭제 시 줄 번호(index)가 아닌 ID 기준으로 삭제
@app.route('/apply-admin/delete/<string:target_id>', methods=['POST'])
def delete_item(target_id):
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

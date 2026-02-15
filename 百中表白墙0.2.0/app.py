from flask import Flask, render_template, request, redirect, url_for, session, abort
import json
import os
import time
from datetime import datetime

app = Flask(__name__, static_folder='static', static_url_path='/')
app.secret_key = 'your-secret-key-here'  # 用于会话管理

# 存储IP请求记录：{ip: [timestamp1, timestamp2, ...]}
ip_requests = {}
MAX_REQUESTS = 60  # 1分钟最大请求数
TIME_WINDOW = 60    # 时间窗口（秒）

@app.before_request
def limit_requests():
    ip = request.remote_addr
    current_time = time.time()
    
    # 初始化IP记录
    if ip not in ip_requests:
        ip_requests[ip] = []
    
    # 清理过期记录
    ip_requests[ip] = [t for t in ip_requests[ip] if current_time - t < TIME_WINDOW]
    
    # 检查请求频率
    if len(ip_requests[ip]) >= MAX_REQUESTS:
        abort(429)
    
    # 记录新请求
    ip_requests[ip].append(current_time)

# 确保数据文件夹存在
DATA_DIR = 'data'
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# 表白数据文件路径
CONFESSIONS_FILE = os.path.join(DATA_DIR, 'confessions.json')

# 初始化表白数据文件
if not os.path.exists(CONFESSIONS_FILE):
    with open(CONFESSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f, ensure_ascii=False, indent=2)

# 管理员配置文件路径
ADMIN_CONFIG_FILE = os.path.join(DATA_DIR, 'admin_config.json')

# 初始化管理员配置文件
def init_admin_config():
    if not os.path.exists(ADMIN_CONFIG_FILE):
        admin_config = {
            'admins': [
                {
                    'username': 'admin',
                    'password': 'admin',
                    'role': 'main',
                    'status': 'active'
                }
            ]
        }
        with open(ADMIN_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(admin_config, f, ensure_ascii=False, indent=2)

# 加载管理员配置
def load_admin_config():
    init_admin_config()
    with open(ADMIN_CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# 保存管理员配置
def save_admin_config(config):
    with open(ADMIN_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

# 根据用户名获取管理员信息
def get_admin_by_username(username):
    config = load_admin_config()
    for admin in config.get('admins', []):
        if admin.get('username') == username:
            return admin
    return None

# 字体配置文件路径
FONT_CONFIG_FILE = os.path.join(DATA_DIR, 'font_config.json')

# 初始化字体配置文件
def init_font_config():
    if not os.path.exists(FONT_CONFIG_FILE):
        font_config = {
            'font': 'default'
        }
        with open(FONT_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(font_config, f, ensure_ascii=False, indent=2)

# 加载字体配置
def load_font_config():
    init_font_config()
    with open(FONT_CONFIG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# 保存字体配置
def save_font_config(config):
    with open(FONT_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

# 初始化字体配置
init_font_config()

# 初始化管理员配置
init_admin_config()

# 加载表白数据
def load_confessions():
    with open(CONFESSIONS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# 保存表白数据
def save_confessions(confessions):
    try:
        import fcntl
        with open(CONFESSIONS_FILE, 'r+', encoding='utf-8') as f:
            # 获取文件锁
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                # 清空文件并写入新数据
                f.seek(0)
                f.truncate()
                json.dump(confessions, f, ensure_ascii=False, indent=2)
            finally:
                # 释放文件锁
                fcntl.flock(f, fcntl.LOCK_UN)
    except ImportError:
        # Windows系统不支持fcntl，使用简单的文件写入
        with open(CONFESSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(confessions, f, ensure_ascii=False, indent=2)

@app.route('/')
def index():
    confessions = load_confessions()
    # 只显示未封禁的表白
    active_confessions = [c for c in confessions if c.get('status', 'active') == 'active']
    # 按置顶状态和创建时间排序：置顶的在前，然后按创建时间倒序
    active_confessions.sort(key=lambda x: (not x.get('pinned', False), x['created_at']), reverse=False)
    # 确保置顶的表白信息显示在最前面，未置顶的按创建时间倒序
    pinned_confessions = [c for c in active_confessions if c.get('pinned', False)]
    unpinned_confessions = [c for c in active_confessions if not c.get('pinned', False)]
    # 未置顶的按创建时间倒序
    unpinned_confessions.sort(key=lambda x: x['created_at'], reverse=True)
    # 合并列表：置顶的在前，未置顶的在后
    active_confessions = pinned_confessions + unpinned_confessions
    # 加载字体配置
    font_config = load_font_config()
    return render_template('index.html', confessions=active_confessions, is_admin=session.get('is_admin', False), current_font=font_config['font'])

@app.route('/confess', methods=['GET', 'POST'])
def confess():
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            # 加载现有数据
            confessions = load_confessions()
            # 创建新表白
            new_confession = {
                'id': len(confessions) + 1,
                'content': content,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'active',  # 添加状态字段
                'pinned': False  # 添加置顶字段，默认为False
            }
            # 添加到列表
            confessions.append(new_confession)
            # 保存数据
            save_confessions(confessions)
            return redirect(url_for('index'))
    # 加载字体配置
    font_config = load_font_config()
    return render_template('confess.html', is_admin=session.get('is_admin', False), current_font=font_config['font'])

# 管理员登录
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = get_admin_by_username(username)
        if admin and password == admin.get('password') and admin.get('status') == 'active':
            session['is_admin'] = True
            session['admin_username'] = username
            session['admin_role'] = admin.get('role')
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error='账号或密码错误，或账号已被封禁')
    # 加载字体配置
    font_config = load_font_config()
    return render_template('admin_login.html', current_font=font_config['font'])

# 修改管理员密码
@app.route('/admin/change-password', methods=['GET', 'POST'])
def change_password():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        admin_config = load_admin_config()
        
        # 验证当前密码
        if current_password != admin_config['password']:
            return render_template('change_password.html', error='当前密码错误')
        
        # 验证新密码
        if new_password != confirm_password:
            return render_template('change_password.html', error='两次输入的新密码不一致')
        
        if not new_password:
            return render_template('change_password.html', error='新密码不能为空')
        
        # 更新密码
        admin_config['password'] = new_password
        save_admin_config(admin_config)
        
        # 加载字体配置
        font_config = load_font_config()
        return render_template('change_password.html', success='密码修改成功', is_admin=True, current_font=font_config['font'])
    
    # 加载字体配置
    font_config = load_font_config()
    return render_template('change_password.html', is_admin=True, current_font=font_config['font'])

# 管理员登出
@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    return redirect(url_for('index'))

# 管理员后台
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    confessions = load_confessions()
    search_query = request.args.get('search', '')
    
    # 搜索功能
    if search_query:
        filtered_confessions = [c for c in confessions if search_query in c.get('content', '')]
    else:
        filtered_confessions = confessions
    
    # 加载字体配置
    font_config = load_font_config()
    # 加载管理员配置
    admin_config = load_admin_config()
    
    return render_template('admin_dashboard.html', 
                          confessions=filtered_confessions, 
                          search_query=search_query, 
                          is_admin=True, 
                          admin_role=session.get('admin_role'), 
                          admin_username=session.get('admin_username'),
                          admins=admin_config.get('admins', []),
                          current_font=font_config['font'])

# 管理表白（封禁/解封/删除/置顶/取消置顶）
@app.route('/admin/manage/<int:confession_id>', methods=['POST'])
def manage_confession(confession_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    action = request.form.get('action')
    admin_role = session.get('admin_role')
    
    # 检查权限：副管理员只能执行封禁/解封操作
    if admin_role == 'sub' and action not in ['ban', 'unban']:
        return redirect(url_for('admin_dashboard'))
    
    confessions = load_confessions()
    
    for confession in confessions:
        if confession.get('id') == confession_id:
            if action == 'ban':
                confession['status'] = 'banned'
            elif action == 'unban':
                confession['status'] = 'active'
            elif action == 'delete' and admin_role == 'main':
                confessions.remove(confession)
            elif action == 'pin' and admin_role == 'main':
                confession['pinned'] = True
            elif action == 'unpin' and admin_role == 'main':
                confession['pinned'] = False
            break
    
    save_confessions(confessions)
    return redirect(url_for('admin_dashboard'))

# 切换字体
@app.route('/admin/change-font', methods=['POST'])
def change_font():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    font = request.form.get('font')
    if font:
        # 加载字体配置
        font_config = load_font_config()
        # 更新字体
        font_config['font'] = font
        # 保存配置
        save_font_config(font_config)
    
    return redirect(url_for('admin_dashboard'))

# 管理副管理员账号（封禁/解封）
@app.route('/admin/manage-admin/<username>', methods=['POST'])
def manage_admin(username):
    if not session.get('is_admin') or session.get('admin_role') != 'main':
        return redirect(url_for('admin_login'))
    
    action = request.form.get('action')
    admin_config = load_admin_config()
    
    for admin in admin_config.get('admins', []):
        if admin.get('username') == username and admin.get('role') == 'sub':
            if action == 'ban':
                admin['status'] = 'banned'
            elif action == 'unban':
                admin['status'] = 'active'
            break
    
    save_admin_config(admin_config)
    return redirect(url_for('admin_dashboard'))

@app.errorhandler(429)
def too_many_requests(error):
    # 加载字体配置
    font_config = load_font_config()
    return render_template('429.html', is_admin=False, current_font=font_config['font']), 429

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
import json
import os

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_from_directory, url_for)

import config
from database import (delete_plugin, delete_scan, get_all_plugins, get_all_scans,
                       get_all_vulnerabilities, get_plugin, get_scan,
                       get_vulnerabilities_by_scan, get_vulnerability,
                       init_db, save_plugin)
from scanner import start_worker, submit_scan

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False


# ==== 页面路由 ====

@app.route('/')
def index():
    scans = get_all_scans()
    plugin_count = len(get_all_plugins())
    vuln_count = len(get_all_vulnerabilities())
    return render_template('index.html',
                           scans=scans,
                           plugin_count=plugin_count,
                           vuln_count=vuln_count)


@app.route('/scans/new', methods=['GET', 'POST'])
def new_scan():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        scan_type = request.form.get('scan_type', 'full')
        if not target:
            return render_template('new_scan.html', error='请输入目标 IP 或域名')
        scan_id = submit_scan(target, scan_type)
        return redirect(url_for('scan_detail', scan_id=scan_id))
    return render_template('new_scan.html')


@app.route('/scans/<int:scan_id>')
def scan_detail(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return "扫描记录不存在", 404
    vulns = get_vulnerabilities_by_scan(scan_id)
    return render_template('scan_detail.html', scan=scan, vulns=vulns)


@app.route('/vulnerabilities')
def vulnerability_list():
    vulns = get_all_vulnerabilities()
    return render_template('vulnerability_list.html', vulns=vulns)


@app.route('/vulnerabilities/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    vuln = get_vulnerability(vuln_id)
    if not vuln:
        return "漏洞记录不存在", 404
    return render_template('vulnerability_detail.html', vuln=vuln)


@app.route('/plugins')
def plugin_list():
    plugins = get_all_plugins()
    return render_template('plugins.html', plugins=plugins)


@app.route('/plugins/editor', methods=['GET', 'POST'])
@app.route('/plugins/editor/<int:plugin_id>', methods=['GET', 'POST'])
def plugin_editor(plugin_id=None):
    plugin = None
    if plugin_id:
        plugin = get_plugin(plugin_id)
        if not plugin:
            return "插件不存在", 404

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        content = request.form.get('content', '').strip()
        description = request.form.get('description', '').strip()
        if not name or not content:
            return render_template('plugin_editor.html',
                                   plugin=plugin,
                                   error='插件名称和内容不能为空')
        save_plugin(name, content, description)
        return redirect(url_for('plugin_list'))

    return render_template('plugin_editor.html', plugin=plugin)


@app.route('/api/plugins/<int:plugin_id>/delete', methods=['POST'])
def api_delete_plugin(plugin_id):
    delete_plugin(plugin_id)
    return jsonify({'ok': True})


@app.route('/api/scans/<int:scan_id>/delete', methods=['POST'])
def api_delete_scan(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'not found'}), 404
    delete_scan(scan_id)
    return jsonify({'ok': True})


# ==== API 路由 ====

@app.route('/api/scans/<int:scan_id>/status')
def api_scan_status(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'not found'}), 404
    return jsonify({
        'id': scan['id'],
        'target': scan['target'],
        'status': scan['status'],
        'created_at': scan['created_at'],
        'updated_at': scan['updated_at'],
    })


@app.route('/api/scans/<int:scan_id>/nmap_output')
def api_nmap_output(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'output': scan.get('nmap_output', '')})


@app.route('/api/scans/<int:scan_id>/nuclei_output')
def api_nuclei_output(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'output': scan.get('nuclei_output', '')})


# ==== 启动 ====

if __name__ == '__main__':
    if config.DB_TYPE == 'sqlite':
        os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    init_db()
    start_worker()
    db_info = 'SQLite' if config.DB_TYPE == 'sqlite' else f'MySQL ({config.MYSQL_USER}@{config.MYSQL_HOST}:{config.MYSQL_PORT}/{config.MYSQL_DATABASE})'
    print(f"BlackBox Scanner 启动中...")
    print(f"数据库: {db_info}")
    print(f"访问地址: http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG
    )

import json
import os
import re
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

from config import NMAP_PATH, NUCLEI_PATH, DIRSEARCH_PATH, PLUGINS_DIR, NUCLEI_TEMPLATES_DIR
from database import (create_scan, get_all_plugins, insert_vulnerability,
                       update_scan_status, get_scan)

SCAN_QUEUE = []
SCAN_LOCK = threading.Lock()
SCAN_THREAD = None


def _run_command(cmd, timeout=600):
    """执行命令并返回 stdout/stderr"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout, shell=False,
            encoding='utf-8', errors='replace',
        )
        return result.stdout or '', result.stderr or '', result.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', -1
    except FileNotFoundError:
        return '', f'Command not found: {cmd[0]}', -1


def run_nmap(target):
    """执行 Nmap 扫描，返回 (可读文本输出, 开放端口列表)"""
    cmd = [NMAP_PATH, '-sV', '-T4', '-Pn', '-oX', '-', target]
    stdout, stderr, rc = _run_command(cmd, timeout=300)

    if rc != 0:
        return f"Nmap 扫描失败 (code={rc}):\n{stderr}", []

    open_ports = _parse_nmap_xml(stdout)

    # 生成可读文本摘要
    lines = [f"Nmap 扫描完成 - 目标: {target}", f"发现 {len(open_ports)} 个开放端口:", ""]
    for p in open_ports:
        lines.append(f"  {p['port']}/{p['protocol']}\t{p['service']}")
    if not open_ports:
        lines.append("  (未发现开放端口)")
    text_output = '\n'.join(lines)

    return text_output, open_ports


def _parse_nmap_xml(xml_output):
    """从 Nmap XML 输出解析开放端口和对应服务"""
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.iter('host'):
            for port in host.iter('port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    portid = port.get('portid', '')
                    protocol = port.get('protocol', '')
                    service = port.find('service')
                    service_name = service.get('name', '') if service is not None else ''
                    ports.append({
                        'port': portid,
                        'protocol': protocol,
                        'service': service_name,
                    })
    except ET.ParseError:
        pass
    return ports


def _sync_plugins_to_disk():
    """将数据库中的自定义插件同步到 plugins 目录"""
    if not os.path.exists(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR)
    plugins = get_all_plugins()
    for p in plugins:
        filepath = os.path.join(PLUGINS_DIR, f"{p['name']}.yaml")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(p['content'])


def run_nuclei(scan_id, target_urls):
    """执行 Nuclei 扫描并解析 JSON 输出
    target_urls: 完整 URL 列表，如 ['http://192.168.1.1:80', 'https://192.168.1.1:443']
    """
    if not target_urls:
        print("[Nuclei] 无扫描目标，跳过")
        return '(无扫描目标)'

    _sync_plugins_to_disk()

    # 写入 targets 文件
    targets_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    for url in target_urls:
        targets_file.write(url + '\n')
    targets_path = targets_file.name
    targets_file.close()

    cmd = [
        NUCLEI_PATH,
        '-list', targets_path,
        '-jsonl',
        '-no-color',
        '-timeout', '30',
        '-retries', '1',
    ]

    plugins_path = PLUGINS_DIR
    if os.path.exists(plugins_path) and os.listdir(plugins_path):
        cmd.extend(['-templates', plugins_path])

    if os.path.exists(NUCLEI_TEMPLATES_DIR):
        cmd.extend(['-templates', NUCLEI_TEMPLATES_DIR])

    print(f"[Nuclei] 扫描 {len(target_urls)} 个目标: {target_urls}")
    stdout, stderr, rc = _run_command(cmd, timeout=600)

    # 清理 targets 文件
    try:
        os.unlink(targets_path)
    except OSError:
        pass

    # 从 stdout (jsonl) 解析漏洞
    parsed_vulns = []
    for line in stdout.split('\n'):
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            entry = json.loads(line)
            parsed_vulns.append(_parse_nuclei_entry(entry))
        except json.JSONDecodeError:
            continue

    print(f"[Nuclei] 解析到 {len(parsed_vulns)} 个漏洞")

    for v in parsed_vulns:
        insert_vulnerability(
            scan_id=scan_id,
            template_name=v.get('template_name', ''),
            template_id=v.get('template_id', ''),
            severity=v.get('severity', ''),
            matched_at=v.get('matched_at', ''),
            ip=v.get('ip', ''),
            host=v.get('host', ''),
            request_headers=v.get('request_headers', ''),
            request_body=v.get('request_body', ''),
            response_headers=v.get('response_headers', ''),
            response_body=v.get('response_body', ''),
            info_json=v.get('info_json', ''),
            curl_command=v.get('curl_command', ''),
        )

    # 生成可读输出
    output_lines = []
    if stderr:
        output_lines.append(f"[Nuclei stderr]\n{stderr}")
    if stdout and not parsed_vulns:
        output_lines.append(f"[Nuclei stdout]\n{stdout}")
    if parsed_vulns:
        output_lines.append(f"发现 {len(parsed_vulns)} 个漏洞:")
        for v in parsed_vulns:
            output_lines.append(f"  [{v.get('severity', '?')}] {v.get('template_name', '?')} - {v.get('matched_at', '?')}")
    return '\n'.join(output_lines) if output_lines else '(无输出)'


def _build_target_urls(target, open_ports):
    """根据 nmap 扫描结果构建完整的扫描 URL 列表"""
    urls = []
    for p in open_ports:
        port = p['port']
        service = p.get('service', '').lower()
        # 判断是否应该用 https
        if port == '443' or 'ssl' in service or 'https' in service or 'tls' in service:
            urls.append(f'https://{target}:{port}')
        else:
            urls.append(f'http://{target}:{port}')
    return urls


def _filter_http_ports(open_ports):
    """从 nmap 结果筛选 HTTP/HTTPS 端口"""
    http_ports = []
    for p in open_ports:
        service = p.get('service', '').lower()
        port = p['port']
        if service in ('http', 'https', 'http-proxy', 'ssl', 'tls',
                       'http-alt', 'https-alt', 'www', 'tomcat', 'nginx', 'apache',
                       'iis', 'jetty', 'node', 'gunicorn', 'uwsgi') or \
           port in ('80', '443', '8080', '8443', '8000', '8090', '8888', '9090', '3000', '5000'):
            http_ports.append(p)
    return http_ports


def run_dirsearch(target_urls):
    """执行 Dirsearch 目录扫描，只保留非 404 的发现结果"""
    if not target_urls:
        print("[Dirsearch] 无 HTTP/HTTPS 目标，跳过")
        return '(无 HTTP/HTTPS 端口，跳过目录扫描)'

    all_output = []
    for url in target_urls:
        print(f"[Dirsearch] 扫描: {url}")
        cmd = [
            DIRSEARCH_PATH,
            '-u', url,
            '-e', 'php,asp,aspx,jsp,html,txt,json,xml,conf,bak,zip,tar.gz,sql,db,log,env,git,svn',
            '--format=plain',
            '--no-color',
            '--timeout=10',
            '--max-time=300',
            '--retries=1',
            '--random-agent',
            '--full-url',
        ]
        stdout, stderr, rc = _run_command(cmd, timeout=360)
        if rc != 0 and not stdout:
            all_output.append(f"--- {url} ---\n[扫描失败]: {stderr[:200]}")
            continue

        # 解析 plain 格式输出，过滤进度行，只保留非 404/429/503 的发现
        found = []
        for line in stdout.split('\n'):
            line = line.strip()
            # 跳过空行、进度（%）、控制字符
            if not line or line.startswith('%') or line.startswith('\x1b'):
                continue
            # dirsearch plain 格式: "SC - PATH" 或 "SC - PATH  -> REDIRECT"
            # SC 是三位状态码
            parts = line.split(None, 1)  # split by whitespace, max 2 parts
            if len(parts) >= 2:
                code = parts[0]
                rest = parts[1]
                # 只收集非 404 且非 429 非 503 的条目
                if code.isdigit() and code not in ('404', '429', '503'):
                    # 去掉 redirect 箭头后面的内容，保留完整路径
                    if '  -> ' in rest:
                        rest = rest.split('  -> ')[0]
                    found.append(f"  {code}  {rest}")
                elif code == '404':
                    pass  # 忽略 404
                else:
                    pass  # 可能是其他格式行，忽略

        if found:
            found.sort(key=lambda x: (not x.strip().startswith('  2'), x))  # 2xx 排前面
            all_output.append(f"--- {url} ---\n" + '\n'.join(found))
        else:
            all_output.append(f"--- {url} ---\n(未发现有效目录/文件)")

    return '\n\n'.join(all_output)


def _parse_nuclei_entry(entry):
    """解析单条 Nuclei JSON 结果"""
    info = entry.get('info', {})
    request_str = entry.get('request', '')
    response_str = entry.get('response', '')

    req_headers, req_body = _split_headers_body(request_str)
    resp_headers, resp_body = _split_headers_body(response_str)

    curl_cmd = _build_curl(entry)

    return {
        'template_name': info.get('name', ''),
        'template_id': entry.get('template-id', ''),
        'severity': info.get('severity', ''),
        'matched_at': entry.get('matched-at', ''),
        'ip': entry.get('ip', ''),
        'host': entry.get('host', ''),
        'request_headers': req_headers,
        'request_body': req_body,
        'response_headers': resp_headers,
        'response_body': resp_body,
        'info_json': json.dumps(info, ensure_ascii=False),
        'curl_command': curl_cmd,
    }


def _split_headers_body(raw):
    """将原始 HTTP 消息分割为 headers 和 body"""
    if not raw:
        return '', ''
    parts = raw.split('\r\n\r\n', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return raw, ''


def _build_curl(entry):
    """根据条目信息生成 curl 命令"""
    method = entry.get('request_method', entry.get('method', 'GET'))
    matched_at = entry.get('matched-at', '')
    request_str = entry.get('request', '')
    
    if not matched_at:
        return ''

    parts = ['curl', '-X', method]

    lines = request_str.split('\n') if request_str else []
    for line in lines:
        line = line.strip()
        if line.lower().startswith(('host:', 'content-length:', 'connection:')):
            continue
        if ':' in line and not line.startswith('{'):
            parts.extend(['-H', line])

    body_start = request_str.find('\r\n\r\n') if request_str else -1
    if body_start > 0:
        body = request_str[body_start + 4:]
        if body.strip():
            parts.extend(['-d', body.strip()])

    parts.append(matched_at)
    return ' '.join(parts)


def _is_url(target):
    """判断目标是否已是完整 URL"""
    return target.startswith('http://') or target.startswith('https://')


def _scan_worker():
    """后台扫描工作线程，支持多种 scan_type"""
    global SCAN_QUEUE
    while True:
        scan_id = None
        with SCAN_LOCK:
            if SCAN_QUEUE:
                scan_id = SCAN_QUEUE.pop(0)

        if scan_id is None:
            time.sleep(2)
            continue

        scan = get_scan(scan_id)
        if not scan:
            continue

        target = scan['target']
        scan_type = scan.get('scan_type', 'full')

        try:
            if _is_url(target):
                _scan_url_mode(scan_id, target, scan_type)
            else:
                _scan_ip_mode(scan_id, target, scan_type)
        except Exception as e:
            update_scan_status(scan_id, 'failed', nmap_output=str(e))


def _scan_url_mode(scan_id, target, scan_type):
    """URL 模式：跳过 Nmap，按 scan_type 执行 Dirsearch/Nuclei"""
    print(f"[Scanner] URL 模式: {target}")

    if scan_type == 'dirsearch':
        # 仅 dirsearch
        update_scan_status(scan_id, 'dirsearch_scanning',
                           nmap_output='(已跳过 - URL 模式)',
                           open_ports=target)
        dirsearch_output = run_dirsearch([target])
        update_scan_status(scan_id, 'completed', dirsearch_output=dirsearch_output)

    elif scan_type == 'nmap':
        # nmap 不可用，跳过
        update_scan_status(scan_id, 'completed',
                           nmap_output='(URL 模式下不支持仅 Nmap 扫描)',
                           open_ports=target)

    else:
        # full / dirsearch_nmap: Dirsearch → Nuclei
        # 1. Dirsearch
        update_scan_status(scan_id, 'dirsearch_scanning',
                           nmap_output='(已跳过 - URL 直接扫描模式)',
                           open_ports=target)
        dirsearch_output = run_dirsearch([target])

        if scan_type == 'dirsearch_nmap':
            # 仅 Dirsearch
            update_scan_status(scan_id, 'completed', dirsearch_output=dirsearch_output)
            return

        # 2. Nuclei
        update_scan_status(scan_id, 'nuclei_scanning', dirsearch_output=dirsearch_output)
        nuclei_output = run_nuclei(scan_id, [target])
        update_scan_status(scan_id, 'completed',
                           nuclei_output=nuclei_output,
                           dirsearch_output=dirsearch_output)


def _scan_ip_mode(scan_id, target, scan_type):
    """IP/域名模式：Nmap → (Dirsearch) → (Nuclei)"""
    # 1. Nmap
    update_scan_status(scan_id, 'nmap_scanning')
    nmap_output, open_ports = run_nmap(target)
    ports_display = ', '.join(f"{p['port']}/{p['protocol']}({p['service']})" for p in open_ports) if open_ports else '(无)'
    all_urls = _build_target_urls(target, open_ports)

    if scan_type == 'nmap':
        # 仅 nmap
        update_scan_status(scan_id, 'completed', nmap_output=nmap_output, open_ports=ports_display)
        return

    # 2. 筛选 HTTP 端口 → Dirsearch
    dirsearch_output = None
    http_ports = _filter_http_ports(open_ports)
    if http_ports:
        http_urls = _build_target_urls(target, http_ports)
        update_scan_status(scan_id, 'dirsearch_scanning',
                           nmap_output=nmap_output,
                           open_ports=ports_display)
        dirsearch_output = run_dirsearch(http_urls)
    else:
        print("[Scanner] 无 HTTP 端口，跳过 Dirsearch")

    if scan_type == 'dirsearch_nmap':
        # nmap → dirsearch，不跑 nuclei
        update_scan_status(scan_id, 'completed',
                           nmap_output=nmap_output,
                           open_ports=ports_display,
                           dirsearch_output=dirsearch_output)
        return

    # 3. Nuclei（full / dirsearch_full 都跑）
    update_scan_status(scan_id, 'nuclei_scanning',
                       nmap_output=nmap_output,
                       open_ports=ports_display,
                       dirsearch_output=dirsearch_output)
    nuclei_output = run_nuclei(scan_id, all_urls)
    update_scan_status(scan_id, 'completed',
                       nuclei_output=nuclei_output,
                       dirsearch_output=dirsearch_output)


def start_worker():
    """启动后台扫描线程"""
    global SCAN_THREAD
    if SCAN_THREAD is None or not SCAN_THREAD.is_alive():
        SCAN_THREAD = threading.Thread(target=_scan_worker, daemon=True)
        SCAN_THREAD.start()


def submit_scan(target, scan_type='full'):
    """提交扫描任务到队列"""
    scan_id = create_scan(target, scan_type)
    with SCAN_LOCK:
        SCAN_QUEUE.append(scan_id)
    return scan_id


def batch_submit_scan(targets, scan_type='full'):
    """批量提交扫描任务"""
    scan_ids = []
    for target in targets:
        target = target.strip()
        if not target or target.startswith('#'):
            continue
        sid = create_scan(target, scan_type)
        scan_ids.append(sid)
    with SCAN_LOCK:
        SCAN_QUEUE.extend(scan_ids)
    return scan_ids


def remove_from_queue(scan_ids):
    """从等待队列中移除指定任务（不删除数据库记录）"""
    removed = 0
    with SCAN_LOCK:
        for sid in scan_ids:
            if sid in SCAN_QUEUE:
                SCAN_QUEUE.remove(sid)
                removed += 1
    return removed

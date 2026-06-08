"""
C盘深度清理工具 - Flask Web后端
提供REST API接口和Web界面
"""
import os
import sys
import json
import threading
from flask import Flask, render_template, jsonify, request, send_from_directory


# PyInstaller 兼容：获取正确的资源路径
def resource_path(relative_path):
    """获取资源文件的绝对路径，兼容 PyInstaller 打包后的环境"""
    if getattr(sys, 'frozen', False):
        # 运行在 PyInstaller 打包的 exe 中
        base_path = sys._MEIPASS
    else:
        # 运行在普通 Python 环境中
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import DiskScanner, format_size, categorize_file, LARGE_FILE_THRESHOLD
from cleaner import clean_file_list, CleanResult, get_clean_summary, format_size_simple

app = Flask(
    __name__,
    template_folder=resource_path('templates'),
    static_folder=resource_path('static'),
)

# 全局扫描器
scanner = DiskScanner()

# 清理历史
clean_history = []


# ============================================================
# 页面路由
# ============================================================
@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


# ============================================================
# API - 扫描
# ============================================================
@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """开始扫描C盘"""
    if scanner.scanning:
        return jsonify({'status': 'error', 'message': '扫描正在进行中'})

    data = request.get_json() or {}
    scan_paths = data.get('paths', ['C:\\'])

    def on_complete(results):
        pass  # 结果通过get_results获取

    scanner.start_scan(scan_paths, on_complete)
    return jsonify({'status': 'started', 'message': '扫描已开始'})


@app.route('/api/scan/status')
def scan_status():
    """获取扫描状态和结果"""
    results = scanner.get_results()
    return jsonify(results)


@app.route('/api/scan/cancel', methods=['POST'])
def cancel_scan():
    """取消扫描"""
    scanner.cancel_scan()
    return jsonify({'status': 'cancelled'})


# ============================================================
# API - 文件列表
# ============================================================
@app.route('/api/files/safe')
def get_safe_files():
    """获取可安全清理的文件列表"""
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    safe_files = results.get('safe_files', [])
    # 过滤掉太小的文件
    filtered = [f for f in safe_files if f.get('size', 0) > 1024 * 1024]  # >1MB

    return jsonify({
        'status': 'ok',
        'files': filtered,
        'count': len(filtered),
        'total_size': sum(f.get('size', 0) for f in filtered),
        'total_size_formatted': format_size(sum(f.get('size', 0) for f in filtered)),
    })


@app.route('/api/files/caution')
def get_caution_files():
    """获取谨慎清理的文件列表"""
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    caution_files = results.get('caution_files', [])
    filtered = [f for f in caution_files if f.get('size', 0) > 1024 * 1024]

    return jsonify({
        'status': 'ok',
        'files': filtered,
        'count': len(filtered),
        'total_size': sum(f.get('size', 0) for f in filtered),
        'total_size_formatted': format_size(sum(f.get('size', 0) for f in filtered)),
    })


@app.route('/api/files/large')
def get_large_files():
    """获取大文件列表"""
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    large_files = results.get('large_files', [])

    return jsonify({
        'status': 'ok',
        'files': large_files,
        'count': len(large_files),
        'total_size': sum(f.get('size', 0) for f in large_files),
        'total_size_formatted': format_size(sum(f.get('size', 0) for f in large_files)),
    })


@app.route('/api/files/treemap')
def get_treemap_data():
    """获取树状图数据（用于可视化）"""
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    # 构建树状图数据
    treemap_data = []

    # 安全文件
    safe_files = results.get('safe_files', [])[:50]
    for f in safe_files:
        if f.get('size', 0) > 1024 * 1024:
            treemap_data.append({
                'name': f.get('name', ''),
                'path': f.get('path', ''),
                'size': f.get('size', 0),
                'size_formatted': f.get('size_formatted', ''),
                'category': 'safe',
                'category_label': '可安全清理',
                'parent': '安全清理',
            })

    # 谨慎文件
    caution_files = results.get('caution_files', [])[:50]
    for f in caution_files:
        if f.get('size', 0) > 1024 * 1024:
            treemap_data.append({
                'name': f.get('name', ''),
                'path': f.get('path', ''),
                'size': f.get('size', 0),
                'size_formatted': f.get('size_formatted', ''),
                'category': 'caution',
                'category_label': '谨慎清理',
                'parent': '谨慎清理',
            })

    # 大文件
    large_files = results.get('large_files', [])[:30]
    for f in large_files:
        if f.get('size', 0) > LARGE_FILE_THRESHOLD:
            treemap_data.append({
                'name': f.get('name', ''),
                'path': f.get('path', ''),
                'size': f.get('size', 0),
                'size_formatted': f.get('size_formatted', ''),
                'category': 'large',
                'category_label': '大文件',
                'parent': '大文件',
            })

    return jsonify({
        'status': 'ok',
        'data': treemap_data,
        'count': len(treemap_data),
    })


# ============================================================
# API - 清理操作
# ============================================================
@app.route('/api/clean/quick', methods=['POST'])
def quick_clean():
    """
    一键清理 - 只清理安全文件
    删除前显示大文件列表让用户确认
    """
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    data = request.get_json() or {}
    selected_paths = data.get('paths', None)  # 如果指定了路径，只清理选中的
    confirmed = data.get('confirmed', False)

    safe_files = results.get('safe_files', [])
    # 过滤 >1MB 的文件
    files_to_clean = [f for f in safe_files if f.get('size', 0) > 1024 * 1024]

    if selected_paths:
        files_to_clean = [f for f in files_to_clean if f.get('path') in selected_paths]

    if not confirmed:
        # 返回预览列表，等待用户确认
        large_items = [f for f in files_to_clean if f.get('size', 0) > 10 * 1024 * 1024]  # >10MB
        return jsonify({
            'status': 'preview',
            'message': '请确认要删除的文件',
            'files': files_to_clean[:200],  # 限制返回数量
            'large_items': large_items[:50],
            'count': len(files_to_clean),
            'total_size': sum(f.get('size', 0) for f in files_to_clean),
            'total_size_formatted': format_size(sum(f.get('size', 0) for f in files_to_clean)),
            'large_count': len(large_items),
            'large_size_formatted': format_size(sum(f.get('size', 0) for f in large_items)),
        })

    # 执行清理
    result = clean_file_list(files_to_clean, permanent=False)

    # 记录历史
    clean_history.append({
        'time': __import__('datetime').datetime.now().isoformat(),
        'type': 'quick',
        'result': {
            'deleted_count': len(result.deleted),
            'failed_count': len(result.failed),
            'skipped_count': len(result.skipped),
            'total_freed': result.total_freed,
            'total_freed_formatted': format_size(result.total_freed),
        }
    })

    return jsonify({
        'status': 'done',
        'deleted': len(result.deleted),
        'failed': len(result.failed),
        'skipped': len(result.skipped),
        'total_freed': result.total_freed,
        'total_freed_formatted': format_size(result.total_freed),
        'details': {
            'deleted_files': result.deleted[:50],
            'failed_files': result.failed[:20],
            'skipped_files': result.skipped[:20],
        }
    })


@app.route('/api/clean/deep', methods=['POST'])
def deep_clean():
    """
    深度清理 - 清理安全文件 + 谨慎文件
    包含可能影响用户使用但不影响系统的文件
    """
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    data = request.get_json() or {}
    selected_paths = data.get('paths', None)
    confirmed = data.get('confirmed', False)
    include_caution = data.get('include_caution', True)
    permanent = data.get('permanent', False)  # 是否永久删除

    safe_files = results.get('safe_files', [])
    caution_files = results.get('caution_files', [])

    files_to_clean = [f for f in safe_files if f.get('size', 0) > 1024 * 1024]
    caution_to_clean = [f for f in caution_files if f.get('size', 0) > 1024 * 1024] if include_caution else []

    all_files = files_to_clean + caution_to_clean

    if selected_paths:
        all_files = [f for f in all_files if f.get('path') in selected_paths]

    if not confirmed:
        large_items = [f for f in all_files if f.get('size', 0) > 10 * 1024 * 1024]

        # 分类显示
        caution_only = [f for f in caution_to_clean if f.get('size', 0) > 10 * 1024 * 1024]

        return jsonify({
            'status': 'preview',
            'message': '深度清理将删除以下文件，请仔细确认',
            'files': all_files[:300],
            'large_items': large_items[:80],
            'caution_items': caution_only[:50],  # 特别标出的谨慎文件
            'safe_count': len(files_to_clean),
            'caution_count': len(caution_to_clean),
            'total_count': len(all_files),
            'total_size': sum(f.get('size', 0) for f in all_files),
            'total_size_formatted': format_size(sum(f.get('size', 0) for f in all_files)),
            'caution_size_formatted': format_size(sum(f.get('size', 0) for f in caution_to_clean)),
            'safe_size_formatted': format_size(sum(f.get('size', 0) for f in files_to_clean)),
            'warnings': [
                '浏览器缓存将被清除，下次打开网页可能需要重新加载',
                '下载文件夹中的大文件将被删除，请确认没有需要的文件',
                '部分应用缓存将被清除，应用可能需要重新登录',
                '系统临时文件将被清除，正在运行的应用可能受影响',
            ]
        })

    # 执行清理
    result = clean_file_list(all_files, permanent=permanent)

    clean_history.append({
        'time': __import__('datetime').datetime.now().isoformat(),
        'type': 'deep',
        'permanent': permanent,
        'result': {
            'deleted_count': len(result.deleted),
            'failed_count': len(result.failed),
            'skipped_count': len(result.skipped),
            'total_freed': result.total_freed,
            'total_freed_formatted': format_size(result.total_freed),
        }
    })

    return jsonify({
        'status': 'done',
        'deleted': len(result.deleted),
        'failed': len(result.failed),
        'skipped': len(result.skipped),
        'total_freed': result.total_freed,
        'total_freed_formatted': format_size(result.total_freed),
        'details': {
            'deleted_files': result.deleted[:50],
            'failed_files': result.failed[:20],
            'skipped_files': result.skipped[:20],
        }
    })


@app.route('/api/clean/custom', methods=['POST'])
def custom_clean():
    """自定义清理 - 根据用户选择的文件列表清理"""
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    data = request.get_json() or {}
    paths = data.get('paths', [])
    confirmed = data.get('confirmed', False)
    permanent = data.get('permanent', False)

    if not paths:
        return jsonify({'status': 'error', 'message': '请选择要清理的文件'})

    # 从所有结果中匹配
    all_safe = results.get('safe_files', [])
    all_caution = results.get('caution_files', [])
    all_large = results.get('large_files', [])
    all_files_map = {}

    for f in all_safe + all_caution + all_large:
        all_files_map[f.get('path', '')] = f

    files_to_clean = [all_files_map[p] for p in paths if p in all_files_map]

    if not confirmed:
        return jsonify({
            'status': 'preview',
            'message': '请确认要删除的文件',
            'files': files_to_clean,
            'total_count': len(files_to_clean),
            'total_size': sum(f.get('size', 0) for f in files_to_clean),
            'total_size_formatted': format_size(sum(f.get('size', 0) for f in files_to_clean)),
        })

    result = clean_file_list(files_to_clean, permanent=permanent)

    clean_history.append({
        'time': __import__('datetime').datetime.now().isoformat(),
        'type': 'custom',
        'permanent': permanent,
        'result': {
            'deleted_count': len(result.deleted),
            'failed_count': len(result.failed),
            'skipped_count': len(result.skipped),
            'total_freed': result.total_freed,
            'total_freed_formatted': format_size(result.total_freed),
        }
    })

    return jsonify({
        'status': 'done',
        'deleted': len(result.deleted),
        'failed': len(result.failed),
        'skipped': len(result.skipped),
        'total_freed': result.total_freed,
        'total_freed_formatted': format_size(result.total_freed),
        'details': {
            'deleted_files': result.deleted[:50],
            'failed_files': result.failed[:20],
            'skipped_files': result.skipped[:20],
        }
    })


# ============================================================
# API - 摘要
# ============================================================
@app.route('/api/summary')
def get_summary():
    """获取清理摘要"""
    results = scanner.get_results()
    if results.get('status') == 'not_scanned':
        return jsonify({'status': 'error', 'message': '请先扫描'})

    return jsonify({
        'status': 'ok',
        'summary': results.get('summary', {}),
    })


@app.route('/api/history')
def get_history():
    """获取清理历史"""
    return jsonify({
        'status': 'ok',
        'history': clean_history[-20:],  # 最近20条
    })


# ============================================================
# 启动
# ============================================================
def main():
    import webbrowser
    import socket

    # 获取可用端口
    port = 5000
    for p in range(5000, 5100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', p)) != 0:
                port = p
                break

    print("=" * 60)
    print("  C盘深度清理工具 v1.0")
    print("  Disk Cleaner with Treemap Visualization")
    print("=" * 60)
    print(f"  启动服务: http://localhost:{port}")
    print(f"  按 Ctrl+C 停止服务")
    print("=" * 60)

    # 自动打开浏览器
    webbrowser.open(f'http://localhost:{port}')

    app.run(host='127.0.0.1', port=port, debug=False, threaded=True)


if __name__ == '__main__':
    main()

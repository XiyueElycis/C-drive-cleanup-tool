"""
磁盘扫描引擎 - 快速扫描C盘大文件和文件夹
使用os.scandir提升性能，跳过系统保护目录
"""
import os
import stat
import time
import threading
from collections import defaultdict
from pathlib import Path

# ============================================================
# 系统保护目录 - 绝对不能删除
# ============================================================
PROTECTED_PATHS = {
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\Boot",
    r"C:\Windows\System",
    r"C:\Windows\SystemResources",
    r"C:\Windows\WinSxS",  # Windows组件存储
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
    r"C:\ProgramData\Package Cache",
    r"C:\Users\All Users",
    r"C:\bootmgr",
    r"C:\BOOTNXT",
    r"C:\Boot",
    r"C:\EFI",
    r"C:\swapfile.sys",
    r"C:\pagefile.sys",
    r"C:\hiberfil.sys",
    r"C:\DumpStack.log",
}

# 系统关键文件夹（可扫描但不可删除其中文件）
SYSTEM_CRITICAL_DIRS = {
    "Windows", "Program Files", "Program Files (x86)",
    "ProgramData", "System Volume Information",
    "$Recycle.Bin", "Config.Msi", "Recovery",
}

# 可安全清理的路径模式
SAFE_CLEAN_PATTERNS = [
    r"C:\Windows\Temp",
    r"C:\Windows\Prefetch",
    r"C:\Windows\SoftwareDistribution\Download",
    r"C:\Windows\Logs",
    r"C:\Windows\System32\LogFiles",
    r"C:\Windows\System32\WDI\LogFiles",
    r"C:\Windows\LiveKernelReports",
    r"C:\Windows\Memory.dmp",
    r"C:\Windows\Minidump",
    r"C:\Windows\CbsTemp",
    r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp",
    r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp",
    r"C:\$Recycle.Bin",
]

# 用户临时文件模式
USER_TEMP_PATTERNS = [
    r"AppData\Local\Temp",
    r"AppData\Local\Microsoft\Windows\INetCache",
    r"AppData\Local\Microsoft\Windows\Temporary Internet Files",
    r"AppData\Local\Microsoft\Windows\Explorer",
    r"AppData\Local\Microsoft\Windows\WER",
    r"AppData\Local\Microsoft\Windows\WebCache",
    r"AppData\Local\CrashDumps",
    r"AppData\Local\D3DSCache",
    r"AppData\Local\NVIDIA\DXCache",
    r"AppData\Local\NVIDIA\GLCache",
    r"AppData\LocalLow\NVIDIA\PerDriverVersion\DXCache",
    r"AppData\LocalLow\NVIDIA\PerDriverVersion\GLCache",
    r".cache",
    r".npm\_cacache",
    r"AppData\Roaming\npm-cache",
    r"AppData\Local\pip\cache",
    r"AppData\Local\Programs\Common\Microsoft\Visual C++ for Python",
    r"AppData\Roaming\Python\Python311\site-packages",
]

# 谨慎清理 - 可能影响用户使用但不影响系统
CAUTION_PATTERNS = [
    r"AppData\Local\Google\Chrome\User Data\Default\Cache",
    r"AppData\Local\Google\Chrome\User Data\Default\Code Cache",
    r"AppData\Local\Mozilla\Firefox\Profiles",
    r"AppData\Local\Microsoft\Edge\User Data\Default\Cache",
    r"AppData\Local\Microsoft\Edge\User Data\Default\Code Cache",
    r"AppData\Local\Microsoft\Teams",
    r"AppData\Roaming\Microsoft\Teams\Cache",
    r"AppData\Local\Discord\Cache",
    r"AppData\Roaming\discord\Cache",
    r"AppData\Local\Microsoft\Windows\Notifications",
    r"AppData\Local\SquirrelTemp",
    r"AppData\Local\Microsoft\Terminal Server Client\Cache",
    r"AppData\Roaming\Adobe\Common\Media Cache",
    r"AppData\Roaming\Code\Cache",
    r"AppData\Roaming\Code\CachedData",
    r"Downloads",
    r"AppData\Local\Microsoft\Windows\INetCache\IE",
]

# 临时文件扩展名
TEMP_EXTENSIONS = {'.tmp', '.temp', '.log', '.dmp', '.etl', '.mdmp',
                   '.hdmp', '.wer', '.gid', '.old', '.bak', '.chk',
                   '.~', '.cache', '.partial', '.opdownload'}

# 可安全删除的特定文件名
SAFE_FILE_NAMES = {
    'thumbs.db', 'desktop.ini', '.ds_store',
    'debug.log', 'error.log', 'trace.log',
}

# 大文件阈值 (100MB)
LARGE_FILE_THRESHOLD = 100 * 1024 * 1024


def format_size(size_bytes):
    """格式化文件大小显示"""
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    if i == 0:
        return f"{int(size)} {units[i]}"
    return f"{size:.2f} {units[i]}"


def is_junction(path):
    """检查路径是否为NTFS连接点/重解析点"""
    try:
        # 检查FILE_ATTRIBUTE_REPARSE_POINT属性
        attrs = os.stat(path).st_file_attributes
        return bool(stat.FILE_ATTRIBUTE_REPARSE_POINT & attrs)
    except (OSError, AttributeError):
        return False


def is_protected_path(path):
    """检查路径是否为系统保护路径"""
    path_lower = path.lower().replace('/', '\\')
    for pp in PROTECTED_PATHS:
        pp_lower = pp.lower()
        if path_lower == pp_lower or path_lower.startswith(pp_lower + '\\'):
            return True
    return False


def safe_to_scan(path):
    """判断路径是否可以安全扫描"""
    try:
        path_lower = path.lower().replace('/', '\\')

        # 跳过系统关键目录的内部
        for sys_dir in SYSTEM_CRITICAL_DIRS:
            sys_dir_lower = sys_dir.lower()
            if sys_dir_lower in path_lower.split('\\'):
                # 检查是否是确切的关键目录
                parts = path_lower.split('\\')
                for i, part in enumerate(parts):
                    if part == sys_dir_lower:
                        # 允许扫描ProgramData下的非Microsoft目录
                        if sys_dir_lower == 'programdata':
                            if i + 1 < len(parts) and parts[i + 1] == 'microsoft':
                                return False
                            return True
                        return False
        return True
    except:
        return False


def categorize_file(file_path):
    """
    将文件分类：
    - 'system': 系统文件，不能删除
    - 'safe': 可安全删除
    - 'caution': 可能影响使用，需确认
    - 'normal': 普通文件
    """
    path_lower = file_path.lower().replace('/', '\\')
    file_name = os.path.basename(file_path).lower()
    ext = os.path.splitext(file_path)[1].lower()

    # 检查系统保护路径
    if is_protected_path(file_path):
        return 'system'

    # 检查安全清理路径
    for safe_pattern in SAFE_CLEAN_PATTERNS:
        safe_lower = safe_pattern.lower()
        if path_lower.startswith(safe_lower):
            return 'safe'

    # 检查用户临时文件
    for temp_pattern in USER_TEMP_PATTERNS:
        temp_lower = temp_pattern.lower()
        if temp_lower in path_lower:
            return 'safe'

    # 检查谨慎清理路径
    for caution_pattern in CAUTION_PATTERNS:
        caution_lower = caution_pattern.lower()
        if caution_lower in path_lower:
            return 'caution'

    # 检查临时扩展名
    if ext in TEMP_EXTENSIONS:
        return 'safe'

    # 检查安全文件名
    if file_name in SAFE_FILE_NAMES:
        return 'safe'

    # 检查文件夹类型
    if os.path.isdir(file_path):
        dir_name = os.path.basename(file_path).lower()
        if dir_name in {'temp', 'tmp', 'cache', 'caches', 'logs', 'log'}:
            return 'safe'
        if dir_name in {'downloads', 'download', 'downloadeded'}:
            return 'caution'

    return 'normal'


def get_dir_size_scandir(path, max_depth=10, current_depth=0):
    """
    使用os.scandir快速计算目录大小
    返回 (size, file_count, error_count)
    """
    total_size = 0
    file_count = 0
    error_count = 0

    if current_depth > max_depth:
        return 0, 0, 0

    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total_size += entry.stat().st_size
                        file_count += 1
                    elif entry.is_dir(follow_symlinks=False):
                        # 跳过连接点
                        try:
                            if entry.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                                continue
                        except:
                            pass

                        sub_size, sub_files, sub_errors = get_dir_size_scandir(
                            entry.path, max_depth, current_depth + 1)
                        total_size += sub_size
                        file_count += sub_files
                        error_count += sub_errors
                except OSError:
                    error_count += 1
                    continue
    except (PermissionError, OSError):
        error_count += 1

    return total_size, file_count, error_count


def get_top_level_items(path):
    """获取目录下的顶级文件和文件夹"""
    items = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    info = {
                        'name': entry.name,
                        'path': entry.path,
                        'size': 0,
                        'is_dir': entry.is_dir(follow_symlinks=False),
                        'file_count': 0,
                    }

                    if entry.is_file(follow_symlinks=False):
                        info['size'] = entry.stat().st_size
                        info['file_count'] = 1
                    elif entry.is_dir(follow_symlinks=False):
                        # 检查是否是连接点
                        try:
                            if entry.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                                info['is_junction'] = True
                                info['size'] = 0
                            else:
                                info['size'], info['file_count'], _ = get_dir_size_scandir(entry.path)
                        except:
                            info['size'] = 0

                    info['category'] = categorize_file(entry.path)
                    items.append(info)
                except OSError:
                    continue
    except (PermissionError, OSError):
        pass

    return items


class DiskScanner:
    """磁盘扫描器 - 支持后台线程扫描"""

    def __init__(self):
        self._scan_results = {}
        self._scanning = False
        self._progress = 0
        self._total_dirs = 0
        self._scanned_dirs = 0
        self._lock = threading.Lock()
        self._cancel_event = threading.Event()
        self._scan_thread = None

        # 扫描结果分类
        self.safe_files = []       # 可安全清理
        self.caution_files = []    # 谨慎清理
        self.large_files = []      # 大文件 (>100MB)
        self.all_items = []        # 所有项目

    @property
    def scanning(self):
        return self._scanning

    @property
    def progress(self):
        return self._progress

    def cancel_scan(self):
        """取消扫描"""
        self._cancel_event.set()

    def start_scan(self, scan_paths=None, callback=None):
        """
        开始后台扫描
        scan_paths: 要扫描的路径列表，默认为C盘
        callback: 扫描完成后的回调函数
        """
        if self._scanning:
            return False

        if scan_paths is None:
            scan_paths = ["C:\\"]

        self._cancel_event.clear()
        self._scanning = True
        self._progress = 0

        def scan_worker():
            try:
                results = self._do_scan(scan_paths)
                with self._lock:
                    self._scan_results = results
                    self._scanning = False
                    self._progress = 100
                if callback:
                    callback(results)
            except Exception as e:
                with self._lock:
                    self._scanning = False
                if callback:
                    callback({'error': str(e)})

        self._scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self._scan_thread.start()
        return True

    def _do_scan(self, scan_paths):
        """执行扫描"""
        self.safe_files = []
        self.caution_files = []
        self.large_files = []
        self.all_items = []

        total_paths = len(scan_paths)
        scanned_size = 0

        for path_idx, scan_path in enumerate(scan_paths):
            if self._cancel_event.is_set():
                break

            if not os.path.exists(scan_path):
                continue

            # 获取顶级项目
            items = get_top_level_items(scan_path)
            self.all_items.extend(items)

            # 递归扫描大文件夹
            for item in items:
                if self._cancel_event.is_set():
                    break

                # 分类文件
                category = item.get('category', 'normal')
                item_path = item.get('path', '')
                item_size = item.get('size', 0)

                # 收集可清理文件
                if category == 'safe':
                    self.safe_files.append(item)
                elif category == 'caution':
                    self.caution_files.append(item)

                # 收集大文件
                if item_size > LARGE_FILE_THRESHOLD and not item.get('is_dir'):
                    self.large_files.append(item)

                # 如果是目录且安全可扫描，进一步扫描子目录
                if item.get('is_dir') and safe_to_scan(item_path) and not is_protected_path(item_path):
                    try:
                        sub_items = get_top_level_items(item_path)
                        for sub in sub_items:
                            sub_cat = categorize_file(sub.get('path', ''))
                            sub_size = sub.get('size', 0)

                            if sub_cat == 'safe':
                                self.safe_files.append(sub)
                            elif sub_cat == 'caution':
                                self.caution_files.append(sub)

                            if sub_size > LARGE_FILE_THRESHOLD and not sub.get('is_dir'):
                                self.large_files.append(sub)
                    except:
                        pass

            # 更新进度
            with self._lock:
                self._progress = int((path_idx + 1) / total_paths * 80)

        # 深度扫描用户目录
        users_path = r"C:\Users"
        if os.path.exists(users_path) and not self._cancel_event.is_set():
            try:
                with os.scandir(users_path) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False) and not entry.name.startswith('.'):
                            self._scan_user_directory(entry.path)
            except:
                pass

        # 排序：按大小降序
        self.safe_files.sort(key=lambda x: x.get('size', 0), reverse=True)
        self.caution_files.sort(key=lambda x: x.get('size', 0), reverse=True)
        self.large_files.sort(key=lambda x: x.get('size', 0), reverse=True)

        # 计算总空间
        total_safe_size = sum(f.get('size', 0) for f in self.safe_files)
        total_caution_size = sum(f.get('size', 0) for f in self.caution_files)
        total_large_size = sum(f.get('size', 0) for f in self.large_files)

        # 去重 large_files (已经在safe或caution中)
        safe_paths = {f.get('path') for f in self.safe_files}
        caution_paths = {f.get('path') for f in self.caution_files}
        unique_large = [f for f in self.large_files
                       if f.get('path') not in safe_paths
                       and f.get('path') not in caution_paths]

        return {
            'safe_files': self._serialize_items(self.safe_files),
            'caution_files': self._serialize_items(self.caution_files),
            'large_files': self._serialize_items(unique_large),
            'all_items': self._serialize_items(self.all_items[:100]),  # 限制顶级项目
            'summary': {
                'safe_count': len(self.safe_files),
                'safe_size': total_safe_size,
                'safe_size_formatted': format_size(total_safe_size),
                'caution_count': len(self.caution_files),
                'caution_size': total_caution_size,
                'caution_size_formatted': format_size(total_caution_size),
                'large_count': len(unique_large),
                'large_size': total_large_size,
                'large_size_formatted': format_size(total_large_size),
                'total_cleanable': total_safe_size + total_caution_size,
                'total_cleanable_formatted': format_size(total_safe_size + total_caution_size),
            }
        }

    def _scan_user_directory(self, user_path):
        """扫描单个用户目录"""
        if self._cancel_event.is_set():
            return

        try:
            # 扫描AppData\Local\Temp
            temp_path = os.path.join(user_path, 'AppData', 'Local', 'Temp')
            if os.path.exists(temp_path):
                temp_items = get_top_level_items(temp_path)
                for item in temp_items:
                    item['category'] = 'safe'
                    self.safe_files.append(item)

            # 扫描AppData\Roaming下的cache
            roaming = os.path.join(user_path, 'AppData', 'Roaming')
            if os.path.exists(roaming):
                try:
                    with os.scandir(roaming) as it:
                        for entry in it:
                            if entry.is_dir(follow_symlinks=False):
                                cache_path = os.path.join(entry.path, 'Cache')
                                if os.path.exists(cache_path):
                                    cache_items = get_top_level_items(cache_path)
                                    for item in cache_items:
                                        item['category'] = 'caution'
                                        self.caution_files.append(item)

                                codedata_path = os.path.join(entry.path, 'Code', 'CachedData')
                                if os.path.exists(codedata_path):
                                    code_items = get_top_level_items(codedata_path)
                                    for item in code_items:
                                        item['category'] = 'caution'
                                        self.caution_files.append(item)
                except:
                    pass

            # 扫描AppData\Local下的cache
            local = os.path.join(user_path, 'AppData', 'Local')
            if os.path.exists(local):
                try:
                    with os.scandir(local) as it:
                        for entry in it:
                            if entry.is_dir(follow_symlinks=False):
                                cache_path = os.path.join(entry.path, 'Cache')
                                if os.path.exists(cache_path):
                                    cache_items = get_top_level_items(cache_path)
                                    for item in cache_items:
                                        item['category'] = 'caution'
                                        self.caution_files.append(item)
                except:
                    pass

            # 扫描Downloads文件夹
            downloads = os.path.join(user_path, 'Downloads')
            if os.path.exists(downloads):
                dl_items = get_top_level_items(downloads)
                for item in dl_items:
                    if item.get('size', 0) > 50 * 1024 * 1024:  # >50MB
                        item['category'] = 'caution'
                        self.caution_files.append(item)

        except:
            pass

    def _serialize_items(self, items):
        """序列化项目列表"""
        result = []
        seen_paths = set()
        for item in items:
            path = item.get('path', '')
            if path in seen_paths:
                continue
            seen_paths.add(path)
            result.append({
                'name': item.get('name', ''),
                'path': path,
                'size': item.get('size', 0),
                'size_formatted': format_size(item.get('size', 0)),
                'is_dir': item.get('is_dir', False),
                'category': item.get('category', 'normal'),
                'file_count': item.get('file_count', 0),
            })
        return result

    def get_results(self):
        """获取扫描结果"""
        with self._lock:
            if not self._scan_results:
                return {'status': 'not_scanned'}
            return {
                'status': 'completed' if not self._scanning else 'scanning',
                'progress': self._progress,
                **self._scan_results
            }


# 全局扫描器实例
scanner = DiskScanner()

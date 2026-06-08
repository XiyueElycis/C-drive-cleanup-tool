"""
安全清理模块 - 负责文件分类和删除
严格区分：系统文件(不可删) / 安全清理 / 谨慎清理(可能影响用户使用)
"""
import os
import shutil
import stat
import send2trash
from pathlib import Path
from datetime import datetime


# ============================================================
# 清理操作结果
# ============================================================
class CleanResult:
    def __init__(self):
        self.deleted = []       # 成功删除的文件
        self.failed = []        # 删除失败的文件
        self.skipped = []       # 跳过的文件
        self.total_freed = 0    # 释放的总空间
        self.errors = []        # 错误信息


# ============================================================
# 路径安全检查
# ============================================================
def is_safe_to_delete(file_path):
    """
    检查文件是否可以安全删除
    返回 (safe: bool, reason: str)
    """
    path_lower = file_path.lower().replace('/', '\\')

    # 绝对禁止删除的路径
    FORBIDDEN = [
        r"c:\windows",
        r"c:\windows\system32",
        r"c:\windows\syswow64",
        r"c:\program files",
        r"c:\program files (x86)",
        r"c:\programdata\microsoft",
        r"c:\boot",
        r"c:\efi",
        r"c:\$recycle.bin",
    ]

    # 禁止删除的关键文件
    FORBIDDEN_FILES = [
        'ntoskrnl.exe', 'ntldr', 'bootmgr', 'bootnxt',
        'pagefile.sys', 'hiberfil.sys', 'swapfile.sys',
        'sam', 'security', 'software', 'system', 'default',
        'ntuser.dat', 'ntuser.ini', 'usrc.log', 'usrclass.dat',
    ]

    # 检查禁止路径
    for forbidden in FORBIDDEN:
        if path_lower == forbidden or path_lower.startswith(forbidden + '\\'):
            return False, "系统关键目录，禁止删除"

    # 检查禁止文件名
    file_name = os.path.basename(file_path).lower()
    if file_name in FORBIDDEN_FILES:
        return False, "系统关键文件，禁止删除"

    # 检查是否在Windows目录下（除了Temp/Prefetch/SoftwareDistribution/Logs）
    if path_lower.startswith(r"c:\windows"):
        allowed_under_windows = [
            r"c:\windows\temp",
            r"c:\windows\prefetch",
            r"c:\windows\softwaredistribution\download",
            r"c:\windows\logs",
            r"c:\windows\cbstemp",
            r"c:\windows\livekernelreports",
            r"c:\windows\minidump",
            r"c:\windows\memory.dmp",
            r"c:\windows\serviceprofiles",
        ]
        is_allowed = any(path_lower.startswith(a) for a in allowed_under_windows)
        if not is_allowed:
            return False, "Windows系统目录下的文件，不建议删除"

    # 检查Program Files
    if path_lower.startswith(r"c:\program files") or path_lower.startswith(r"c:\program files (x86)"):
        return False, "程序安装目录，不建议直接删除文件"

    return True, "OK"


def remove_readonly(func, path, exc_info):
    """处理只读文件的删除"""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def safe_delete_file(file_path):
    """
    安全删除文件（移到回收站）
    返回 (success: bool, size_freed: int, error: str)
    """
    if not os.path.exists(file_path):
        return False, 0, "文件不存在"

    # 安全检查
    safe, reason = is_safe_to_delete(file_path)
    if not safe:
        return False, 0, reason

    original_size = 0
    try:
        if os.path.isfile(file_path):
            original_size = os.path.getsize(file_path)

        # 发送到回收站（可恢复）
        send2trash.send2trash(file_path)

        return True, original_size, ""
    except PermissionError:
        # 尝试修改权限后删除
        try:
            os.chmod(file_path, stat.S_IWRITE)
            send2trash.send2trash(file_path)
            return True, original_size, ""
        except Exception as e:
            return False, 0, f"权限不足: {str(e)}"
    except Exception as e:
        return False, 0, str(e)


def permanent_delete_file(file_path):
    """
    永久删除文件（不可恢复，用于深度清理）
    返回 (success: bool, size_freed: int, error: str)
    """
    if not os.path.exists(file_path):
        return False, 0, "文件不存在"

    safe, reason = is_safe_to_delete(file_path)
    if not safe:
        return False, 0, reason

    original_size = 0
    try:
        if os.path.isfile(file_path):
            original_size = os.path.getsize(file_path)

        if os.path.isfile(file_path):
            os.remove(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path, onerror=remove_readonly)

        return True, original_size, ""
    except Exception as e:
        return False, 0, str(e)


def clean_file_list(file_list, permanent=False):
    """
    清理文件列表
    file_list: [{'path': str, 'name': str, 'size': int}, ...]
    permanent: 是否永久删除
    返回 CleanResult
    """
    result = CleanResult()

    for item in file_list:
        file_path = item.get('path', '')
        file_name = item.get('name', os.path.basename(file_path))

        if not file_path or not os.path.exists(file_path):
            result.skipped.append({
                'name': file_name,
                'path': file_path,
                'reason': '文件不存在'
            })
            continue

        if permanent:
            success, freed, error = permanent_delete_file(file_path)
        else:
            success, freed, error = safe_delete_file(file_path)

        if success:
            result.deleted.append({
                'name': file_name,
                'path': file_path,
                'size': freed
            })
            result.total_freed += freed
        elif error and '禁止' in error or '不建议' in error:
            result.skipped.append({
                'name': file_name,
                'path': file_path,
                'reason': error
            })
        else:
            result.failed.append({
                'name': file_name,
                'path': file_path,
                'reason': error or '未知错误'
            })

    return result


def get_clean_summary(safe_files, caution_files):
    """
    获取清理摘要
    返回格式化的文本信息
    """
    safe_size = sum(f.get('size', 0) for f in safe_files)
    caution_size = sum(f.get('size', 0) for f in caution_files)

    lines = []
    lines.append("=" * 60)
    lines.append("  C盘清理分析报告")
    lines.append("=" * 60)
    lines.append(f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"  🟢 可安全清理: {len(safe_files)} 项, 共 {format_size_simple(safe_size)}")
    lines.append(f"     包括: 临时文件、系统缓存、日志文件、回收站等")
    lines.append(f"     这些文件删除后不影响系统和软件运行")
    lines.append("")
    lines.append(f"  🟡 谨慎清理: {len(caution_files)} 项, 共 {format_size_simple(caution_size)}")
    lines.append(f"     包括: 浏览器缓存、下载文件夹大文件、应用缓存等")
    lines.append(f"     删除后可能影响部分应用的使用体验，但不影响系统运行")
    lines.append("")
    lines.append(f"  🔴 系统文件: 已自动排除，不会被删除")
    lines.append(f"     包括: Windows系统文件、Program Files等")
    lines.append("")
    lines.append(f"  💾 最大可释放空间: {format_size_simple(safe_size + caution_size)}")
    lines.append("=" * 60)

    return "\n".join(lines)


def format_size_simple(size_bytes):
    """简单的大小格式化"""
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

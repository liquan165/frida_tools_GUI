# frida_tools_gui.py
# pip install PySide6
# python frida_tools_gui.py

import os
import re
import sys
import glob
import shlex
import subprocess
from dataclasses import dataclass

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QPlainTextEdit, QGroupBox, QListWidget, QListWidgetItem,
    QRadioButton, QMessageBox, QSplitter, QComboBox, QFileDialog, QMenu
)

TOOL_DIR = "/data/local/tmp/hacktools"
DEFAULT_JS_DIR = r"D:\hacktools\Mobile\fridatools"


def run_cmd(cmd, timeout=60, check=False):
    p = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, shell=False
    )
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr


def run_adb(args, timeout=60):
    return run_cmd(["adb"] + args, timeout=timeout)


def run_adb_shell(shell_cmd, timeout=60):
    return run_adb(["shell", shell_cmd], timeout=timeout)


def su_c(cmd):
    safe = cmd.replace("'", r"'\''")
    return f"su -c '{safe}'"


def parse_adb_devices(output: str):
    cnt = 0
    lines = output.splitlines()
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 2 and parts[1] == "device":
            cnt += 1
    return cnt


@dataclass
class AppState:
    selected_package: str = ""
    selected_js: str = ""
    js_dir: str = DEFAULT_JS_DIR


class Worker(QThread):
    """Task signature: task(log)"""
    log = Signal(str)
    done = Signal(bool, str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            def logger(msg: str):
                self.log.emit(str(msg))
            self.fn(logger)
            self.done.emit(True, "OK")
        except Exception as e:
            self.done.emit(False, str(e))


class FridaRunner(QThread):
    """
    Run frida in background, stream output, allow stop/kill.
    """
    log = Signal(str)
    started_ok = Signal()
    finished_ok = Signal(int)

    def __init__(self, cmd_list):
        super().__init__()
        self.cmd_list = cmd_list
        self.proc = None

    def run(self):
        try:
            creationflags = 0
            if os.name == "nt":
                # Needed to send CTRL_BREAK_EVENT
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

            self.log.emit("启动 Frida: " + " ".join(shlex.quote(x) for x in self.cmd_list))
            self.proc = subprocess.Popen(
                self.cmd_list,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags
            )
            self.started_ok.emit()

            if self.proc.stdout:
                for line in self.proc.stdout:
                    self.log.emit(line.rstrip("\n"))

            code = self.proc.wait()
            self.finished_ok.emit(code)
        except Exception as e:
            self.log.emit(f"[FridaRunner异常] {e}")
            self.finished_ok.emit(-1)

    def send_ctrl_c(self):
        """
        Try graceful stop.
        Windows: send CTRL_BREAK_EVENT to process group.
        Others: SIGINT.
        """
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            if os.name == "nt":
                # More reliable than CTRL_C_EVENT in many cases
                self.proc.send_signal(subprocess.signal.CTRL_BREAK_EVENT)  # type: ignore
            else:
                self.proc.send_signal(subprocess.signal.SIGINT)  # type: ignore
        except Exception:
            # fallback terminate
            try:
                self.proc.terminate()
            except Exception:
                pass

    def kill_now(self):
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            self.proc.kill()
        except Exception:
            pass

    def write_stdin_line(self, s: str):
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.write(s + "\n")
                self.proc.stdin.flush()
        except Exception:
            pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Frida Tools GUI")
        self.resize(1020, 680)

        self.state = AppState()
        self._worker = None
        self._frida_exec_list = []
        self.frida_runner: FridaRunner | None = None

        root = QWidget()
        self.setCentralWidget(root)

        main = QVBoxLayout(root)
        main.setContentsMargins(12, 12, 12, 12)
        main.setSpacing(10)

        title = QLabel("Frida Tools (GUI)")
        f = QFont()
        f.setPointSize(14)
        f.setBold(True)
        title.setFont(f)
        main.addWidget(title)

        splitter = QSplitter(Qt.Horizontal)
        main.addWidget(splitter, 1)

        # Left panel
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setSpacing(10)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Device / server group
        gb_device = QGroupBox("设备 / Frida-Server")
        v_dev = QVBoxLayout(gb_device)

        self.btn_check = QPushButton("1) 检查ADB与设备")
        self.btn_scan_start = QPushButton(f"2) 扫描并启动 {TOOL_DIR}/frida*")
        self.btn_scan_start.setEnabled(False)

        v_dev.addWidget(self.btn_check)
        v_dev.addWidget(self.btn_scan_start)

        # Package search group
        gb_pkg = QGroupBox("包名选择")
        v_pkg = QVBoxLayout(gb_pkg)

        row_kw = QHBoxLayout()
        self.ed_keyword = QLineEdit()
        self.ed_keyword.setPlaceholderText("输入关键词，例如: wechat / com.xxx ...")
        self.btn_search_pkg = QPushButton("3) 搜索包名")
        self.btn_search_pkg.setEnabled(False)
        row_kw.addWidget(self.ed_keyword, 1)
        row_kw.addWidget(self.btn_search_pkg)
        v_pkg.addLayout(row_kw)

        self.list_pkgs = QListWidget()
        self.list_pkgs.setMinimumHeight(150)
        self.list_pkgs.setEnabled(False)
        v_pkg.addWidget(self.list_pkgs)

        row_custom = QHBoxLayout()
        self.ed_custom_pkg = QLineEdit()
        self.ed_custom_pkg.setPlaceholderText("或在这里自定义输入完整包名（优先级更高）")
        self.btn_use_custom = QPushButton("使用自定义包名")
        self.btn_use_custom.setEnabled(False)
        row_custom.addWidget(self.ed_custom_pkg, 1)
        row_custom.addWidget(self.btn_use_custom)
        v_pkg.addLayout(row_custom)

        self.lbl_selected_pkg = QLabel("已选择包名：<未选择>")
        v_pkg.addWidget(self.lbl_selected_pkg)

        # Mode + JS group
        gb_run = QGroupBox("运行模式 / JS脚本")
        v_run = QVBoxLayout(gb_run)

        row_mode = QHBoxLayout()
        self.rb_spawn = QRadioButton("Spawn（重启应用）")
        self.rb_attach = QRadioButton("Attach（附加到运行中进程）")
        self.rb_spawn.setChecked(True)
        self.rb_spawn.setEnabled(False)
        self.rb_attach.setEnabled(False)
        row_mode.addWidget(self.rb_spawn)
        row_mode.addWidget(self.rb_attach)
        row_mode.addStretch(1)
        v_run.addLayout(row_mode)

        # JS 目录选择
        row_js_dir = QHBoxLayout()
        lbl_js_dir = QLabel("JS目录:")
        self.ed_js_dir = QLineEdit()
        self.ed_js_dir.setText(DEFAULT_JS_DIR)
        self.ed_js_dir.setEnabled(False)
        self.btn_browse_dir = QPushButton("浏览...")
        self.btn_browse_dir.setEnabled(False)
        row_js_dir.addWidget(lbl_js_dir)
        row_js_dir.addWidget(self.ed_js_dir, 1)
        row_js_dir.addWidget(self.btn_browse_dir)
        v_run.addLayout(row_js_dir)

        # JS 文件选择
        row_js = QHBoxLayout()
        self.cb_js = QComboBox()
        self.cb_js.setEnabled(False)
        self.btn_refresh_js = QPushButton("刷新JS列表")
        self.btn_refresh_js.setEnabled(False)
        row_js.addWidget(self.cb_js, 1)
        row_js.addWidget(self.btn_refresh_js)
        v_run.addLayout(row_js)

        self.btn_run = QPushButton("4) 执行 Frida")
        self.btn_run.setEnabled(False)
        v_run.addWidget(self.btn_run)

        row_stop = QHBoxLayout()
        self.btn_stop = QPushButton("停止 Frida（Ctrl+C）")
        self.btn_kill = QPushButton("强制结束 Frida（Kill）")
        self.btn_stop.setEnabled(False)
        self.btn_kill.setEnabled(False)
        row_stop.addWidget(self.btn_stop)
        row_stop.addWidget(self.btn_kill)
        v_run.addLayout(row_stop)

        left_layout.addWidget(gb_device)
        left_layout.addWidget(gb_pkg)
        left_layout.addWidget(gb_run)
        left_layout.addStretch(1)

        # Right panel: logs + input
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setSpacing(10)
        right_layout.setContentsMargins(0, 0, 0, 0)

        gb_log = QGroupBox("输出 / 日志")
        v_log = QVBoxLayout(gb_log)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_view.customContextMenuRequested.connect(self.show_log_context_menu)
        v_log.addWidget(self.log_view)

        # simple input line (best-effort for frida interactive input)
        row_in = QHBoxLayout()
        self.ed_stdin = QLineEdit()
        self.ed_stdin.setPlaceholderText("（可选）向 frida stdin 发送一行文本后回车")
        self.btn_send = QPushButton("发送")
        self.ed_stdin.setEnabled(False)
        self.btn_send.setEnabled(False)
        row_in.addWidget(self.ed_stdin, 1)
        row_in.addWidget(self.btn_send)
        v_log.addLayout(row_in)

        right_layout.addWidget(gb_log, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([430, 590])

        # Signals
        self.btn_check.clicked.connect(self.on_check)
        self.btn_scan_start.clicked.connect(self.on_scan_start)
        self.btn_search_pkg.clicked.connect(self.on_search_pkg)
        self.list_pkgs.itemSelectionChanged.connect(self.on_pkg_selected)
        self.btn_use_custom.clicked.connect(self.on_use_custom)
        self.btn_refresh_js.clicked.connect(self.refresh_js_list)
        self.btn_browse_dir.clicked.connect(self.on_browse_js_dir)
        self.btn_run.clicked.connect(self.on_run)

        self.btn_stop.clicked.connect(self.on_stop_frida)
        self.btn_kill.clicked.connect(self.on_kill_frida)
        self.btn_send.clicked.connect(self.on_send_stdin)
        self.ed_stdin.returnPressed.connect(self.on_send_stdin)

        self.refresh_js_list()

    def append_log(self, s: str):
        self.log_view.appendPlainText(s.rstrip("\n"))

    def error_box(self, title, msg):
        QMessageBox.critical(self, title, msg)

    def set_busy(self, busy: bool):
        # Disable everything while worker tasks run (except stop/kill handled separately)
        self.btn_check.setEnabled(not busy)
        if busy:
            self.btn_scan_start.setEnabled(False)
            self.btn_search_pkg.setEnabled(False)
            self.list_pkgs.setEnabled(False)
            self.btn_refresh_js.setEnabled(False)
            self.btn_browse_dir.setEnabled(False)
            self.ed_js_dir.setEnabled(False)
            self.cb_js.setEnabled(False)
            self.btn_use_custom.setEnabled(False)
            self.ed_keyword.setEnabled(False)
            self.ed_custom_pkg.setEnabled(False)
            self.rb_spawn.setEnabled(False)
            self.rb_attach.setEnabled(False)
            self.btn_run.setEnabled(False)

    def restore_stage_controls(self):
        self.btn_check.setEnabled(True)
        self.btn_scan_start.setEnabled(True)
        self.btn_search_pkg.setEnabled(True)
        self.list_pkgs.setEnabled(True)
        self.btn_refresh_js.setEnabled(True)
        self.btn_browse_dir.setEnabled(True)
        self.ed_js_dir.setEnabled(True)
        self.cb_js.setEnabled(True)
        self.btn_use_custom.setEnabled(True)
        self.ed_keyword.setEnabled(True)
        self.ed_custom_pkg.setEnabled(True)
        self.rb_spawn.setEnabled(True)
        self.rb_attach.setEnabled(True)
        self.update_run_button()

    def run_worker(self, task_fn, after_ok=None):
        self.set_busy(True)
        self.append_log("---- 正在执行，请稍候 ----")
        w = Worker(task_fn)
        w.log.connect(self.append_log)

        def done(ok, msg):
            self.set_busy(False)
            if not ok:
                self.append_log(f"[失败] {msg}")
                self.error_box("执行失败", msg)
                return
            if after_ok:
                after_ok()

        w.done.connect(done)
        w.start()
        self._worker = w

    # Step 1
    def on_check(self):
        def task(log):
            log("检查 ADB ...")
            code, _, _ = run_adb(["version"], timeout=10)
            if code != 0:
                raise RuntimeError("错误: ADB未就绪；请确认Android SDK环境变量配置正确")

            log("检测设备 ...")
            code, out, err = run_adb(["devices"], timeout=10)
            if code != 0:
                raise RuntimeError(f"adb devices 失败: {err.strip()}")

            log(out.strip())
            device_count = parse_adb_devices(out)
            if device_count == 0:
                raise RuntimeError("未检测到有效设备连接")
            if device_count > 1:
                raise RuntimeError(f"检测到 {device_count} 个设备, 请断开多余设备")

            log(f"检查手机路径: {TOOL_DIR}")
            code, out, _ = run_adb_shell(su_c(f"[ -d {TOOL_DIR} ] && echo Exist"), timeout=20)
            if code != 0 or "Exist" not in out:
                raise RuntimeError(f"[路径错误] 目录不存在: {TOOL_DIR}\n请检查设备文件系统结构")
            log("设备与路径检查通过")

        self.run_worker(task, after_ok=self.restore_stage_controls)

    # Step 2
    def on_scan_start(self):
        def task(log):
            log("正在扫描目标工具 ...")
            code, out, _ = run_adb_shell(su_c(f"ls {TOOL_DIR}/frida* 2>/dev/null"), timeout=30)
            files = [line.strip() for line in out.splitlines() if line.strip()]
            if code != 0 or not files:
                raise RuntimeError("[警告] 未找到frida开头的可执行文件")
            log("发现以下可执行文件:")
            for f in files:
                log(f"  {f}")
            self._frida_exec_list = files

        def after_ok():
            files = self._frida_exec_list[:]
            ret = QMessageBox.question(
                self, "确认执行", "是否执行上述程序并后台启动？",
                QMessageBox.Yes | QMessageBox.No
            )
            if ret != QMessageBox.Yes:
                self.append_log("操作已取消")
                self.restore_stage_controls()
                return

            def task2(log):
                for f in files:
                    log(f"正在执行: {f}")
                    cmd = su_c(f"chmod 777 {f} && {f} &")
                    code, _, err = run_adb_shell(cmd, timeout=30)
                    if code != 0 and err.strip():
                        log(f"[警告] 启动可能失败: {f}\n{err.strip()}")
                log("================================")
                log("Frida-Server 已启动（已尝试启动）")
                log("================================")

            self.run_worker(task2, after_ok=self.restore_stage_controls)

        self.run_worker(task, after_ok=after_ok)

    # Step 3
    def on_search_pkg(self):
        keyword = self.ed_keyword.text().strip()
        if not keyword:
            self.error_box("错误", "未输入关键词")
            return

        def task(log):
            log("adb shell setenforce 0")
            run_adb_shell("setenforce 0", timeout=10)

            log(f"正在检索包含 [{keyword}] 的包名 ...")
            code, out, err = run_adb_shell("pm list packages", timeout=40)
            if code != 0:
                raise RuntimeError(f"pm list packages 失败: {err.strip()}")

            matches = [line.strip() for line in out.splitlines() if keyword.lower() in line.lower()]
            if not matches:
                raise RuntimeError("未找到包含该关键词的包名")
            self._pkg_matches = matches

        def after_ok():
            self.list_pkgs.clear()
            for line in getattr(self, "_pkg_matches", []):
                self.list_pkgs.addItem(QListWidgetItem(line))
            self.append_log(f"共找到 {self.list_pkgs.count()} 个匹配的包名（点击选择）")
            self.restore_stage_controls()

        self.run_worker(task, after_ok=after_ok)

    def on_pkg_selected(self):
        items = self.list_pkgs.selectedItems()
        if not items:
            return
        raw = items[0].text().strip()
        pkg = raw.replace("package:", "", 1).strip()
        self.state.selected_package = pkg
        self.lbl_selected_pkg.setText(f"已选择包名：{pkg}")
        self.update_run_button()

    def on_use_custom(self):
        pkg = self.ed_custom_pkg.text().strip()
        if not pkg:
            self.error_box("错误", "未输入包名")
            return
        self.state.selected_package = pkg
        self.lbl_selected_pkg.setText(f"已选择包名：{pkg}（自定义）")
        self.update_run_button()

    def refresh_js_list(self):
        js_dir = self.ed_js_dir.text().strip()
        if not js_dir or not os.path.exists(js_dir):
            self.append_log(f"[!] JS目录不存在: {js_dir}")
            return
        
        self.state.js_dir = js_dir
        pattern = os.path.join(js_dir, "*.js")
        js_files = sorted(glob.glob(pattern))
        
        self.cb_js.clear()
        for f in js_files:
            self.cb_js.addItem(f)
        
        if js_files:
            self.state.selected_js = js_files[0]
            self.append_log(f"[*] 找到 {len(js_files)} 个JS文件")
        else:
            self.state.selected_js = ""
            self.append_log(f"[!] 在 {js_dir} 中未找到JS文件")
        
        self.update_run_button()
    
    def on_browse_js_dir(self):
        """浏览并选择 JS 脚本目录"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "选择 JS 脚本目录",
            self.ed_js_dir.text() or DEFAULT_JS_DIR
        )
        if dir_path:
            self.ed_js_dir.setText(dir_path)
            self.state.js_dir = dir_path
            self.append_log(f"[*] 已选择目录: {dir_path}")
            self.refresh_js_list()

    def update_run_button(self):
        has_pkg = bool(self.state.selected_package.strip())
        js_file = self.cb_js.currentText().strip()
        has_js = self.cb_js.count() > 0 and js_file and os.path.exists(js_file)
        frida_not_running = self.frida_runner is None or (self.frida_runner.proc is None) or (self.frida_runner.proc.poll() is not None)
        self.btn_run.setEnabled(has_pkg and has_js and frida_not_running)

    # Step 4
    def on_run(self):
        pkg = self.state.selected_package.strip()
        if not pkg:
            self.error_box("错误", "未选择包名")
            return

        js_file = self.cb_js.currentText().strip()
        if not js_file or not os.path.exists(js_file):
            self.error_box("错误", f"未选择有效的JS文件\n路径: {js_file}")
            return
        
        # 修复路径分隔符问题：Windows 反斜杠转为正斜杠
        js_file_normalized = js_file.replace('\\', '/')

        # 保存 attach_mode 到实例变量，避免作用域问题
        self._current_attach_mode = self.rb_attach.isChecked()
        self._current_pkg = pkg
        self._current_js_file = js_file
        self._current_js_file_normalized = js_file_normalized

        def task(log):
            log("adb forward tcp:27042 tcp:27042")
            run_adb(["forward", "tcp:27042", "tcp:27042"], timeout=10)

            log("清理 /data/local/tmp/hook/ ...")
            run_adb_shell(su_c("rm -rf /data/local/tmp/hook/"), timeout=20)

            log("================================")
            log(f"目标包名: {self._current_pkg}")
            log(f"使用脚本: {self._current_js_file}")
            log(f"标准化路径: {self._current_js_file_normalized}")
            log(f"运行模式: {'Attach' if self._current_attach_mode else 'Spawn'}")
            log("================================")

            if self._current_attach_mode:
                log("正在检查进程是否运行 ...")
                _, out, _ = run_adb_shell(f"ps | grep {shlex.quote(self._current_pkg)} | grep -v grep", timeout=20)
                if out.strip() == "":
                    log("[警告] 目标进程未运行，尝试启动应用 ...")
                    run_adb_shell(f"monkey -p {shlex.quote(self._current_pkg)} 1", timeout=20)
                    log("等待应用启动 3 秒 ...")
                    import time
                    time.sleep(3)

        def after_ok():
            # 在最开始就输出日志，确保函数被执行
            self.append_log("[DEBUG] after_ok() 函数开始执行")
            self.append_log(f"[DEBUG] sys.executable = {sys.executable}")
            
            # 修复：使用 python -m 方式调用 frida，解决 maye 启动时的环境变量问题
            import shutil
            
            self.append_log("[DEBUG] 开始查找 frida 路径...")
            
            # 尝试查找 frida 完整路径
            frida_path = shutil.which("frida")
            
            self.append_log(f"[DEBUG] shutil.which('frida') 返回: {frida_path}")
            
            if frida_path:
                # 如果找到了 frida，使用完整路径
                frida_cmd = [frida_path]
                self.append_log(f"[调试] 使用 Frida 路径: {frida_path}")
            else:
                # 使用 python -m 方式（更稳定，推荐）
                frida_cmd = [sys.executable, "-m", "frida_tools.cli"]
                self.append_log(f"[调试] 使用 Python 模块: {sys.executable} -m frida_tools.cli")
            
            self.append_log(f"[DEBUG] 最终命令列表: {frida_cmd}")
            
            # Start frida runner (non-blocking)
            # 使用实例变量，避免作用域问题
            if self._current_attach_mode:
                cmd = frida_cmd + ["-U", self._current_pkg, "-l", self._current_js_file_normalized]
            else:
                cmd = frida_cmd + ["-U", "-l", self._current_js_file_normalized, "-f", self._current_pkg]
            
            self.append_log(f"[DEBUG] 完整命令: {cmd}")

            self.start_frida(cmd)

        self.run_worker(task, after_ok=after_ok)

    def start_frida(self, cmd):
        # prevent double start
        if self.frida_runner and self.frida_runner.proc and self.frida_runner.proc.poll() is None:
            self.append_log("[提示] Frida 正在运行，先停止再启动。")
            return

        self.frida_runner = FridaRunner(cmd)
        self.frida_runner.log.connect(self.append_log)

        def on_started():
            self.append_log("[Frida] 已启动，可点击停止/强制结束。")
            self.btn_stop.setEnabled(True)
            self.btn_kill.setEnabled(True)
            self.ed_stdin.setEnabled(True)
            self.btn_send.setEnabled(True)
            self.btn_run.setEnabled(False)

        def on_finished(code):
            self.append_log(f"[Frida] 进程已退出，exit code={code}")
            self.btn_stop.setEnabled(False)
            self.btn_kill.setEnabled(False)
            self.ed_stdin.setEnabled(False)
            self.btn_send.setEnabled(False)
            self.restore_stage_controls()
            self.update_run_button()

        self.frida_runner.started_ok.connect(on_started)
        self.frida_runner.finished_ok.connect(on_finished)
        self.frida_runner.start()

    def on_stop_frida(self):
        if not self.frida_runner:
            return
        self.append_log("[操作] 发送 Ctrl+C / Ctrl+Break 停止 Frida ...")
        self.frida_runner.send_ctrl_c()

    def on_kill_frida(self):
        if not self.frida_runner:
            return
        self.append_log("[操作] 强制结束 Frida ...")
        self.frida_runner.kill_now()

    def on_send_stdin(self):
        s = self.ed_stdin.text()
        if not s.strip():
            return
        if not self.frida_runner:
            return
        self.frida_runner.write_stdin_line(s)
        self.ed_stdin.clear()

    def show_log_context_menu(self, pos):
        """显示日志区域的右键菜单"""
        menu = QMenu(self)
        
        # 清空日志动作
        clear_action = QAction("清空日志", self)
        clear_action.triggered.connect(self.clear_log)
        menu.addAction(clear_action)
        
        # 复制选中文本动作
        copy_action = QAction("复制", self)
        copy_action.triggered.connect(self.log_view.copy)
        copy_action.setEnabled(self.log_view.textCursor().hasSelection())
        menu.addAction(copy_action)
        
        # 全选动作
        select_all_action = QAction("全选", self)
        select_all_action.triggered.connect(self.log_view.selectAll)
        menu.addAction(select_all_action)
        
        # 分隔符
        menu.addSeparator()
        
        # 导出日志动作
        export_action = QAction("导出日志到文件...", self)
        export_action.triggered.connect(self.export_log)
        menu.addAction(export_action)
        
        # 在鼠标位置显示菜单
        menu.exec(self.log_view.mapToGlobal(pos))
    
    def clear_log(self):
        """清空日志"""
        reply = QMessageBox.question(
            self,
            "确认清空",
            "确定要清空所有日志吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.log_view.clear()
            self.append_log("[*] 日志已清空")
    
    def export_log(self):
        """导出日志到文件"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出日志",
            "frida_log.txt",
            "Text Files (*.txt);;Log Files (*.log);;All Files (*.*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.log_view.toPlainText())
                self.append_log(f"[+] 日志已导出到: {file_path}")
                QMessageBox.information(self, "导出成功", f"日志已保存到:\n{file_path}")
            except Exception as e:
                self.error_box("导出失败", f"无法保存日志文件:\n{str(e)}")


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

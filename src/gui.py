#!/usr/bin/env python3
"""
服务器架构与服务分析工具 - 图形界面 v3.1
集成所有v2.0分析模块，支持文件架构解析
"""

import sys
import os
from pathlib import Path
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.service_config import ServiceConfigAnalyzer
from modules.network import NetworkAnalyzer
from modules.ip_analysis import IPAnalyzer
from modules.server_role import ServerRoleIdentifier
from modules.reporter import ReportGenerator
from modules.flowchart import generate_architecture_flowchart
from modules.utils import safe_execute
from modules.file_structure_analyzer import FileStructureAnalyzer
from modules.web_proxy_analyzer import WebProxyAnalyzer
from modules.access_log_analyzer import AccessLogAnalyzer
from modules.backend_service_discovery import BackendServiceDiscovery
from modules.ssh_security_analyzer import SSHSecurityAnalyzer
from modules.startup_analyzer import StartupAnalyzer
from modules.log_file_analyzer import LogFileAnalyzer
from modules.database_detector import DatabaseDetector
from modules.outbound_tracker import OutboundConnectionTracker as OutboundTracker
from modules.timeline_analyzer import TimelineAnalyzer
from modules.correlation_engine import CorrelationEngine


class ModernPalette:
    """现代配色方案"""
    PRIMARY = "#1E88E5"
    PRIMARY_LIGHT = "#64B5F6"
    PRIMARY_DARK = "#1565C0"
    WHITE = "#FFFFFF"
    LIGHT_BG = "#F5F7FA"
    CARD_BG = "#FFFFFF"
    TEXT_DARK = "#2C3E50"
    TEXT_MEDIUM = "#546E7A"
    TEXT_LIGHT = "#78909C"
    SUCCESS = "#43A047"
    WARNING = "#FB8C00"
    ERROR = "#E53935"
    INFO = "#039BE5"
    BORDER_LIGHT = "#E0E7EC"


class QuickFileScanner:
    """快速文件扫描器（带超时）"""
    
    def __init__(self, target_dir, max_depth=5, max_files=5000):
        self.target_dir = Path(target_dir)
        self.max_depth = max_depth
        self.max_files = max_files
        self.stats = {}
    
    def scan_quickly(self, timeout=10) -> dict:
        """快速扫描目录，获取统计信息"""
        start_time = time.time()
        
        stats = {
            'total_files': 0,
            'total_dirs': 0,
            'total_size': 0,
            'file_types': {},
            'important_dirs': [],
            'complexity': 'low'
        }
        
        try:
            for root, dirs, files in os.walk(self.target_dir):
                if time.time() - start_time > timeout:
                    stats['timeout'] = True
                    break
                
                try:
                    rel_path = Path(root).relative_to(self.target_dir)
                    depth = len(rel_path.parts)
                    if depth > self.max_depth:
                        dirs.clear()
                        continue
                except ValueError:
                    continue
                
                stats['total_dirs'] += len(dirs)
                
                for file in files:
                    if stats['total_files'] >= self.max_files:
                        break
                    
                    stats['total_files'] += 1
                    file_path = Path(root) / file
                    
                    try:
                        size = file_path.stat().st_size
                        stats['total_size'] += size
                    except:
                        pass
                    
                    ext = file_path.suffix.lower()
                    if ext:
                        stats['file_types'][ext] = stats['file_types'].get(ext, 0) + 1
                    
                    # 标记重要目录
                    if any(kw in file.lower() for kw in ['nginx', 'apache', 'apache2', 'httpd', 
                        'mysql', 'postgres', 'redis', 'mongo', 'ssh', 'cron', 'systemd']):
                        if str(rel_path) not in stats['important_dirs']:
                            stats['important_dirs'].append(str(rel_path))
                
                if stats['total_files'] >= self.max_files:
                    break
        except Exception as e:
            stats['error'] = str(e)
        
        stats['size_mb'] = stats['total_size'] / (1024 * 1024)
        
        if stats['size_mb'] > 500:
            stats['complexity'] = 'very_high'
        elif stats['size_mb'] > 100:
            stats['complexity'] = 'high'
        elif stats['size_mb'] > 10:
            stats['complexity'] = 'medium'
        else:
            stats['complexity'] = 'low'
        
        stats['scan_time'] = time.time() - start_time
        
        return stats


class ServerAnalyzerGUI:
    """服务器分析工具GUI v3.0"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Server Forensic Analyzer v3.0")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)
        self.root.configure(bg=ModernPalette.LIGHT_BG)
        
        self.analysis_running = False
        self.timeout_var = tk.IntVar(value=60)
        self.auto_timeout_var = tk.BooleanVar(value=True)
        self.scan_stats = {}
        
        self._setup_ui()
    
    def _create_card(self, parent, padding=15):
        """创建卡片容器"""
        card = tk.Frame(parent, bg=ModernPalette.CARD_BG, relief="flat", bd=0)
        
        shadow = tk.Frame(parent, bg="#D0D5D9", relief="flat", bd=0)
        shadow.place(x=4, y=4, relwidth=1, relheight=1, in_=card)
        card.lift()
        
        inner = tk.Frame(card, bg=ModernPalette.CARD_BG, padx=padding, pady=padding)
        inner.pack(fill="both", expand=True)
        
        return card, inner
    
    def _setup_ui(self):
        """构建用户界面 - 左右分栏布局"""
        # 主容器
        main = tk.Frame(self.root, bg=ModernPalette.LIGHT_BG)
        main.pack(fill="both", expand=True, padx=20, pady=15)
        
        # 左侧区域
        left_frame = tk.Frame(main, bg=ModernPalette.LIGHT_BG)
        left_frame.pack(side="left", fill="both", expand=True)
        
        # 右侧区域
        right_frame = tk.Frame(main, bg=ModernPalette.LIGHT_BG, width=400)
        right_frame.pack(side="right", fill="both", padx=(15, 0))
        right_frame.pack_propagate(False)
        
        # ========== 左侧：标题区 ==========
        header = tk.Frame(left_frame, bg=ModernPalette.LIGHT_BG)
        header.pack(fill="x", pady=(0, 15))
        
        tk.Label(header,
                text="🔍 Server Forensic Analyzer v3.0",
                font=('Segoe UI', 20, 'bold'),
                fg=ModernPalette.PRIMARY,
                bg=ModernPalette.LIGHT_BG).pack(anchor="w")
        
        tk.Label(header,
                text="服务器架构与服务分析 | 取证分析专用工具",
                font=('Segoe UI', 10),
                fg=ModernPalette.TEXT_MEDIUM,
                bg=ModernPalette.LIGHT_BG).pack(anchor="w", pady=(5, 0))
        
        sep = tk.Frame(left_frame, height=1, bg=ModernPalette.BORDER_LIGHT)
        sep.pack(fill="x", pady=(0, 15))
        
        # ========== 左侧：配置区 ==========
        config_card, config_inner = self._create_card(left_frame)
        config_card.pack(fill="x", pady=(0, 10))
        
        tk.Label(config_inner,
                text="📁 目标目录",
                font=('Segoe UI', 11, 'bold'),
                fg=ModernPalette.PRIMARY_DARK,
                bg=ModernPalette.CARD_BG).grid(row=0, column=0, sticky="w", pady=(0, 8))
        
        dir_frame = tk.Frame(config_inner, bg=ModernPalette.CARD_BG)
        dir_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        dir_frame.columnconfigure(0, weight=1)
        
        self.dir_var = tk.StringVar()
        dir_entry = tk.Entry(dir_frame,
                            textvariable=self.dir_var,
                            font=('Segoe UI', 10),
                            bg=ModernPalette.LIGHT_BG,
                            fg=ModernPalette.TEXT_DARK,
                            relief="flat",
                            bd=0,
                            insertbackground=ModernPalette.PRIMARY)
        dir_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 10))
        
        tk.Button(dir_frame,
                 text="浏览",
                 command=self._browse,
                 bg=ModernPalette.PRIMARY,
                 fg=ModernPalette.WHITE,
                 font=('Segoe UI', 9, 'bold'),
                 relief="flat",
                 padx=20,
                 pady=5,
                 cursor="hand2").pack(side="left")
        
        # 快速扫描信息
        self.scan_info_label = tk.Label(config_inner,
                                     text="",
                                     bg=ModernPalette.CARD_BG,
                                     fg=ModernPalette.INFO,
                                     font=('Segoe UI', 9))
        self.scan_info_label.grid(row=2, column=0, sticky="w", pady=(0, 10))
        
        # 超时设置
        tk.Label(config_inner,
                text="⏱️ 超时配置",
                font=('Segoe UI', 11, 'bold'),
                fg=ModernPalette.PRIMARY_DARK,
                bg=ModernPalette.CARD_BG).grid(row=3, column=0, sticky="w", pady=(0, 8))
        
        timeout_frame = tk.Frame(config_inner, bg=ModernPalette.CARD_BG)
        timeout_frame.grid(row=4, column=0, sticky="w", pady=(0, 10))
        
        auto_cb = tk.Checkbutton(timeout_frame,
                                text="自动调整超时",
                                variable=self.auto_timeout_var,
                                bg=ModernPalette.CARD_BG,
                                fg=ModernPalette.TEXT_DARK,
                                font=('Segoe UI', 10),
                                selectcolor=ModernPalette.WHITE,
                                activebackground=ModernPalette.CARD_BG,
                                activeforeground=ModernPalette.TEXT_DARK,
                                command=self._on_auto_timeout_toggle)
        auto_cb.pack(side="left")
        
        self.manual_frame = tk.Frame(timeout_frame, bg=ModernPalette.CARD_BG)
        self.manual_frame.pack(side="left", padx=(15, 0))
        
        tk.Label(self.manual_frame,
                text="秒",
                bg=ModernPalette.CARD_BG,
                fg=ModernPalette.TEXT_LIGHT,
                font=('Segoe UI', 9)).pack(side="left", padx=(5, 0))
        
        tk.Spinbox(self.manual_frame,
                  from_=10, to=600,
                  textvariable=self.timeout_var,
                  font=('Segoe UI', 10),
                  width=8,
                  bg=ModernPalette.LIGHT_BG,
                  fg=ModernPalette.TEXT_DARK,
                  relief="flat").pack(side="left")
        
        # 按钮
        btn_frame = tk.Frame(config_inner, bg=ModernPalette.CARD_BG)
        btn_frame.grid(row=5, column=0, sticky="w")
        
        self.start_btn = tk.Button(btn_frame,
                                  text="▶  开始分析",
                                  command=self._start,
                                  bg=ModernPalette.PRIMARY,
                                  fg=ModernPalette.WHITE,
                                  font=('Segoe UI', 11, 'bold'),
                                  relief="flat",
                                  padx=30,
                                  pady=10,
                                  cursor="hand2")
        self.start_btn.pack(side="left", padx=(0, 10))
        
        tk.Button(btn_frame,
                 text="✕ 退出",
                 command=self.root.quit,
                 bg=ModernPalette.LIGHT_BG,
                 fg=ModernPalette.TEXT_MEDIUM,
                 font=('Segoe UI', 10),
                 relief="flat",
                 padx=20,
                 pady=10,
                 cursor="hand2").pack(side="left")
        
        # ========== 左侧：进度区 ==========
        progress_card, progress_inner = self._create_card(left_frame)
        progress_card.pack(fill="x", pady=(0, 10))
        
        tk.Label(progress_inner,
                text="📊 分析进度",
                font=('Segoe UI', 11, 'bold'),
                fg=ModernPalette.PRIMARY_DARK,
                bg=ModernPalette.CARD_BG).pack(anchor="w", pady=(0, 10))
        
        self.progress = ttk.Progressbar(progress_inner,
                                       length=300,
                                       mode='determinate')
        self.progress.pack(fill="x", pady=(0, 5))
        
        self.step_label = tk.Label(progress_inner,
                                  text="等待开始...",
                                  bg=ModernPalette.CARD_BG,
                                  fg=ModernPalette.TEXT_MEDIUM,
                                  font=('Segoe UI', 9))
        self.step_label.pack(anchor="w")
        
        # 日志
        self.log_text = scrolledtext.ScrolledText(progress_inner,
                                                  wrap="word",
                                                  height=6,
                                                  font=('Consolas', 9),
                                                  bg=ModernPalette.LIGHT_BG,
                                                  fg=ModernPalette.TEXT_DARK,
                                                  relief="flat",
                                                  bd=0,
                                                  padx=10,
                                                  pady=10,
                                                  state='disabled')
        self.log_text.pack(fill="both", expand=True, pady=(10, 0))
        
        # ========== 左侧：结果区 ==========
        result_card, result_inner = self._create_card(left_frame)
        result_card.pack(fill="both", expand=True)
        
        tk.Label(result_inner,
                text="📋 分析结果",
                font=('Segoe UI', 11, 'bold'),
                fg=ModernPalette.PRIMARY_DARK,
                bg=ModernPalette.CARD_BG).pack(anchor="w", pady=(0, 10))
        
        self.result_text = scrolledtext.ScrolledText(result_inner,
                                                    wrap="word",
                                                    height=8,
                                                    font=('Consolas', 9),
                                                    bg=ModernPalette.LIGHT_BG,
                                                    fg=ModernPalette.TEXT_DARK,
                                                    relief="flat",
                                                    bd=0,
                                                    padx=10,
                                                    pady=10,
                                                    state='disabled')
        self.result_text.pack(fill="both", expand=True)
        
        # ========== 右侧：分析详情栏 ==========
        detail_header = tk.Frame(right_frame, bg=ModernPalette.LIGHT_BG)
        detail_header.pack(fill="x", pady=(0, 10))
        
        tk.Label(detail_header,
                text="📝 分析详情",
                font=('Segoe UI', 14, 'bold'),
                fg=ModernPalette.PRIMARY,
                bg=ModernPalette.LIGHT_BG).pack(anchor="w")
        
        tk.Label(detail_header,
                text="实时显示各模块运行状态",
                font=('Segoe UI', 9),
                fg=ModernPalette.TEXT_LIGHT,
                bg=ModernPalette.LIGHT_BG).pack(anchor="w", pady=(3, 0))
        
        # 详情卡片
        detail_card, detail_inner = self._create_card(right_frame)
        detail_card.pack(fill="both", expand=True)
        
        self.detail_text = scrolledtext.ScrolledText(detail_inner,
                                                    wrap="word",
                                                    font=('Consolas', 9),
                                                    bg=ModernPalette.LIGHT_BG,
                                                    fg=ModernPalette.TEXT_DARK,
                                                    relief="flat",
                                                    bd=0,
                                                    padx=10,
                                                    pady=10,
                                                    state='disabled')
        self.detail_text.pack(fill="both", expand=True)
        
        # 初始日志
        self._log("✨ 欢迎使用服务器架构分析工具 v3.0")
        self._log("📌 使用说明:")
        self._log("   1. 选择要分析的服务器文件目录")
        self._log("   2. 系统会自动快速扫描目录")
        self._log("   3. 点击'开始分析'运行分析")
        self._log("   4. 右侧显示各模块详细运行状态")
        self._log("-" * 50)
        
        self._detail_log("等待用户选择目录...")
    
    def _on_auto_timeout_toggle(self):
        """自动超时切换"""
        if self.auto_timeout_var.get():
            self.manual_frame.pack_forget()
        else:
            self.manual_frame.pack(side="left", padx=(15, 0))
    
    def _browse(self):
        """浏览目录"""
        path = filedialog.askdirectory(title="选择服务器文件目录")
        if path:
            self.dir_var.set(path)
            self._log(f"📂 已选择: {path}")
            self._quick_scan(path)
    
    def _quick_scan(self, target_dir):
        """快速扫描目录"""
        self.scan_info_label.config(text="正在快速扫描目录...")
        self.root.update_idletasks()
        
        def scan_thread():
            try:
                scanner = QuickFileScanner(target_dir, max_depth=6, max_files=3000)
                stats = scanner.scan_quickly(timeout=8)
                self.scan_stats = stats
                
                if stats.get('timeout'):
                    self.root.after(0, lambda: self.scan_info_label.config(
                        text=f"⚠️ 快速扫描超时，仅分析部分文件"))
                else:
                    complexity = stats.get('complexity', 'low')
                    timeout_suggestion = {
                        'low': 30,
                        'medium': 60,
                        'high': 120,
                        'very_high': 300
                    }.get(complexity, 60)
                    
                    self.root.after(0, lambda: self.scan_info_label.config(
                        text=f"📊 扫描完成: {stats.get('total_files', 0):,} 文件 | "
                             f"{stats.get('size_mb', 0):.1f} MB | "
                             f"复杂度: {complexity}"))
                    
                    if self.auto_timeout_var.get():
                        self.root.after(0, lambda: self.timeout_var.set(timeout_suggestion))
            except Exception as e:
                self.root.after(0, lambda: self.scan_info_label.config(text=f"扫描出错: {e}"))
        
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()
    
    def _log(self, msg):
        """添加日志"""
        self.log_text.config(state='normal')
        
        if "✓" in msg or "成功" in msg:
            self.log_text.insert(tk.END, msg + "\n", 'success')
        elif "✗" in msg or "失败" in msg or "错误" in msg or "超时" in msg:
            self.log_text.insert(tk.END, msg + "\n", 'error')
        elif "⚠️" in msg or "警告" in msg:
            self.log_text.insert(tk.END, msg + "\n", 'warning')
        elif "📊" in msg or "预估" in msg:
            self.log_text.insert(tk.END, msg + "\n", 'info')
        else:
            self.log_text.insert(tk.END, msg + "\n")
        
        self.log_text.tag_config('success', foreground=ModernPalette.SUCCESS)
        self.log_text.tag_config('error', foreground=ModernPalette.ERROR)
        self.log_text.tag_config('warning', foreground=ModernPalette.WARNING)
        self.log_text.tag_config('info', foreground=ModernPalette.INFO)
        
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        self.root.update_idletasks()
    
    def _detail_log(self, msg):
        """右侧详情日志"""
        self.detail_text.config(state='normal')
        
        timestamp = time.strftime("%H:%M:%S")
        
        if "✓" in msg or "完成" in msg:
            color = 'success'
        elif "✗" in msg or "失败" in msg or "错误" in msg:
            color = 'error'
        elif "⚠️" in msg:
            color = 'warning'
        elif "🔍" in msg or "搜索" in msg or "分析" in msg:
            color = 'info'
        else:
            color = 'normal'
        
        self.detail_text.insert(tk.END, f"[{timestamp}] {msg}\n", color)
        
        self.detail_text.tag_config('success', foreground=ModernPalette.SUCCESS)
        self.detail_text.tag_config('error', foreground=ModernPalette.ERROR)
        self.detail_text.tag_config('warning', foreground=ModernPalette.WARNING)
        self.detail_text.tag_config('info', foreground=ModernPalette.INFO)
        
        self.detail_text.see(tk.END)
        self.detail_text.config(state='disabled')
        self.root.update_idletasks()
    
    def _clear_detail(self):
        """清空详情"""
        self.detail_text.config(state='normal')
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.config(state='disabled')
    
    def _clear_log(self):
        """清空日志"""
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
    
    def _display_result(self, text):
        """显示结果"""
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')
    
    def _set_progress(self, value, text):
        """设置进度"""
        self.progress['value'] = value
        self.step_label.config(text=text)
        self.root.update_idletasks()
    
    def _start(self):
        """开始分析"""
        if self.analysis_running:
            return
        
        target_dir = self.dir_var.get().strip()
        if not target_dir:
            messagebox.showwarning("提示", "请先选择服务器文件目录！")
            return
        
        if not Path(target_dir).exists():
            messagebox.showerror("错误", "目录不存在！")
            return
        
        self.analysis_running = True
        self.start_btn.config(state='disabled', bg=ModernPalette.TEXT_LIGHT)
        self._clear_log()
        self._clear_detail()
        self._display_result("正在分析中...\n")
        
        timeout = self.timeout_var.get()
        
        thread = threading.Thread(target=self._run, args=(target_dir, timeout), daemon=True)
        thread.start()
    
    def _run(self, target_dir, timeout):
        """运行分析 - 集成所有v2.0模块"""
        try:
            self._log("=" * 50)
            self._log(f"🚀 开始分析: {target_dir}")
            self._log(f"⏱️ 超时设置: {timeout} 秒")
            self._log("=" * 50)
            
            self._detail_log("=" * 40)
            self._detail_log("🚀 开始综合分析...")
            self._detail_log(f"目标: {target_dir}")
            self._detail_log(f"超时: {timeout}秒")
            
            analysis_data = {'warnings': []}
            step_total = 15
            step = 0
            
            def update_step(step_num, text, detail):
                nonlocal step
                step = step_num
                progress = int((step_num / step_total) * 100)
                self._set_progress(progress, text)
                self._detail_log(f"🔍 步骤{step_num}/{step_total}: {detail}")
            
            step_timeout = max(timeout // 5, 15)
            
            # 步骤1: 文件架构解析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析文件架构...", "解析目录结构...")
            self._log("\n[1/{}] 分析文件架构...".format(step_total))
            
            try:
                arch_analyzer = FileStructureAnalyzer(target_dir, step_timeout)
                arch_result = arch_analyzer.analyze()
                analysis_data['file_structure'] = arch_result['data']
                analysis_data['warnings'].extend(arch_result.get('warnings', []))
                
                if arch_result.get('architecture_diagram'):
                    self._detail_log("    📁 发现 {} 个目录".format(arch_result['data'].get('total_dirs', 0)))
                    self._detail_log("    📄 发现 {} 个文件".format(arch_result['data'].get('total_files', 0)))
                
                self._log("  ✓ 文件架构分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['file_structure'] = {}
            
            # 步骤2: 服务配置
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析服务配置...", "扫描nginx/apache配置...")
            self._log("\n[2/{}] 分析服务配置...".format(step_total))
            self._detail_log("    🔍 搜索 nginx/apache/httpd 等配置...")
            
            try:
                analyzer = ServiceConfigAnalyzer(target_dir, step_timeout)
                result = analyzer.analyze()
                analysis_data['services'] = result['data']
                analysis_data['warnings'].extend(result.get('warnings', []))
                
                for w in result.get('warnings', []):
                    self._log(f"  ⚠️ {w}")
                    self._detail_log(f"    ⚠️ {w[:60]}")
                self._log("  ✓ 服务配置分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['services'] = {}
            
            # 步骤3: Web反向代理
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析反向代理...", "解析代理配置...")
            self._log("\n[3/{}] 分析反向代理配置...".format(step_total))
            
            try:
                proxy_analyzer = WebProxyAnalyzer(target_dir, step_timeout)
                proxy_result = proxy_analyzer.analyze()
                analysis_data['web_proxy'] = proxy_result['data']
                analysis_data['warnings'].extend(proxy_result.get('warnings', []))
                self._log("  ✓ 反向代理分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['web_proxy'] = {}
            
            # 步骤4: 网络分析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析网络端口...", "解析端口映射...")
            self._log("\n[4/{}] 分析网络端口...".format(step_total))
            
            try:
                net_analyzer = NetworkAnalyzer(analysis_data.get('services', {}))
                network_data = net_analyzer.analyze()
                analysis_data['network'] = network_data
                self._log("  ✓ 网络分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['network'] = {}
            
            # 步骤5: IP分析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析IP访问...", "解析访问日志...")
            self._log("\n[5/{}] 分析IP访问...".format(step_total))
            self._detail_log("    🔍 提取IP地址、请求路径...")
            
            try:
                ip_analyzer = IPAnalyzer(target_dir, step_timeout)
                ip_result = ip_analyzer.analyze()
                analysis_data['ip'] = ip_result['data']
                analysis_data['warnings'].extend(ip_result.get('warnings', []))
                
                for w in ip_result.get('warnings', []):
                    self._log(f"  ⚠️ {w}")
                    self._detail_log(f"    ⚠️ {w[:60]}")
                self._log("  ✓ IP分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['ip'] = {}
            
            # 步骤6: 访问日志分析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析访问日志...", "解析access.log...")
            self._log("\n[6/{}] 分析访问日志...".format(step_total))
            
            try:
                log_analyzer = AccessLogAnalyzer(target_dir, step_timeout)
                log_result = log_analyzer.analyze()
                analysis_data['access_log_analysis'] = log_result['data']
                analysis_data['warnings'].extend(log_result.get('warnings', []))
                self._log("  ✓ 访问日志分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['access_log_analysis'] = {}
            
            # 步骤7: 后端服务发现
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 发现后端服务...", "扫描服务进程...")
            self._log("\n[7/{}] 发现后端服务...".format(step_total))
            self._detail_log("    🔍 搜索 gost/xray/v2ray 等后端...")
            
            try:
                backend_analyzer = BackendServiceDiscovery(target_dir, step_timeout)
                backend_result = backend_analyzer.analyze(analysis_data.get('web_proxy'))
                analysis_data['backend_services'] = backend_result['data']
                analysis_data['warnings'].extend(backend_result.get('warnings', []))
                self._log("  ✓ 后端服务发现完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['backend_services'] = {}
            
            # 步骤8: SSH安全评估
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 评估SSH安全...", "分析登录日志...")
            self._log("\n[8/{}] 评估SSH安全...".format(step_total))
            
            try:
                ssh_analyzer = SSHSecurityAnalyzer(target_dir, step_timeout)
                ssh_result = ssh_analyzer.analyze()
                analysis_data['ssh_security'] = ssh_result['data']
                analysis_data['warnings'].extend(ssh_result.get('warnings', []))
                self._log("  ✓ SSH安全评估完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['ssh_security'] = {}
            
            # 步骤9: 启动项分析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析启动项...", "扫描systemd/cron...")
            self._log("\n[9/{}] 分析启动项...".format(step_total))
            
            try:
                startup_analyzer = StartupAnalyzer(target_dir, step_timeout)
                startup_result = startup_analyzer.analyze()
                analysis_data['startup_items'] = startup_result['data']
                analysis_data['warnings'].extend(startup_result.get('warnings', []))
                self._log("  ✓ 启动项分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['startup_items'] = {}
            
            # 步骤10: 日志文件分析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析日志文件...", "标注日志类型...")
            self._log("\n[10/{}] 分析日志文件...".format(step_total))
            
            try:
                logfile_analyzer = LogFileAnalyzer(target_dir, step_timeout)
                logfile_result = logfile_analyzer.analyze()
                analysis_data['log_files'] = logfile_result['data']
                analysis_data['warnings'].extend(logfile_result.get('warnings', []))
                self._log("  ✓ 日志文件分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['log_files'] = {}
            
            # 步骤11: 数据库探测
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 探测数据库...", "扫描数据库服务...")
            self._log("\n[11/{}] 探测数据库...".format(step_total))
            
            try:
                db_analyzer = DatabaseDetector(target_dir, step_timeout)
                db_result = db_analyzer.analyze()
                analysis_data['database_services'] = db_result['data']
                analysis_data['warnings'].extend(db_result.get('warnings', []))
                self._log("  ✓ 数据库探测完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['database_services'] = {}
            
            # 步骤12: 出站连接追踪
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 追踪出站连接...", "分析外部连接...")
            self._log("\n[12/{}] 追踪出站连接...".format(step_total))
            
            try:
                outbound_analyzer = OutboundTracker(target_dir, step_timeout)
                outbound_result = outbound_analyzer.analyze()
                analysis_data['outbound_connections'] = outbound_result['data']
                analysis_data['warnings'].extend(outbound_result.get('warnings', []))
                self._log("  ✓ 出站连接追踪完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['outbound_connections'] = {}
            
            # 步骤13: 角色识别
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 识别服务器角色...", "综合判断...")
            self._log("\n[13/{}] 识别服务器角色...".format(step_total))
            
            try:
                role_id = ServerRoleIdentifier(
                    analysis_data.get('services', {}),
                    analysis_data.get('network', {})
                )
                roles_data = role_id.identify()
                analysis_data['roles'] = roles_data
                self._log("  ✓ 角色识别完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['roles'] = {}
            
            # 步骤14: 时间线分析
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 分析时间线...", "关联事件...")
            self._log("\n[14/{}] 分析时间线...".format(step_total))
            
            try:
                timeline_analyzer = TimelineAnalyzer(target_dir, step_timeout)
                timeline_result = timeline_analyzer.analyze(analysis_data)
                analysis_data['timeline'] = timeline_result['data']
                analysis_data['warnings'].extend(timeline_result.get('warnings', []))
                self._log("  ✓ 时间线分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
                analysis_data['timeline'] = {}
            
            # 步骤15: 关联分析与完整架构图
            step += 1
            update_step(step, f"步骤 {step}/{step_total}: 关联分析...", "构建架构图...")
            self._log("\n[15/{}] 执行关联分析...".format(step_total))
            self._detail_log("    🔗 关联所有数据源...")
            
            try:
                correlation_engine = CorrelationEngine()
                correlation_result = correlation_engine.analyze(
                    web_proxy_data=analysis_data.get('web_proxy'),
                    access_log_data=analysis_data.get('access_log_analysis'),
                    backend_services=analysis_data.get('backend_services'),
                    startup_items=analysis_data.get('startup_items'),
                    ssh_security=analysis_data.get('ssh_security'),
                    log_files=analysis_data.get('log_files'),
                    database_services=analysis_data.get('database_services'),
                    outbound_connections=analysis_data.get('outbound_connections'),
                    services=analysis_data.get('services'),
                    network=analysis_data.get('network')
                )
                analysis_data['full_architecture'] = correlation_result['data']
                analysis_data['warnings'].extend(correlation_result.get('warnings', []))
                
                arch_diagram = correlation_engine.generate_architecture_diagram()
                analysis_data['architecture_diagram'] = arch_diagram
                
                self._log("  ✓ 关联分析完成")
                self._detail_log("✅ 步骤{}完成".format(step))
            except Exception as e:
                self._log(f"  ✗ 失败: {e}")
                self._detail_log(f"✗ 步骤{step}失败: {e}")
            
            # 步骤16: 生成报告
            step += 1
            self._set_progress(95, f"步骤 {step}/{step_total}: 生成报告...")
            self._log("\n[16/{}] 生成综合报告...".format(step_total))
            self._detail_log("📝 生成综合分析报告...")
            
            try:
                reporter = ReportGenerator()
                text_path = reporter.generate_text_report(analysis_data)
                
                arch_flowchart = generate_architecture_flowchart(
                    analysis_data.get('services', {}),
                    analysis_data.get('network', {}),
                    analysis_data.get('roles', {})
                )
                
                with open(text_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if analysis_data.get('architecture_diagram'):
                    content += "\n\n" + analysis_data['architecture_diagram']
                
                if analysis_data.get('file_structure', {}).get('architecture_diagram'):
                    content += "\n\n" + analysis_data['file_structure']['architecture_diagram']
                
                content += "\n\n" + arch_flowchart
                
                with open(text_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                self._display_result(content)
                self._log(f"  ✓ 报告已保存: {text_path}")
                self._detail_log(f"✅ 报告完成")
                self._detail_log(f"📄 报告: {text_path}")
            except Exception as e:
                self._log(f"  ✗ 报告生成失败: {e}")
                self._detail_log(f"✗ 报告生成失败: {e}")
            
            self._set_progress(100, "分析完成！")
            self._log("\n" + "=" * 50)
            self._log("✅ 分析完成！")
            self._detail_log("=" * 40)
            self._detail_log("🎉 所有分析任务完成！")
            
            if analysis_data.get('warnings'):
                self._log(f"\n共 {len(analysis_data['warnings'])} 个警告/提示")
                self._detail_log(f"⚠️ 共 {len(analysis_data['warnings'])} 个警告")
            
        except Exception as e:
            self._log(f"\n❌ 严重错误: {e}")
            self._detail_log(f"❌ 严重错误: {e}")
        finally:
            self.analysis_running = False
            self.start_btn.config(state='normal', bg=ModernPalette.PRIMARY)


def main():
    root = tk.Tk()
    app = ServerAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

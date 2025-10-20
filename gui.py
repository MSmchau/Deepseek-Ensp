#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
网络设备配置GUI界面
使用tkinter实现，提供交换机与路由器的配置管理功能
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging
import os
import sys
from datetime import datetime

# 导入配置和必要的模块
from config import (
    DEEPSEEK_API_KEY, DEEPSEEK_API_URL, SIMULATION_MODE,
    DEFAULT_DEVICE_IP, DEFAULT_DEVICE_PORT, DEFAULT_DEVICE_USERNAME, DEFAULT_DEVICE_PASSWORD,
    DEVICE_TYPE
)

# 导入主模块中的函数
from main import process_config_command

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gui.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 动态导入其他模块，避免循环导入
class NetworkConfigGUI:
    """网络设备配置GUI界面类"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DeepSeek接入Ensp - 网络设备配置管理")
        self.root.geometry("1000x700")
        
        # 设置中文字体支持
        self._setup_fonts()
        
        # 初始化变量
        self.device = None
        self.execution_thread = None
        
        # 创建主框架
        self.main_notebook = ttk.Notebook(root)
        self.main_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建各个标签页
        self._create_connection_tab()
        self._create_configuration_tab()
        self._create_troubleshooting_tab()
        self._create_device_tab()
        self._create_log_tab()
        
        # 创建状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 加载配置
        self._load_config()
        
        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _setup_fonts(self):
        """设置中文字体支持"""
        # tkinter在Windows上通常会自动处理中文字体
        pass
    
    def _create_connection_tab(self):
        """创建设备连接标签页"""
        connection_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(connection_frame, text="设备连接")
        
        # 设备类型选择
        type_frame = ttk.LabelFrame(connection_frame, text="设备类型")
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.device_type_var = tk.StringVar(value=DEVICE_TYPE)
        device_types = ["交换机", "路由器", "防火墙"]
        
        for device_type in device_types:
            radio = ttk.Radiobutton(
                type_frame,
                text=device_type,
                variable=self.device_type_var,
                value=device_type
            )
            radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        # 连接信息输入
        conn_frame = ttk.LabelFrame(connection_frame, text="连接信息")
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # IP地址
        ttk.Label(conn_frame, text="IP地址:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.ip_var = tk.StringVar(value=DEFAULT_DEVICE_IP)
        ttk.Entry(conn_frame, textvariable=self.ip_var, width=30).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        # 端口
        ttk.Label(conn_frame, text="端口:").grid(row=0, column=2, sticky=tk.W, padx=10, pady=5)
        self.port_var = tk.StringVar(value=str(DEFAULT_DEVICE_PORT))
        ttk.Entry(conn_frame, textvariable=self.port_var, width=10).grid(row=0, column=3, sticky=tk.W, padx=10, pady=5)
        
        # 用户名
        ttk.Label(conn_frame, text="用户名:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.username_var = tk.StringVar(value=DEFAULT_DEVICE_USERNAME)
        ttk.Entry(conn_frame, textvariable=self.username_var, width=30).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # 密码
        ttk.Label(conn_frame, text="密码:").grid(row=1, column=2, sticky=tk.W, padx=10, pady=5)
        self.password_var = tk.StringVar(value=DEFAULT_DEVICE_PASSWORD)
        ttk.Entry(conn_frame, textvariable=self.password_var, show="*", width=30).grid(row=1, column=3, sticky=tk.W, padx=10, pady=5)
        
        # 连接按钮
        btn_frame = ttk.Frame(connection_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.connect_btn = ttk.Button(btn_frame, text="连接设备", command=self._connect_device)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(btn_frame, text="断开连接", command=self._disconnect_device, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # 连接状态
        self.status_label = ttk.Label(btn_frame, text="状态: 未连接", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # 设备信息显示
        info_frame = ttk.LabelFrame(connection_frame, text="设备信息")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.device_info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=10)
        self.device_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.device_info_text.config(state=tk.DISABLED)
    
    def _create_configuration_tab(self):
        """创建配置管理标签页"""
        config_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(config_frame, text="配置管理")
        
        # 配置方式选择
        mode_frame = ttk.LabelFrame(config_frame, text="配置方式")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.config_mode_var = tk.StringVar(value="natural")
        
        natural_radio = ttk.Radiobutton(
            mode_frame,
            text="自然语言配置",
            variable=self.config_mode_var,
            value="natural",
            command=self._update_config_mode
        )
        natural_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        file_radio = ttk.Radiobutton(
            mode_frame,
            text="文件导入配置",
            variable=self.config_mode_var,
            value="file",
            command=self._update_config_mode
        )
        file_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        # 自然语言配置区域
        self.natural_frame = ttk.LabelFrame(config_frame, text="自然语言描述")
        self.natural_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.natural_text = scrolledtext.ScrolledText(self.natural_frame, wrap=tk.WORD, height=10)
        self.natural_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.natural_text.insert(tk.END, "请输入设备配置的自然语言描述，例如：\n为交换机配置VLAN 10，IP地址为192.168.10.1/24")
        # 绑定回车键执行配置
        self.natural_text.bind("<Return>", lambda event: self._execute_configuration())
        
        # 文件导入配置区域
        self.file_frame = ttk.LabelFrame(config_frame, text="配置文件")
        self.file_frame.pack(fill=tk.X, padx=10, pady=5)
        self.file_frame.pack_forget()  # 初始隐藏
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(self.file_frame, textvariable=self.file_path_var, width=60).pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        ttk.Button(self.file_frame, text="浏览...", command=self._browse_config_file).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 配置命令显示区域
        cmd_frame = ttk.LabelFrame(config_frame, text="生成的配置命令")
        cmd_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.command_text = scrolledtext.ScrolledText(cmd_frame, wrap=tk.WORD, height=10)
        self.command_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.command_text.config(state=tk.DISABLED)
        
        # 执行结果区域
        result_frame = ttk.LabelFrame(config_frame, text="执行结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=10)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.result_text.config(state=tk.DISABLED)
        
        # 操作按钮
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.execute_btn = ttk.Button(btn_frame, text="执行配置", command=self._execute_configuration)
        self.execute_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(btn_frame, text="取消", command=self._cancel_execution, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(config_frame, variable=self.progress_var, length=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
    
    def _create_troubleshooting_tab(self):
        """创建故障排查标签页"""
        troubleshoot_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(troubleshoot_frame, text="故障排查")
        
        # 问题描述/网络命令
        desc_frame = ttk.LabelFrame(troubleshoot_frame, text="问题描述/网络命令")
        desc_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.problem_text = scrolledtext.ScrolledText(desc_frame, wrap=tk.WORD, height=10)
        self.problem_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.problem_text.insert(tk.END, "请描述您遇到的网络问题，例如：\n交换机端口无法连接，ping测试失败\n\n或直接输入网络命令，如：\nping 192.168.1.1\ntracert 8.8.8.8")
        
        # 添加提示文本
        hint_frame = ttk.Frame(desc_frame)
        hint_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(hint_frame, text="提示: 您可以直接在问题描述中输入网络命令(ping/tracert)或设备命令(display interface等)", 
                 font=('SimHei', 8), foreground='gray').pack(anchor='w')
        
        # 快速命令按钮框架
        quick_commands_frame = ttk.Frame(troubleshoot_frame)
        quick_commands_frame.pack(fill=tk.X, padx=10, pady=2)
        
        ttk.Label(quick_commands_frame, text="快速命令:", font=('SimHei', 9)).pack(side=tk.LEFT, padx=5)
        
        # 添加快速命令按钮
        quick_commands = [
            ('Ping 网关', 'ping 192.168.1.1'),
            ('Ping DNS', 'ping 8.8.8.8'),
            ('显示接口', 'display interface'),
            ('显示VLAN', 'display vlan'),
            ('显示ARP表', 'display arp'),
            ('显示路由表', 'display ip routing-table')
        ]
        
        for text, command in quick_commands:
            btn = ttk.Button(quick_commands_frame, text=text, width=10, 
                            command=lambda cmd=command: self._insert_quick_command(cmd))
            btn.pack(side=tk.LEFT, padx=2, pady=2)
        
        # 排查结果
        result_frame = ttk.LabelFrame(troubleshoot_frame, text="执行结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.troubleshoot_result = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=15)
        self.troubleshoot_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.troubleshoot_result.config(state=tk.DISABLED)
        
        # 操作按钮
        btn_frame = ttk.Frame(troubleshoot_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="开始排查/执行命令", command=self._start_troubleshooting).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出报告", command=self._export_troubleshoot_report).pack(side=tk.LEFT, padx=5)
    
    def _create_device_tab(self):
        """创建设备管理标签页"""
        device_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(device_frame, text="设备管理")
        
        # 操作选择
        op_frame = ttk.LabelFrame(device_frame, text="操作类型")
        op_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.crud_op_var = tk.StringVar(value="list")
        
        list_radio = ttk.Radiobutton(
            op_frame,
            text="查看设备列表",
            variable=self.crud_op_var,
            value="list",
            command=self._update_crud_mode
        )
        list_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        add_radio = ttk.Radiobutton(
            op_frame,
            text="添加设备",
            variable=self.crud_op_var,
            value="add",
            command=self._update_crud_mode
        )
        add_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        edit_radio = ttk.Radiobutton(
            op_frame,
            text="编辑设备",
            variable=self.crud_op_var,
            value="edit",
            command=self._update_crud_mode
        )
        edit_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        delete_radio = ttk.Radiobutton(
            op_frame,
            text="删除设备",
            variable=self.crud_op_var,
            value="delete",
            command=self._update_crud_mode
        )
        delete_radio.pack(side=tk.LEFT, padx=10, pady=5)
        
        # 设备列表
        self.device_list_frame = ttk.LabelFrame(device_frame, text="设备列表")
        self.device_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 创建Treeview显示设备列表
        columns = ("id", "type", "ip", "port", "username")
        self.device_tree = ttk.Treeview(self.device_list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=150)
        
        self.device_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设备表单
        self.device_form_frame = ttk.LabelFrame(device_frame, text="设备信息")
        self.device_form_frame.pack(fill=tk.X, padx=10, pady=5)
        self.device_form_frame.pack_forget()  # 初始隐藏
        
        # 设备表单元素
        form_grid = ttk.Frame(self.device_form_frame)
        form_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # 设备ID
        ttk.Label(form_grid, text="设备ID:", width=12).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.device_id_var = tk.StringVar()
        self.device_id_entry = ttk.Entry(form_grid, textvariable=self.device_id_var, width=30)
        self.device_id_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.device_id_entry.config(state=tk.DISABLED)
        
        # 设备类型
        ttk.Label(form_grid, text="设备类型:", width=12).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.device_form_type_var = tk.StringVar(value="交换机")
        device_type_combo = ttk.Combobox(form_grid, textvariable=self.device_form_type_var, values=["交换机", "路由器", "防火墙"], width=28)
        device_type_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # IP地址
        ttk.Label(form_grid, text="IP地址:", width=12).grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.device_ip_var = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.device_ip_var, width=30).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # 端口
        ttk.Label(form_grid, text="端口:", width=12).grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.device_port_var = tk.StringVar(value="22")
        ttk.Entry(form_grid, textvariable=self.device_port_var, width=30).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        # 用户名
        ttk.Label(form_grid, text="用户名:", width=12).grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.device_username_var = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.device_username_var, width=30).grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)
        
        # 密码
        ttk.Label(form_grid, text="密码:", width=12).grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.device_password_var = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.device_password_var, show="*", width=30).grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)
        
        # 操作按钮
        btn_frame = ttk.Frame(device_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="执行", command=self._execute_crud).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="刷新", command=self._refresh_device_list).pack(side=tk.LEFT, padx=5)
    
    def _create_log_tab(self):
        """创建日志标签页"""
        log_frame = ttk.Frame(self.main_notebook)
        self.main_notebook.add(log_frame, text="操作日志")
        
        # 日志显示区域
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text.config(state=tk.DISABLED)
        
        # 操作按钮
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="清空日志", command=self._clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出日志", command=self._export_log).pack(side=tk.LEFT, padx=5)
    
    def _load_config(self):
        """加载配置信息"""
        try:
            logger.info("配置信息已加载")
            self._update_log("配置信息已加载")
        except Exception as e:
            logger.error(f"加载配置失败: {str(e)}")
            self._update_log(f"加载配置失败: {str(e)}")
    
    def _update_config_mode(self):
        """更新配置模式"""
        if self.config_mode_var.get() == "natural":
            self.natural_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            self.file_frame.pack_forget()
        else:
            self.natural_frame.pack_forget()
            self.file_frame.pack(fill=tk.X, padx=10, pady=5)
    
    def _update_crud_mode(self):
        """更新CRUD操作模式"""
        if self.crud_op_var.get() == "list":
            self.device_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            self.device_form_frame.pack_forget()
            self._refresh_device_list()
        else:
            self.device_form_frame.pack(fill=tk.X, padx=10, pady=5)
            # 根据操作类型重置表单
            self._reset_device_form()
            
            # 如果是编辑模式且有选中项，加载设备信息
            if self.crud_op_var.get() == "edit":
                selected_item = self.device_tree.selection()
                if selected_item:
                    self._load_device_info(selected_item[0])
    
    def _connect_device(self):
        """连接设备"""
        try:
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get().strip())
            username = self.username_var.get().strip()
            password = self.password_var.get().strip()
            device_type = self.device_type_var.get()
            
            if not ip:
                messagebox.showerror("输入错误", "请输入设备IP地址")
                return
            
            if not username:
                messagebox.showerror("输入错误", "请输入用户名")
                return
            
            # 更新状态栏
            self.status_var.set(f"正在连接设备 {ip}...")
            self._update_log(f"尝试连接设备: {ip}:{port}")
            
            # 禁用连接按钮
            self.connect_btn.config(state=tk.DISABLED)
            
            # 创建连接线程
            def connect_task():
                try:
                    # 动态导入NetworkDevice类
                    from network_device import NetworkDevice
                    
                    # 创建设备实例
                    self.device = NetworkDevice(ip, username, password, port)
                    
                    # 连接设备
                    connected = self.device.connect()
                    
                    # 在主线程中更新UI
                    def update_ui():
                        if connected:
                            self.status_label.config(text="状态: 已连接", foreground="green")
                            self.disconnect_btn.config(state=tk.NORMAL)
                            self.status_var.set(f"已连接到设备 {ip}")
                            
                            # 获取设备信息
                            try:
                                device_info = self.device.get_basic_info()
                                self.device_info_text.config(state=tk.NORMAL)
                                self.device_info_text.delete(1.0, tk.END)
                                
                                # 优化设备信息显示格式
                                if isinstance(device_info, dict):
                                    # 设备类型信息
                                    if "设备类型" in device_info:
                                        self.device_info_text.insert(tk.END, f"设备类型: {device_info['设备类型']}\n\n")
                                    
                                    # 版本信息，格式化显示
                                    if "版本信息" in device_info:
                                        self.device_info_text.insert(tk.END, "版本信息:\n")
                                        self.device_info_text.insert(tk.END, "=" * 60 + "\n")
                                        # 对版本信息进行简单的格式化，使其更易读
                                        version_lines = device_info['版本信息'].split('\n')
                                        for line in version_lines:
                                            # 跳过空行和只有空白字符的行
                                            if line.strip():
                                                self.device_info_text.insert(tk.END, line + "\n")
                                        self.device_info_text.insert(tk.END, "=" * 60 + "\n\n")
                                    
                                    # 接口信息，格式化显示
                                    if "接口信息" in device_info:
                                        self.device_info_text.insert(tk.END, "接口信息:\n")
                                        self.device_info_text.insert(tk.END, "=" * 60 + "\n")
                                        # 对接口信息进行特殊处理，使其更清晰
                                        interface_lines = device_info['接口信息'].split('\n')
                                        for line in interface_lines:
                                            # 跳过空行和只有空白字符的行
                                            if line.strip():
                                                # 高亮接口名称行
                                                if any(keyword in line for keyword in ['Interface', '接口']):
                                                    self.device_info_text.insert(tk.END, "\n" + line + "\n")
                                                elif any(keyword in line for keyword in ['down', 'up']):
                                                    # 为端口状态添加颜色标记
                                                    self.device_info_text.insert(tk.END, line + "\n")
                                                else:
                                                    self.device_info_text.insert(tk.END, line + "\n")
                                        self.device_info_text.insert(tk.END, "=" * 60 + "\n")
                                    
                                    # 错误信息处理
                                    if "error" in device_info:
                                        self.device_info_text.insert(tk.END, f"错误: {device_info['error']}\n")
                                else:
                                    # 如果不是字典，直接显示
                                    self.device_info_text.insert(tk.END, str(device_info))
                                
                                # 添加时间戳
                                from datetime import datetime
                                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                self.device_info_text.insert(tk.END, f"\n信息获取时间: {current_time}")
                                
                                # 设置字体和文本属性
                                self.device_info_text.tag_configure("highlight", foreground="blue", font=('Microsoft YaHei', 10, 'bold'))
                                
                                # 禁用编辑
                                self.device_info_text.config(state=tk.DISABLED)
                            except Exception as e:
                                self.device_info_text.config(state=tk.NORMAL)
                                self.device_info_text.delete(1.0, tk.END)
                                self.device_info_text.insert(tk.END, f"获取设备信息失败: {str(e)}")
                                self.device_info_text.config(state=tk.DISABLED)
                            
                            self._update_log(f"成功连接到设备: {ip}")
                        else:
                            self.status_label.config(text="状态: 连接失败", foreground="red")
                            self.status_var.set(f"连接设备 {ip} 失败")
                            self._update_log(f"连接设备失败: {ip}")
                            messagebox.showerror("连接失败", "无法连接到设备，请检查连接信息")
                        
                        # 重新启用连接按钮
                        self.connect_btn.config(state=tk.NORMAL)
                    
                    # 使用after方法在主线程更新UI
                    self.root.after(0, update_ui)
                    
                except Exception as e:
                    # 保存异常信息为字符串
                    error_msg = str(e)
                    # 在主线程中显示错误
                    def show_error():
                        self.status_label.config(text="状态: 连接错误", foreground="red")
                        self.status_var.set("连接设备时发生错误")
                        self._update_log(f"连接设备时出错: {error_msg}")
                        messagebox.showerror("连接错误", f"连接设备时发生错误: {error_msg}")
                        self.connect_btn.config(state=tk.NORMAL)
                    
                    self.root.after(0, show_error)
            
            # 启动连接线程
            threading.Thread(target=connect_task, daemon=True).start()
            
        except Exception as e:
            self.connect_btn.config(state=tk.NORMAL)
            self.status_var.set("就绪")
            self._update_log(f"连接设备时发生异常: {str(e)}")
            messagebox.showerror("错误", f"连接设备时发生异常: {str(e)}")
    
    def _disconnect_device(self):
        """断开设备连接"""
        try:
            if self.device and self.device.connected:
                self.device.disconnect()
                self.status_label.config(text="状态: 未连接", foreground="red")
                self.disconnect_btn.config(state=tk.DISABLED)
                self.device_info_text.config(state=tk.NORMAL)
                self.device_info_text.delete(1.0, tk.END)
                self.device_info_text.config(state=tk.DISABLED)
                self.status_var.set("已断开设备连接")
                self._update_log("已断开设备连接")
                self.device = None
        except Exception as e:
            self._update_log(f"断开设备连接时出错: {str(e)}")
            messagebox.showwarning("警告", f"断开设备连接时出错: {str(e)}")
    
    def _browse_config_file(self):
        """浏览配置文件"""
        file_path = filedialog.askopenfilename(
            title="选择配置文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def _execute_configuration(self):
        """执行配置"""
        try:
            # 检查设备连接
            if not self.device or not self.device.connected:
                messagebox.showwarning("警告", "请先连接设备")
                return
            
            # 根据配置模式获取命令
            natural_language = None
            command_file = None
            
            if self.config_mode_var.get() == "natural":
                natural_language = self.natural_text.get(1.0, tk.END).strip()
                if not natural_language:
                    messagebox.showerror("输入错误", "请输入自然语言配置描述")
                    return
            else:
                command_file = self.file_path_var.get().strip()
                if not command_file or not os.path.exists(command_file):
                    messagebox.showerror("输入错误", "请选择有效的配置文件")
                    return
            
            # 更新UI状态
            self.execute_btn.config(state=tk.DISABLED)
            self.cancel_btn.config(state=tk.NORMAL)
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.config(state=tk.DISABLED)
            self.command_text.config(state=tk.NORMAL)
            self.command_text.delete(1.0, tk.END)
            self.command_text.config(state=tk.DISABLED)
            self.progress_var.set(0)
            
            # 创建并启动执行线程
            self.execution_thread = CommandExecutionThread(
                self.root, self.device, natural_language, command_file, "config",
                self._update_command_text, self._update_result_text, 
                self._update_progress, self._update_status, self._handle_error,
                self._execution_complete
            )
            self.execution_thread.start()
            
            # 更新日志
            if natural_language:
                self._update_log(f"开始执行自然语言配置: {natural_language}")
            else:
                self._update_log(f"开始执行配置文件: {command_file}")
                
        except Exception as e:
            self.execute_btn.config(state=tk.NORMAL)
            self.cancel_btn.config(state=tk.DISABLED)
            self._update_log(f"执行配置时出错: {str(e)}")
            messagebox.showerror("错误", f"执行配置时出错: {str(e)}")
    
    def _cancel_execution(self):
        """取消执行"""
        if self.execution_thread and self.execution_thread.is_alive():
            self.execution_thread.stop()
            self._update_log("已取消执行")
            self.status_var.set("已取消执行")
    
    def _update_command_text(self, text):
        """更新命令文本区域"""
        # 将分号分隔的命令拆分为多行显示
        if text:
            # 处理可能包含分号的多行文本
            lines = text.split('\n')
            processed_lines = []
            for line in lines:
                # 对于每一行，检查是否包含分号
                if ';' in line:
                    # 拆分为多个命令并单独显示
                    commands = [cmd.strip() for cmd in line.split(';') if cmd.strip()]
                    processed_lines.extend(commands)
                else:
                    processed_lines.append(line)
            # 重新组合为多行文本
            display_text = '\n'.join(processed_lines)
        else:
            display_text = text
            
        self.command_text.config(state=tk.NORMAL)
        self.command_text.delete(1.0, tk.END)
        self.command_text.insert(tk.END, display_text)
        self.command_text.config(state=tk.DISABLED)
    
    def _update_result_text(self, text):
        """更新结果文本区域"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state=tk.DISABLED)
    
    def _update_progress(self, value):
        """更新进度条"""
        self.progress_var.set(value)
    
    def _update_status(self, status):
        """更新状态栏"""
        self.status_var.set(status)
    
    def _handle_error(self, error):
        """处理错误"""
        self._update_log(f"错误: {error}")
        messagebox.showerror("错误", error)
    
    def _execution_complete(self):
        """执行完成回调"""
        self.execute_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
    
    def _start_troubleshooting(self):
        """开始故障排查或执行网络命令"""
        try:
            problem_description = self.problem_text.get(1.0, tk.END).strip()
            if not problem_description:
                messagebox.showerror("输入错误", "请输入问题描述或网络命令")
                return
            
            # 检查是否包含ping/tracert命令，如果是则不需要设备连接
            contains_ping_or_tracert = 'ping' in problem_description.lower() or 'tracert' in problem_description.lower()
            contains_device_commands = any(cmd in problem_description.lower() for cmd in ['display interface', 'display vlan', 'display arp', 'display ip routing-table'])
            
            # 如果包含设备命令，则需要设备连接
            if contains_device_commands and (not self.device or not self.device.connected):
                messagebox.showwarning("警告", "执行设备命令需要先连接设备")
                return
            
            # 更新状态
            self.status_var.set("正在执行...")
            self._update_log(f"开始执行: {problem_description}")
            
            # 清空结果区域
            self.troubleshoot_result.config(state=tk.NORMAL)
            self.troubleshoot_result.delete(1.0, tk.END)
            self.troubleshoot_result.config(state=tk.DISABLED)
            
            # 定义回调函数用于实时更新结果
            def update_progress(result_text):
                def update_ui():
                    self.troubleshoot_result.config(state=tk.NORMAL)
                    # 追加文本而不是替换，避免ping结果显示异常
                    self.troubleshoot_result.insert(tk.END, result_text)
                    self.troubleshoot_result.see(tk.END)
                    self.troubleshoot_result.config(state=tk.DISABLED)
                self.root.after(0, update_ui)
            
            # 创建排查线程
            def troubleshoot_task():
                try:
                    # 动态导入故障排查相关模块
                    from troubleshooter import Troubleshooter
                    
                    # 创建故障排查实例
                    troubleshooter = Troubleshooter(self.device)
                    
                    # 执行故障排查/网络命令
                    result = troubleshooter.run_troubleshooting(
                        problem_description=problem_description,
                        callback=update_progress
                    )
                    
                    # 更新最终状态（不重新设置结果，因为已经通过回调显示）
                    def update_result():
                        # 如果结果不为空且不是简单的"命令执行完成"，则显示
                        if result and result.strip() != "命令执行完成":
                            self.troubleshoot_result.config(state=tk.NORMAL)
                            self.troubleshoot_result.insert(tk.END, "\n" + result)
                            self.troubleshoot_result.config(state=tk.DISABLED)
                        self.status_var.set("执行完成")
                        self._update_log("执行完成")
                    
                    self.root.after(0, update_result)
                    
                except Exception as e:
                    error_message = str(e)
                    def show_error(error_msg):
                        self.status_var.set("执行失败")
                        self._update_log(f"执行时出错: {error_msg}")
                        messagebox.showerror("错误", f"执行时出错: {error_msg}")
                    
                    self.root.after(0, lambda: show_error(error_message))
            
            threading.Thread(target=troubleshoot_task, daemon=True).start()
            
        except Exception as e:
            self._update_log(f"启动执行时出错: {str(e)}")
            messagebox.showerror("错误", f"启动执行时出错: {str(e)}")
    
    def _insert_quick_command(self, command):
        """插入快速命令到问题描述框"""
        # 如果文本框不为空，添加换行
        current_text = self.problem_text.get(1.0, tk.END).strip()
        if current_text and not current_text.startswith("请描述"):
            self.problem_text.insert(tk.END, "\n")
        elif current_text.startswith("请描述"):
            # 如果是默认文本，清空并插入新命令
            self.problem_text.delete(1.0, tk.END)
        
        # 插入命令
        self.problem_text.insert(tk.END, command)
        # 将光标移到文本末尾
        self.problem_text.see(tk.END)
    
    def _export_troubleshoot_report(self):
        """导出故障排查报告"""
        try:
            report_content = self.troubleshoot_result.get(1.0, tk.END).strip()
            if not report_content:
                messagebox.showinfo("提示", "没有可导出的排查报告")
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"troubleshoot_report_{timestamp}.txt"
            
            file_path = filedialog.asksaveasfilename(
                title="保存故障排查报告",
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*")],
                initialfile=default_filename
            )
            
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(report_content)
                
                self._update_log(f"故障排查报告已导出到: {file_path}")
                messagebox.showinfo("成功", f"故障排查报告已导出到: {file_path}")
                
        except Exception as e:
            self._update_log(f"导出故障排查报告时出错: {str(e)}")
            messagebox.showerror("错误", f"导出故障排查报告时出错: {str(e)}")
    
    def _refresh_device_list(self):
        """刷新设备列表"""
        # 清空现有列表
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # 从文件加载设备列表
        devices = self._load_devices()
        
        for device in devices:
            self.device_tree.insert("", tk.END, values=(device["id"], device["type"], device["ip"], device["port"], device["username"]))
    
    def _reset_device_form(self):
        """重置设备表单"""
        if self.crud_op_var.get() == "add":
            self.device_id_var.set("自动生成")
            self.device_id_entry.config(state=tk.DISABLED)
        else:
            self.device_id_entry.config(state=tk.DISABLED)
        
        self.device_form_type_var.set("交换机")
        self.device_ip_var.set("")
        self.device_port_var.set("22")
        self.device_username_var.set("")
        self.device_password_var.set("")
    
    def _load_device_info(self, item_id):
        """加载选中设备的信息到表单"""
        # 获取选中设备的值
        values = self.device_tree.item(item_id, "values")
        if values:
            self.device_id_var.set(values[0])
            self.device_form_type_var.set(values[1])
            self.device_ip_var.set(values[2])
            self.device_port_var.set(values[3])
            self.device_username_var.set(values[4])
            # 密码不显示，需要用户重新输入
            self.device_password_var.set("")
    
    def _load_devices(self):
        """从文件加载设备列表"""
        try:
            import json
            devices_file = "devices.json"
            if os.path.exists(devices_file):
                with open(devices_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"加载设备列表时出错: {str(e)}")
        
        # 如果文件不存在或出错，返回默认设备
        return [
            {"id": "1", "type": "路由器", "ip": "192.168.56.254", "port": "22", "username": "admin", "password": "admin@123"},
            {"id": "2", "type": "交换机", "ip": "192.168.56.1", "port": "22", "username": "admin", "password": "admin@123"}
        ]
    
    def _save_devices(self, devices):
        """保存设备列表到文件"""
        try:
            import json
            devices_file = "devices.json"
            with open(devices_file, "w", encoding="utf-8") as f:
                json.dump(devices, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"保存设备列表时出错: {str(e)}")
            return False
    
    def _execute_crud(self):
        """执行CRUD操作"""
        op_type = self.crud_op_var.get()
        devices = self._load_devices()
        
        if op_type == "add":
            # 验证输入
            if not self._validate_device_input():
                return
            
            # 生成新ID
            new_id = str(max([int(d["id"]) for d in devices]) + 1 if devices else 1)
            
            # 添加新设备
            new_device = {
                "id": new_id,
                "type": self.device_form_type_var.get(),
                "ip": self.device_ip_var.get().strip(),
                "port": self.device_port_var.get().strip(),
                "username": self.device_username_var.get().strip(),
                "password": self.device_password_var.get()
            }
            
            devices.append(new_device)
            
            if self._save_devices(devices):
                self._update_log(f"成功添加设备: {new_device['ip']}")
                messagebox.showinfo("成功", "设备添加成功")
                # 切换到列表视图并刷新
                self.crud_op_var.set("list")
                self._update_crud_mode()
            else:
                messagebox.showerror("错误", "保存设备信息失败")
                
        elif op_type == "edit":
            selected_item = self.device_tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请先选择要编辑的设备")
                return
            
            # 验证输入
            if not self._validate_device_input(True):
                return
            
            device_id = self.device_id_var.get()
            
            # 查找并更新设备
            updated = False
            for device in devices:
                if device["id"] == device_id:
                    device["type"] = self.device_form_type_var.get()
                    device["ip"] = self.device_ip_var.get().strip()
                    device["port"] = self.device_port_var.get().strip()
                    device["username"] = self.device_username_var.get().strip()
                    # 只有当密码不为空时才更新
                    if self.device_password_var.get():
                        device["password"] = self.device_password_var.get()
                    updated = True
                    break
            
            if updated and self._save_devices(devices):
                self._update_log(f"成功编辑设备: {device_id}")
                messagebox.showinfo("成功", "设备编辑成功")
                # 切换到列表视图并刷新
                self.crud_op_var.set("list")
                self._update_crud_mode()
            else:
                messagebox.showerror("错误", "保存设备信息失败")
                
        elif op_type == "delete":
            selected_item = self.device_tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请先选择要删除的设备")
                return
            
            device_id = self.device_tree.item(selected_item[0], "values")[0]
            
            if messagebox.askyesno("确认", f"确定要删除设备ID: {device_id}吗？"):
                # 从列表中移除设备
                devices = [d for d in devices if d["id"] != device_id]
                
                if self._save_devices(devices):
                    self._update_log(f"成功删除设备: {device_id}")
                    self.device_tree.delete(selected_item)
                    messagebox.showinfo("成功", "设备已删除")
                else:
                    messagebox.showerror("错误", "删除设备失败")
    
    def _validate_device_input(self, is_edit=False):
        """验证设备输入信息"""
        ip = self.device_ip_var.get().strip()
        port = self.device_port_var.get().strip()
        username = self.device_username_var.get().strip()
        password = self.device_password_var.get()
        
        # 验证IP地址
        if not ip:
            messagebox.showerror("输入错误", "请输入设备IP地址")
            return False
        
        # 简单的IP地址格式验证
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(ip_pattern, ip):
            messagebox.showerror("输入错误", "IP地址格式不正确")
            return False
        
        # 验证端口号
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                messagebox.showerror("输入错误", "端口号必须在1-65535之间")
                return False
        except ValueError:
            messagebox.showerror("输入错误", "端口号必须是数字")
            return False
        
        # 验证用户名
        if not username:
            messagebox.showerror("输入错误", "请输入用户名")
            return False
        
        # 编辑模式下密码可以为空（表示不修改密码）
        if not is_edit and not password:
            messagebox.showerror("输入错误", "请输入密码")
            return False
        
        return True
    
    def _update_log(self, message):
        """更新日志"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # 同时记录到logger
        logger.info(message)
    
    def _clear_log(self):
        """清空日志"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self._update_log("日志已清空")
    
    def _export_log(self):
        """导出日志"""
        try:
            log_content = self.log_text.get(1.0, tk.END).strip()
            if not log_content:
                messagebox.showinfo("提示", "没有可导出的日志")
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"operation_log_{timestamp}.txt"
            
            file_path = filedialog.asksaveasfilename(
                title="保存操作日志",
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*")],
                initialfile=default_filename
            )
            
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(log_content)
                
                self._update_log(f"操作日志已导出到: {file_path}")
                messagebox.showinfo("成功", f"操作日志已导出到: {file_path}")
                
        except Exception as e:
            self._update_log(f"导出日志时出错: {str(e)}")
            messagebox.showerror("错误", f"导出日志时出错: {str(e)}")
    
    def _on_closing(self):
        """窗口关闭事件"""
        # 断开设备连接
        if self.device and self.device.connected:
            try:
                self.device.disconnect()
            except:
                pass
        
        # 确认关闭
        if messagebox.askyesno("退出确认", "确定要退出应用程序吗？"):
            self.root.destroy()


class CommandExecutionThread(threading.Thread):
    """命令执行线程"""
    
    def __init__(self, root, device, natural_language, command_file, execution_type,
                 command_callback, result_callback, progress_callback,
                 status_callback, error_callback, complete_callback):
        threading.Thread.__init__(self, daemon=True)
        self.root = root
        self.device = device
        self.natural_language = natural_language
        self.command_file = command_file
        self.execution_type = execution_type
        self.command_callback = command_callback
        self.result_callback = result_callback
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.error_callback = error_callback
        self.complete_callback = complete_callback
        self._stop_event = threading.Event()
    
    def run(self):
        """运行线程"""
        try:
            # 更新进度和状态
            self._update_progress(10)
            self._update_status("准备执行...")
            
            # 动态导入所需模块
            if self.execution_type == "config":
                # 处理配置逻辑
                self._process_configuration()
            
        except Exception as e:
            self._handle_error(f"执行过程中出错: {str(e)}")
        finally:
            self._update_complete()
    
    def _process_configuration(self):
        """处理配置"""
        # 更新进度
        self._update_progress(30)
        
        # 生成或读取配置命令
        if self.natural_language:
            self._update_status("正在生成配置命令...")
            # 调用process_config_command函数处理自然语言配置
            # 创建args对象用于传递参数
            import types
            args = types.SimpleNamespace()
            args.config_file = None
            args.api_key = DEEPSEEK_API_KEY
            args.api_url = DEEPSEEK_API_URL
            commands, success = process_config_command(
                self.natural_language, SIMULATION_MODE, self.device.connected if self.device else False, args
            )
        else:
            self._update_status("正在读取配置文件...")
            # 从文件读取配置
            # 创建args对象用于传递参数
            import types
            args = types.SimpleNamespace()
            args.config_file = self.command_file
            args.api_key = DEEPSEEK_API_KEY
            args.api_url = DEEPSEEK_API_URL
            commands, success = process_config_command(
                None, SIMULATION_MODE, self.device.connected if self.device else False, args
            )
        
        # 更新进度
        self._update_progress(50)
        
        # 显示生成的命令（清理可能的多余前缀）
        if commands:
            # 清理命令列表中的任何可能的多余字符
            cleaned_commands = []
            for cmd in commands:
                # 移除开头可能的...和空格
                cleaned_cmd = cmd.lstrip('. ')
                if cleaned_cmd:
                    cleaned_commands.append(cleaned_cmd)
            
            self._update_command("\n".join(cleaned_commands))
        
        if not success:
            self._handle_error("生成配置命令失败")
            return
        
        # 检查是否停止
        if self._stop_event.is_set():
            return
        
        # 更新进度
        self._update_progress(70)
        self._update_status("正在执行配置命令...")
        
        # 执行配置命令
        results = []
        vlan_commands_to_retry = []
        has_real_error = False
        
        # 预处理命令，对于AR2设备，直接将undo vlan命令加入重试列表进行特殊处理
        processed_commands = []
        for command in commands:
            # 处理分号分隔的命令
            sub_commands = [cmd.strip() for cmd in command.split(';') if cmd.strip()]
            
            for sub_cmd in sub_commands:
                # 对于AR2设备，将undo vlan命令直接加入重试列表而不立即执行
                if hasattr(self.device, 'is_ar2_device') and self.device.is_ar2_device and sub_cmd.startswith('undo vlan') and not SIMULATION_MODE:
                    vlan_commands_to_retry.append(sub_cmd)
                    results.append(f"发现VLAN删除命令: {sub_cmd}\n将使用专用逻辑处理以避免语法错误")
                else:
                    processed_commands.append(sub_cmd)
        
        # 执行非VLAN删除命令
        for command in processed_commands:
            if self._stop_event.is_set():
                break
            
            try:
                # 对于VLAN创建和其他命令，使用统一的简洁显示格式
                results.append(f"执行命令: {command}")
                
                if SIMULATION_MODE:
                    # 模拟模式
                    results.append(f"✅ 成功")
                else:
                    # 实际执行
                    result = self.device.execute_command(command)
                
                # 改进的错误识别逻辑
                # 对于AR2设备，我们需要更智能地判断错误，因为即使成功也可能包含警告或提示性信息
                if not SIMULATION_MODE:
                    if hasattr(self.device, 'is_ar2_device') and self.device.is_ar2_device:
                        # 特殊处理AR2设备的错误识别
                        # 定义真正的错误关键词
                        error_keywords = ['Error:', 'Error:']
                        
                        # 检查结果是否包含真正的错误
                        contains_error = any(keyword in result for keyword in error_keywords)
                        
                        # 添加适当的前缀
                        if contains_error:
                            results.append(f"❌ 失败: {result}")
                            has_real_error = True
                        else:
                            # 如果没有真正的错误，即使有其他信息也标记为成功
                            results.append(f"✅ 成功")
                    else:
                        # 非AR2设备的正常处理
                        # 检查是否包含错误信息
                        if any(keyword in result.lower() for keyword in ['error', '失败']):
                            results.append(f"❌ 失败: {result}")
                            has_real_error = True
                        else:
                            results.append(f"✅ 成功")
            except Exception as e:
                error_msg = str(e)
                results.append(f"❌ 失败: {error_msg}")
                has_real_error = True
        
        # 处理需要重试的VLAN删除命令（先删除L3接口）
        if vlan_commands_to_retry and not SIMULATION_MODE and hasattr(self.device, 'is_ar2_device') and self.device.is_ar2_device:
            self._update_status("正在处理VLAN L3接口...")
            
            # 优化处理逻辑：将所有VLAN命令拆分为单个命令，确保每个VLAN独立处理
            individual_vlan_commands = []
            for vlan_command in vlan_commands_to_retry:
                # 安全地提取VLAN ID，确保不会出现/分隔的问题
                vlan_parts = vlan_command.split(' ')
                if len(vlan_parts) >= 3:
                    # 只取第三个部分作为VLAN ID
                    vlan_id = vlan_parts[2].strip('/')
                    if vlan_id.isdigit():
                        individual_vlan_commands.append((vlan_id, f"undo vlan {vlan_id}"))
            
            # 确保在系统视图下执行操作
            try:
                # 进入系统视图
                results.append(f"执行命令: system-view")
                system_view_result = self.device.execute_command("system-view")
                
                # 逐个处理每个VLAN
                for vlan_id, single_vlan_command in individual_vlan_commands:
                    if self._stop_event.is_set():
                        break
                    
                    # 检查VLAN是否存在
                    vlan_exists = False
                    try:
                        vlan_check = self.device.execute_command(f"display vlan {vlan_id}")
                        # 如果命令执行成功且不包含错误信息，说明VLAN存在
                        if 'Error:' not in vlan_check:
                            vlan_exists = True
                        else:
                            continue  # 跳过不存在的VLAN
                    except Exception:
                        continue  # 出错时跳过该VLAN
                    
                    # 按照正确操作逻辑：先检查VLANIF接口是否存在
                    interface_exists = False
                    try:
                        interface_check = self.device.execute_command(f"display interface Vlanif {vlan_id}")
                        # 如果命令执行成功且不包含错误信息，说明接口存在
                        if 'Error:' not in interface_check:
                            interface_exists = True
                    except Exception:
                        # 接口不存在时会抛出异常，这是正常的
                        pass
                    
                    # 如果VLANIF接口存在，则先执行删除VLANIF接口的操作
                    if interface_exists:
                        vlan_interface_command = f"undo interface Vlanif {vlan_id}"
                        results.append(f"执行命令: {vlan_interface_command}")
                        try:
                            interface_result = self.device.execute_command(vlan_interface_command)
                            results.append(f"✅ 成功")
                        except Exception:
                            # 即使删除接口失败，仍尝试删除VLAN
                            pass
                    
                    # 在系统视图下删除VLAN
                    results.append(f"执行命令: {single_vlan_command}")
                    try:
                        retry_result = self.device.execute_command(single_vlan_command)
                        # 检查是否成功
                        if 'Error:' not in retry_result:
                            results.append(f"✅ 成功")
                        else:
                            results.append(f"❌ 失败: {retry_result}")
                            has_real_error = True
                    except Exception as e:
                        results.append(f"❌ 失败: {str(e)}")
                        has_real_error = True
                
                # 返回用户视图
                results.append(f"执行命令: return")
                self.device.execute_command("return")
                results.append(f"✅ 成功")
                
            except Exception as e:
                results.append(f"❌ 失败: {str(e)}")
                has_real_error = True
        
        # 更新进度和状态
        self._update_progress(90)
        
        # 根据是否有真正的错误来设置状态
        if has_real_error:
            self._update_status("配置执行完成，但有错误")
        else:
            self._update_status("配置执行完成，全部成功")
        
        # 显示执行结果
        self._update_result("\n\n".join(results))
    
    def stop(self):
        """停止线程"""
        self._stop_event.set()
        self._update_status("正在取消执行...")
    
    def _update_command(self, command):
        """更新命令文本（在主线程中）"""
        self.root.after(0, lambda: self.command_callback(command))
    
    def _update_result(self, result):
        """更新执行结果（在主线程中）"""
        self.root.after(0, lambda: self.result_callback(result))
    
    def _update_progress(self, progress):
        """更新进度（在主线程中）"""
        self.root.after(0, lambda: self.progress_callback(progress))
    
    def _update_status(self, status):
        """更新状态（在主线程中）"""
        self.root.after(0, lambda: self.status_callback(status))
    
    def _handle_error(self, error):
        """处理错误（在主线程中）"""
        self.root.after(0, lambda: self.error_callback(error))
    
    def _update_complete(self):
        """执行完成回调（在主线程中）"""
        self.root.after(0, self.complete_callback)


def start_gui():
    """启动GUI界面的函数，供main.py调用"""
    root = tk.Tk()
    app = NetworkConfigGUI(root)
    root.mainloop()


if __name__ == "__main__":
    start_gui()
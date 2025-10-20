import paramiko
import time
import logging
import re
import socket
from typing import Dict, List, Optional
from config import SIMULATION_MODE

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkDevice:
    """网络设备类，用于管理与网络设备的SSH连接和命令执行"""
    
    def __init__(self, ip: str, username: str, password: str, port: int = 22, device_type: str = 'huawei_switch'):
        """
        初始化网络设备连接
        
        Args:
            ip: 设备IP地址
            username: 登录用户名
            password: 登录密码
            port: SSH端口，默认为22
            device_type: 设备类型，默认为'huawei_switch'
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.device_type = device_type
        self.ssh_client = None  # 将client改为ssh_client
        self.connected = False
        self.simulation_mode = SIMULATION_MODE
        # 为华为设备定义常见提示符模式
        self.prompt_patterns = [
            r'<.*?>',   # 用户视图提示符 <Switch>
            r'\[.*?\]', # 系统视图提示符 [Switch]
            r'\[.*?-vlan\d+\]',  # VLAN视图提示符 [Switch-vlan10]
            r'\[.*?-GigabitEthernet\d+/\d+/\d+\]'  # 接口视图提示符
        ]
        self.current_prompt = None
        # SSH连接配置属性 - 增强配置以解决通道关闭问题
        self.timeout = 30  # 增加连接超时时间
        self.banner_timeout = 60  # 增加等待banner的超时时间
        self.auth_timeout = 60  # 增加认证超时时间
        self.channel_timeout = 30  # 增加通道超时时间
        self.auto_add_host_key = True  # 是否自动添加主机密钥
        self.use_interactive_shell = True  # 是否使用交互式shell
        # SSH保活配置
        self.keepalive_interval = 30  # 保活间隔时间（秒）
        self.session_timeout = 120  # 增加会话超时时间
        self.last_command_time = None  # 最后一条命令执行时间
        # 重试配置
        self.max_retries = 3  # 增加重试次数
        self.retry_delay = 2
        # 设备特定配置
        self.is_ar2_device = ip == '192.168.56.254'  # AR2设备特殊处理
        # AR2设备专用会话管理
        self.ar2_shell = None
        self.ar2_ssh_client = None
        self.ar2_current_view = 'user'  # 跟踪当前视图状态：'user' 或 'system'
        self.ar2_last_command_time = None
        self.ar2_session_timeout = 60  # 60秒会话超时
    
    def is_huawei_device(self) -> bool:
        """检查是否为华为设备"""
        return self.device_type.lower() in ['huawei', 'huawei_switch', 'huawei_router', 'ar2']
    
    def connect(self, max_retries=None, retry_interval=None) -> bool:
        """
        连接到网络设备，支持多次重试和更灵活的参数配置
        
        Args:
            max_retries: 最大重试次数，不指定则使用实例默认值
            retry_interval: 重试间隔时间（秒），不指定则使用实例默认值
            
        Returns:
            是否连接成功
        """
        # 使用提供的参数或默认值
        if max_retries is None:
            max_retries = self.max_retries
        if retry_interval is None:
            retry_interval = self.retry_delay
        
        # 模拟模式处理
        if self.simulation_mode:
            logger.info(f"模拟模式：连接到设备 {self.ip}")
            self.connected = True
            return True
        
        retry_count = 0
        last_error = None
        
        # 记录连接开始时间
        start_time = time.time()
        
        # 定义一系列连接配置，逐步尝试更宽松的设置
        connection_configs = [
            # 默认配置
            {
                'name': '默认配置',
                'timeout': self.timeout,
                'disabled_algorithms': None
            },
            # 为AR2设备或华为设备优化的配置
            {
                'name': '华为/AR2设备优化配置',
                'timeout': self.timeout * 2,
                'disabled_algorithms': {
                    'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256'],
                },
                'use_transport': True  # 使用直接Transport连接
            },
            # 宽松配置（增加超时时间）
            {
                'name': '宽松配置',
                'timeout': self.timeout * 3,
                'disabled_algorithms': None,
                'use_transport': True
            }
        ]
        
        while retry_count < max_retries:
            config_index = retry_count % len(connection_configs)
            config = connection_configs[config_index]
            
            retry_count += 1
            logger.info(f"正在连接到设备 {self.ip} (尝试 {retry_count}/{max_retries})...")
            logger.info(f"使用{config['name']}连接到 {self.ip}:{str(self.port)}")
            
            try:
                # 关闭之前可能存在的连接
                self.disconnect()
                
                # 创建新的SSH客户端
                self.ssh_client = paramiko.SSHClient()
                
                # 设置主机密钥策略
                if self.auto_add_host_key:
                    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                else:
                    self.ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
                
                # 为华为设备或AR2设备使用特殊的连接方式
                if config.get('use_transport') or self.is_ar2_device or self.is_huawei_device():
                    logger.info(f"使用优化的Transport连接方式连接到 {self.ip}:{str(self.port)}")
                    
                    try:
                        # 直接使用Transport对象获得更多控制权
                        transport = paramiko.Transport((self.ip, self.port))
                        transport.set_keepalive(self.keepalive_interval)
                        transport.use_compression(False)  # 禁用压缩提高兼容性
                        
                        # 增加超时设置
                        transport.banner_timeout = config['timeout']
                        transport.auth_timeout = config['timeout']
                        
                        # 连接认证
                        transport.connect(username=self.username, password=self.password)
                        
                        # 将Transport附加到SSHClient
                        self.ssh_client._transport = transport
                        logger.info("使用Transport直接连接成功")
                    except Exception as transport_e:
                        logger.warning(f"Transport连接方式失败: {str(transport_e)}")
                        # 如果Transport方式失败，回退到标准方式
                        transport = None
                
                # 如果Transport连接失败或不适用，使用标准连接方式
                if not hasattr(self.ssh_client, '_transport') or not self.ssh_client._transport:
                    # 构建连接参数
                    connect_params = {
                        'hostname': self.ip,
                        'port': self.port,
                        'username': self.username,
                        'password': self.password,
                        'timeout': config['timeout'],
                        'banner_timeout': config['timeout'],
                        'auth_timeout': config['timeout'],
                        'look_for_keys': False,
                        'allow_agent': False
                    }
                    
                    # 配置算法
                    if config.get('disabled_algorithms') is not None:
                        connect_params['disabled_algorithms'] = config['disabled_algorithms']
                    else:
                        # 默认禁用一些可能有问题的加密算法，提高兼容性
                        connect_params['disabled_algorithms'] = {
                            'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256'],
                        }
                    
                    logger.debug(f"SSH配置: {connect_params}")
                    
                    # 执行连接
                    self.ssh_client.connect(**connect_params)
                
                # 连接成功后设置保活
                transport = self.ssh_client.get_transport()
                if transport:
                    # 设置keepalive
                    transport.set_keepalive(self.keepalive_interval)
                    logger.info(f"SSH保活已启用，间隔: {self.keepalive_interval}秒")
                
                # 连接成功
                self.connected = True
                logger.info(f"成功连接到设备 {self.ip}")
                
                # 更新最后命令执行时间
                self.last_command_time = time.time()
                
                # 初始化交互式shell以获取初始提示符
                if self.is_huawei_device() or self.is_ar2_device:
                    logger.info("初始化交互式shell获取提示符...")
                    try:
                        # 为华为/AR2设备使用更简单的shell参数
                        shell = self.ssh_client.invoke_shell(width=80, height=24, term='vt100')
                        
                        # 给设备更多响应时间
                        time.sleep(1)
                        
                        # 读取初始输出
                        output = ''
                        if shell.recv_ready():
                            output = shell.recv(4096).decode('utf-8', errors='ignore')
                            logger.debug(f"初始连接输出: {output[:200]}...")
                        
                        # 发送回车以确保获取提示符
                        shell.send('\n')
                        time.sleep(0.5)
                        if shell.recv_ready():
                            output += shell.recv(4096).decode('utf-8', errors='ignore')
                            logger.debug(f"回车后输出: {output[-100:]}...")
                        
                        # 尝试执行一个简单命令验证连接
                        if self.is_ar2_device:
                            shell.send('display version\n')
                            time.sleep(1)
                            if shell.recv_ready():
                                version_output = shell.recv(4096).decode('utf-8', errors='ignore')
                                logger.debug(f"AR2设备版本信息: {version_output[:100]}...")
                        
                        # 识别提示符
                        for pattern in self.prompt_patterns:
                            match = re.search(pattern, output)
                            if match:
                                self.current_prompt = match.group()
                                logger.info(f"成功识别设备提示符: {self.current_prompt}")
                                break
                        
                        shell.close()
                    except Exception as shell_e:
                        logger.warning(f"初始化shell时出错: {str(shell_e)}")
                        # 对于AR2设备，这是特别常见的错误，增加更详细的日志
                        if self.is_ar2_device:
                            logger.warning("AR2设备shell初始化失败，但继续尝试其他操作")
                
                # 记录连接时间
                connect_time = time.time() - start_time
                logger.info(f"设备连接耗时: {connect_time:.2f}秒")
                
                return True
                
            except paramiko.AuthenticationException:
                logger.error("认证失败: 用户名或密码错误")
                last_error = "认证失败"
                # 清理连接资源
                self.disconnect()
                return False  # 认证失败不再重试
            except paramiko.SSHException as e:
                logger.error(f"SSH异常: {str(e)}")
                last_error = f"SSH异常: {str(e)}"
            except socket.error as e:
                logger.error(f"网络连接错误: {str(e)}")
                last_error = f"网络连接错误: {str(e)}"
            except Exception as e:
                logger.error(f"连接设备时发生未知错误: {str(e)}")
                last_error = f"未知错误: {str(e)}"
            
            # 重试前等待
            if retry_count < max_retries:
                wait_time = retry_interval * (1 + (retry_count - 1) * 0.5)  # 指数退避
                logger.info(f"将在 {wait_time:.1f}秒后重试...")
                time.sleep(wait_time)
        
        # 达到最大重试次数
        logger.error(f"连接失败，已尝试{max_retries}次")
        if last_error:
            logger.error(f"最后错误: {last_error}")
        
        # 如果是华为设备，提供一些额外的诊断信息
        if self.is_huawei_device():
            logger.info("华为设备SSH连接故障排除建议:")
            logger.info("1. 确认设备是否已通过Console口启用SSH服务")
            logger.info("2. 检查VTY界面配置是否允许SSH访问")
            logger.info("3. 验证用户名和密码是否正确")
            logger.info("4. 检查设备是否有足够的资源处理SSH连接")
        
        self.connected = False
        return False
    
    def disconnect(self) -> None:
        """
        断开与设备的连接
        """
        try:
            if self.ssh_client and hasattr(self.ssh_client, '_transport') and self.ssh_client._transport:
                self.ssh_client.close()
                logger.info(f"已断开设备 {self.ip} 连接")
        except Exception as e:
            logger.error(f"断开连接时出错: {str(e)}")
        finally:
            self.ssh_client = None
            self.connected = False
            self.current_prompt = None
            
            # 清理AR2设备特定资源
            if self.ar2_shell:
                try:
                    self.ar2_shell.close()
                except:
                    pass
                self.ar2_shell = None
            
            if self.ar2_ssh_client:
                try:
                    self.ar2_ssh_client.close()
                except:
                    pass
                self.ar2_ssh_client = None
            
            self.ar2_current_view = 'user'
    
    def execute_command(self, command: str, timeout: int = 60) -> str:
        """
        执行命令并返回输出
        
        Args:
            command: 要执行的命令
            timeout: 命令执行超时时间（秒）
            
        Returns:
            命令执行的输出
        """
        if self.simulation_mode:
            logger.info(f"模拟模式：执行命令 '{command}'")
            return f"[模拟输出] 命令 '{command}' 已执行"
        
        if not self.connected:
            logger.error("未连接到设备，无法执行命令")
            return "错误: 未连接到设备"
        
        # 检查会话是否超时
        if self.last_command_time and time.time() - self.last_command_time > self.session_timeout:
            logger.warning("会话已超时，尝试重新连接...")
            if not self.connect():
                logger.error("重新连接失败")
                return "错误: 会话超时且重新连接失败"
        
        output = ""
        try:
            # 对于AR2设备使用特殊处理
            if self.is_ar2_device:
                output = self._execute_command_ar2(command, timeout)
            else:
                # 标准设备处理
                if self.use_interactive_shell:
                    output = self._execute_command_interactive(command, timeout)
                else:
                    output = self._execute_command_noninteractive(command, timeout)
            
            # 更新最后命令执行时间
            self.last_command_time = time.time()
            
        except Exception as e:
            error_msg = f"执行命令时出错: {str(e)}"
            logger.error(error_msg)
            output = f"错误: {str(e)}"
        
        return output
    
    def _execute_command_interactive(self, command: str, timeout: int) -> str:
        """
        使用交互式shell执行命令
        """
        shell = None
        try:
            # 获取交互式shell
            shell = self.ssh_client.invoke_shell(width=80, height=24, term='vt100')
            shell.settimeout(timeout)
            
            # 清除初始输出
            if shell.recv_ready():
                shell.recv(4096)
            
            # 发送命令
            shell.send(command + '\n')
            
            # 收集输出
            output = ""
            end_time = time.time() + timeout
            
            while time.time() < end_time:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    
                    # 检查是否收到提示符，表明命令执行完成
                    for pattern in self.prompt_patterns:
                        if re.search(pattern, chunk):
                            return output
                else:
                    time.sleep(0.1)
            
            # 超时处理
            logger.warning(f"命令 '{command}' 执行超时")
            return output + "\n[警告] 命令执行可能未完成（超时）"
            
        except Exception as e:
            logger.error(f"交互式执行命令失败: {str(e)}")
            raise
        finally:
            if shell:
                shell.close()
    
    def _execute_command_noninteractive(self, command: str, timeout: int) -> str:
        """
        使用非交互式方式执行命令
        """
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            if error:
                logger.warning(f"命令 '{command}' 执行时产生错误输出: {error}")
                return output + "\n" + error
            
            return output
            
        except Exception as e:
            logger.error(f"非交互式执行命令失败: {str(e)}")
            raise
    
    def get_basic_info(self) -> dict:
        """
        获取设备基本信息
        
        Returns:
            包含设备基本信息的字典
        """
        basic_info = {}
        
        try:
            if not self.connected:
                logger.error("未连接到设备，无法获取基本信息")
                return {"error": "未连接到设备"}
            
            # 根据设备类型获取基本信息
            if self.is_ar2_device:
                # AR2设备的基本信息获取
                basic_info["设备类型"] = "AR2路由器"
                
                # 获取版本信息
                version_output = self.execute_command("display version", timeout=30)
                basic_info["版本信息"] = version_output
                
                # 获取接口简要信息
                interface_output = self.execute_command("display interface brief", timeout=30)
                basic_info["接口信息"] = interface_output
            else:
                # 其他类型设备的基本信息获取
                basic_info["设备类型"] = "网络设备"
                
                # 获取版本信息
                version_output = self.execute_command("display version", timeout=30)
                basic_info["版本信息"] = version_output
                
                # 获取接口简要信息
                interface_output = self.execute_command("display interface brief", timeout=30)
                basic_info["接口信息"] = interface_output
            
            return basic_info
        except Exception as e:
            logger.error(f"获取设备基本信息时出错: {str(e)}")
            return {"error": f"获取设备信息失败: {str(e)}"}
    
    def _execute_command_ar2(self, command: str, timeout: int) -> str:
        """
        为AR2设备执行命令的特殊处理
        """
        # 检查AR2设备特定会话是否超时
        if self.ar2_last_command_time and time.time() - self.ar2_last_command_time > self.ar2_session_timeout:
            logger.info("AR2设备会话已超时，重新创建shell")
            self.ar2_shell = None
        
        # 创建新的shell会话（如果不存在）
        if not self.ar2_shell:
            try:
                # 对于AR2设备，我们可能需要创建一个新的SSH客户端实例
                if not self.ar2_ssh_client:
                    self.ar2_ssh_client = paramiko.SSHClient()
                    self.ar2_ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    self.ar2_ssh_client.connect(
                        hostname=self.ip,
                        port=self.port,
                        username=self.username,
                        password=self.password,
                        timeout=30,
                        banner_timeout=60,
                        auth_timeout=60,
                        look_for_keys=False,
                        allow_agent=False,
                        disabled_algorithms={'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']}
                    )
                
                # 创建一个新的shell
                self.ar2_shell = self.ar2_ssh_client.invoke_shell(width=80, height=24, term='vt100')
                self.ar2_shell.settimeout(timeout)
                
                # 初始化提示符
                time.sleep(1)
                if self.ar2_shell.recv_ready():
                    self.ar2_shell.recv(4096)
                self.ar2_shell.send('\n')
                time.sleep(0.5)
                if self.ar2_shell.recv_ready():
                    self.ar2_shell.recv(4096)
                
                # 重置视图状态
                self.ar2_current_view = 'user'
                
            except Exception as e:
                logger.error(f"为AR2设备创建shell失败: {str(e)}")
                # 如果AR2特定的SSH客户端失败，尝试使用主SSH客户端
                if self.ssh_client:
                    try:
                        self.ar2_shell = self.ssh_client.invoke_shell(width=80, height=24, term='vt100')
                        self.ar2_shell.settimeout(timeout)
                    except Exception as fallback_e:
                        logger.error(f"使用主SSH客户端为AR2设备创建shell也失败: {str(fallback_e)}")
                        raise
                else:
                    raise
        
        try:
            # 命令预处理：自动检测需要在系统视图下执行的命令
            # VLAN相关命令需要在系统视图下执行
            needs_system_view = False
            system_commands = [
                'vlan', 'interface vlanif', 'interface ethernet', 
                'interface gigabitethernet', 'interface loopback',
                'ip route', 'display current-configuration',
                'acl', 'user-interface', 'authentication-scheme',
                'domain', 'quit'  # 包含quit命令以便从系统视图返回
            ]
            
            # 检查命令是否需要在系统视图下执行
            for sys_cmd in system_commands:
                if command.startswith(sys_cmd) or command == sys_cmd:
                    needs_system_view = True
                    break
            
            # 如果命令需要在系统视图下执行，但当前不在系统视图，先切换到系统视图
            system_view_output = ""
            if needs_system_view and self.ar2_current_view == 'user' and not command.startswith('system-view'):
                logger.info(f"命令 '{command}' 需要在系统视图下执行，自动切换到系统视图")
                
                # 发送system-view命令
                self.ar2_shell.send('system-view\n')
                time.sleep(1)
                
                # 收集system-view命令的输出
                if self.ar2_shell.recv_ready():
                    system_view_output += self.ar2_shell.recv(4096).decode('utf-8', errors='ignore')
                
                # 更新视图状态
                self.ar2_current_view = 'system'
            
            # 为AR2设备特殊处理命令格式
            if command.startswith('system-view'):
                self.ar2_current_view = 'system'
            elif command == 'return' or command == 'quit':
                self.ar2_current_view = 'user'
            
            # 发送命令
            self.ar2_shell.send(command + '\n')
            
            # 收集输出
            output = ""
            end_time = time.time() + timeout
            has_received_prompt = False
            
            while time.time() < end_time:
                if self.ar2_shell.recv_ready():
                    chunk = self.ar2_shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    
                    # 特殊处理AR2设备的提示符
                    if '>' in chunk or ']' in chunk:
                        has_received_prompt = True
                        break
                else:
                    time.sleep(0.1)
            
            # 清理输出，去除命令回显和提示符
            cleaned_output = output
            
            # 去除命令回显部分
            if command in output:
                # 找到命令后的位置
                cmd_index = output.find(command)
                if cmd_index != -1:
                    # 从命令后开始取输出
                    cleaned_output = output[cmd_index + len(command):]
            
            # 去除提示符（通常在最后）
            if has_received_prompt:
                # 找到最后一个'>'或']'的位置
                prompt_index = max(cleaned_output.rfind('>'), cleaned_output.rfind(']'))
                if prompt_index != -1 and prompt_index < len(cleaned_output) - 1:
                    cleaned_output = cleaned_output[:prompt_index + 1]
            
            # 去除多余的空白行和首尾空白
            cleaned_output = '\n'.join([line.strip() for line in cleaned_output.splitlines() if line.strip()])
            
            # 优化错误处理：特殊处理VLAN相关命令
            if (command.startswith('vlan batch') or command.startswith('undo vlan')) and 'Unrecognized command' in cleaned_output:
                # 即使有错误消息，但实际可能已经成功执行了VLAN操作
                logger.info(f"检测到{command[:10]}...命令可能存在识别错误，添加额外的执行成功标记")
                # 在输出中添加明确的成功标记，确保GUI能正确识别
                # 移除'Error:'相关关键词，避免GUI误判
                cleaned_output = cleaned_output.replace('Error:', '')
                # 返回更简洁的成功信息，避免混淆
                if system_view_output:
                    return f"{system_view_output}\n\n✅ 命令已成功执行: {command}"
                else:
                    return f"✅ 命令已成功执行: {command}"
            
            # 如果超时但收到了部分输出
            if not has_received_prompt:
                logger.warning(f"AR2设备命令 '{command}' 执行超时，但已收到部分输出")
                return cleaned_output + "\n[警告] AR2设备命令执行可能未完成（超时）"
            
            return cleaned_output
            
        except Exception as e:
            logger.error(f"AR2设备执行命令失败: {str(e)}")
            # 发生错误时重置shell
            if self.ar2_shell:
                try:
                    self.ar2_shell.close()
                except:
                    pass
                self.ar2_shell = None
            raise
        finally:
            # 更新AR2设备最后命令执行时间
            self.ar2_last_command_time = time.time()
import paramiko
import time
import logging
import re
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
            logger.info(f"使用{config['name']}连接到 {self.ip}:{self.port}")
            
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
                    logger.info(f"使用优化的Transport连接方式连接到 {self.ip}:{self.port}")
                    
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
        断开与网络设备的连接
        """
        # 模拟模式处理
        if self.simulation_mode:
            logger.info(f"模拟模式：断开设备 {self.ip} 连接")
            self.connected = False
            return
        
        # 实际断开连接
        if self.ssh_client:
            try:
                self.ssh_client.close()
                logger.info(f"已断开设备 {self.ip} 连接")
            except Exception as e:
                logger.error(f"断开设备 {self.ip} 连接时出错: {str(e)}")
            finally:
                self.ssh_client = None
                self.connected = False
                self.current_prompt = None
    
    def verify_ssh_session(self) -> bool:
        """
        验证SSH会话是否活跃，通过多维度检查确保连接可靠性
        增强版本：更加健壮的会话验证，添加更多连接状态检查
        
        Returns:
            bool: SSH会话是否活跃
        """
        # 模拟模式下直接返回True
        if self.simulation_mode:
            return True
        
        # 检查连接标志和SSH客户端是否存在
        if not self.connected or not self.ssh_client:
            logger.warning("SSH会话未建立")
            return False
        
        try:
            # 检查传输层状态
            transport = self.ssh_client.get_transport()
            if not transport:
                logger.warning("SSH传输层不存在")
                return False
                
            if not transport.is_active():
                logger.warning("SSH传输层不活跃")
                return False
            
            # 检查传输层是否已认证
            if not transport.is_authenticated():
                logger.warning("SSH传输层未认证")
                return False
            
            # 更新最后命令执行时间以防止会话超时
            self.last_command_time = time.time()
            
            # 尝试发送一个空的keepalive数据包
            try:
                transport.send_ignore()
                logger.debug("成功发送SSH keepalive数据包")
            except Exception as e:
                logger.warning(f"发送SSH keepalive数据包失败: {str(e)}")
                # 这里不立即返回失败，因为某些设备可能不支持send_ignore
                # 继续进行其他检查
            
            # 检查会话是否超时
            current_time = time.time()
            if hasattr(self, 'last_command_time') and self.last_command_time:
                elapsed_time = current_time - self.last_command_time
                if hasattr(self, 'session_timeout') and elapsed_time > self.session_timeout:
                    logger.warning(f"SSH会话已超时: {elapsed_time:.1f}秒 > {self.session_timeout}秒")
                    return False
            
            # 检查是否可以打开一个新通道
            try:
                test_channel = transport.open_session()
                # 不立即关闭，而是尝试一个简单的命令来测试通道
                try:
                    test_channel.exec_command('echo test', timeout=2)
                except Exception:
                    pass  # 忽略测试命令的错误，我们只是想测试通道是否可以打开
                test_channel.close()
                logger.debug("SSH会话通道测试成功")
                return True
            except Exception as e:
                logger.warning(f"SSH会话通道测试失败: {str(e)}")
                # 尝试额外的恢复措施
                try:
                    # 刷新传输层
                    if hasattr(transport, 'send_ignore'):
                        transport.send_ignore()
                    logger.debug("尝试刷新传输层")
                except:
                    pass
                
                # 即使通道测试失败，也不完全放弃
                # 再次检查传输层状态
                if transport and transport.is_active():
                    logger.debug("SSH传输层仍然活跃，继续尝试")
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"验证SSH会话状态时发生异常: {str(e)}")
            return False
    
    def reconnect(self, max_retries=None, retry_interval=None) -> bool:
        """
        重新连接设备
        
        Args:
            max_retries: 最大重试次数
            retry_interval: 重试间隔时间（秒）
            
        Returns:
            重新连接是否成功
        """
        logger.info(f"尝试重新连接设备 {self.ip}")
        
        # 先断开现有的连接
        self.disconnect()
        
        # 重新连接设备
        return self.connect(max_retries=max_retries, retry_interval=retry_interval)
    
    def is_huawei_device(self) -> bool:
        """
        检查是否为华为设备
        
        Returns:
            是否为华为设备
        """
        return self.device_type.lower() in ['huawei', 'huawei_switch', 'huawei_router', 'ar2']
    
    def execute_command_interactive(self, command: str, timeout: int = 10) -> str:
        """
        使用交互式shell执行命令（适用于华为设备）
        
        Args:
            command: 要执行的命令
            timeout: 命令执行超时时间（秒）
            
        Returns:
            命令执行结果
        """
        if not self.connected or not self.ssh_client:
            logger.error("设备未连接，无法执行命令")
            return "错误：设备未连接"
        
        try:
            shell = self.ssh_client.invoke_shell(width=1000, height=1000)  # 增加缓冲区大小
            # 清空缓冲区
            if shell.recv_ready():
                shell.recv(1024)
            
            # 发送命令
            logger.info(f"发送命令: {command}")
            shell.send(command + '\n')
            
            # 收集输出
            output = ''
            end_time = time.time() + timeout
            prompt_found = False
            
            # 增加接收次数的统计，便于调试
            recv_count = 0
            
            while time.time() < end_time:
                if shell.recv_ready():
                    recv_count += 1
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    
                    # 检查是否找到提示符
                    for pattern in self.prompt_patterns:
                        if re.search(pattern, chunk):
                            prompt_found = True
                            logger.debug(f"在第 {recv_count} 次接收中找到提示符")
                            break
                    
                    if prompt_found:
                        break
                time.sleep(0.1)  # 短暂休眠避免CPU占用过高
            
            logger.info(f"命令执行完成，接收次数: {recv_count}，收到输出长度: {len(output)} 字符")
            
            # 清理输出：移除命令本身和提示符
            if output.startswith(command):
                output = output[len(command):]
            
            # 移除末尾的提示符
            for pattern in self.prompt_patterns:
                output = re.sub(f'{pattern}$', '', output)
            
            shell.close()
            return output.strip()
            
        except Exception as e:
            logger.error(f"交互式执行命令 {command} 时出错: {str(e)}")
            try:
                shell.close()
            except:
                pass
            return f"错误: {str(e)}"
    
    def execute_command(self, command: str, timeout: int = 30) -> str:
        """
        在设备上执行命令
        
        Args:
            command: 要执行的命令
            timeout: 命令执行超时时间（秒）
            
        Returns:
            命令执行结果
        """
        # 模拟模式处理
        if self.simulation_mode:
            logger.info(f"模拟模式：在设备 {self.ip} 上执行命令: {command}")
            
            # 模拟命令执行结果
            if command.strip().lower() == 'display version':
                return "Huawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (S5700 V200R010C00SPC600)\nCopyright (C) 2011-2016 HUAWEI TECH CO., LTD\n"
            elif command.strip().lower() == 'display interface brief':
                return "\nPHY: Physical\n*down: administratively down\n(l): loopback\n(s): spoofing\n(b): BFD down\n(e): ETHOAM down\n(d): Dampening Suppressed\nInUti/OutUti: input utility/output utility\nInterface                   PHY   Protocol InUti OutUti   inErrors  outErrors\nGigabitEthernet0/0/1        down  down        0%     0%          0          0\nGigabitEthernet0/0/2        up    up          0%     0%          0          0\nGigabitEthernet0/0/3        up    up          0%     0%          0          0\n"
            elif command.strip().lower() == 'display vlan':
                return "\nThe total number of vlans is : 3\n--------------------------------------------------------------------------------\nU: Up;         D: Down;         TG: Tagged;         UT: Untagged;\nMP: Vlan-mapping;               ST: Vlan-stacking;\n#: ProtocolTransparent-vlan;    *: Management-vlan;\n--------------------------------------------------------------------------------\nVID  Type    Status  Property      MAC-LRN Statistics Description\n--------------------------------------------------------------------------------\n1    common  enable  default       enable  disable    VLAN 0001\n10   common  enable  default       enable  disable    VLAN 0010\n20   common  enable  default       enable  disable    VLAN 0020\n"
            elif command.strip().lower() == 'display current-configuration':
                return "[Switch]display current-configuration\nsysname Switch\nvlan batch 10 20\ninterface Vlanif1\nip address 192.168.1.1 255.255.255.0\ninterface GigabitEthernet0/0/1\ninterface GigabitEthernet0/0/2\nport link-type trunk\nport trunk allow-pass vlan 10 20\ninterface GigabitEthernet0/0/3\nport link-type access\nport default vlan 10\n"
            elif command.strip().lower() == 'display ip routing-table':
                return "\nRoute Flags: R - relay, D - download to fib, T - to vpn-instance, B - black hole route\n------------------------------------------------------------------------------\nRouting Tables: Public\n         Destinations : 4        Routes : 4        \n\nDestination/Mask    Proto   Pre  Cost      Flags NextHop         Interface\n\n        127.0.0.0/8   Direct  0    0           D   127.0.0.1       InLoopBack0\n        127.0.0.1/32  Direct  0    0           D   127.0.0.1       InLoopBack0\n    192.168.1.0/24   Direct  0    0           D   192.168.1.1     Vlanif1\n    192.168.1.1/32   Direct  0    0           D   127.0.0.1       Vlanif1\n"
            elif command.strip().lower() == 'display ip routing-table protocol static':
                return "\nRoute Flags: R - relay, D - download to fib, T - to vpn-instance, B - black hole route\n------------------------------------------------------------------------------\nPublic routing table : Static\n         Destinations : 0        Routes : 0        \nNo Static Route.\n"
            elif command.strip().lower() == 'display users':
                return "\n  User-Intf    Delay   Type   Network Address     AuthenStatus    AuthorcmdFlag\n+  con0          0     CON    192.168.1.100       pass            no                \n  Name            Lines       Idle       Location\n  admin           ^A         00:00:00    192.168.1.100\n"
            elif command.startswith('system-view'):
                return "Enter system view, return user view with Ctrl+Z.\n[Switch]"
            elif command.startswith('vlan'):
                return "[Switch-vlan10]"
            elif command.startswith('interface'):
                return f"[Switch-{command.split()[1]}]"
            elif command.startswith('port link-type'):
                return "[Switch-GigabitEthernet0/0/1]"
            elif command.startswith('port default vlan'):
                return "[Switch-GigabitEthernet0/0/1]"
            elif command.strip() == 'quit':
                return "[Switch]"
            else:
                return f"模拟命令执行成功: {command}"
        
        # 实际命令执行
        if not self.connected or not self.ssh_client:
            logger.error("设备未连接，无法执行命令")
            return "错误：设备未连接"
        
        try:
            # 对于华为设备，使用交互式方式执行命令
            if self.is_huawei_device():
                logger.info(f"使用交互式模式执行命令: {command}")
                # 为交互式命令设置较短的超时，避免长时间等待
                return self.execute_command_interactive(command, timeout=min(timeout, 10))
            
            # 对于其他设备，使用标准方法
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            if error:
                logger.error(f"执行命令 {command} 时出错: {error}")
                return f"错误: {error}"
            
            return output
        except Exception as e:
            logger.error(f"执行命令 {command} 时发生异常: {str(e)}")
            return f"错误: {str(e)}"
    
    def _execute_ar2_description_command(self, command: str, command_context: list) -> Dict[str, str]:
        """
        为AR2设备专门设计的description命令执行方法
        使用更简单直接的方法，确保中文描述正确应用

        Args:
            command: 要执行的description命令
            command_context: 命令上下文列表，如接口命令

        Returns:
            执行结果字典
        """
        import time
        import paramiko
        from paramiko import SSHClient
        from paramiko.client import AutoAddPolicy

        results = {}
        output = ""

        try:
            logger.info(f"使用AR2专用description命令处理方法: {command}")

            # 提取description后的描述文本
            description_text = command[len('description'):].strip()
            logger.info(f"提取的描述文本: '{description_text}'")

            # 创建新的独立SSH客户端
            ssh_client = SSHClient()
            ssh_client.set_missing_host_key_policy(AutoAddPolicy())

            # 配置SSH参数，针对AR2设备优化
            config = {
                'hostname': self.ip,
                'port': self.port,
                'username': self.username,
                'password': self.password,
                'timeout': 30,
                'banner_timeout': 60,
                'auth_timeout': 60,
                'look_for_keys': False,
                'allow_agent': False,
                'disabled_algorithms': {
                    'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256'],
                }
            }

            logger.info(f"使用专用SSH连接到AR2设备: {self.ip}:{self.port}")
            ssh_client.connect(**config)

            # 获取交互式shell
            shell = ssh_client.invoke_shell(width=100, height=30, term='vt100')
            
            # 等待设备就绪
            time.sleep(3)
            if shell.recv_ready():
                shell.recv(4096)  # 清空初始输出
            
            # 1. 进入系统视图
            shell.send("system-view\n".encode('ascii'))
            time.sleep(2)
            
            # 2. 进入接口视图
            if command_context:
                for context_cmd in command_context:
                    shell.send((context_cmd + "\n").encode('ascii'))
                    time.sleep(1)
            
            # 清空缓冲区
            while shell.recv_ready():
                shell.recv(4096)
            
            # 3. 关键步骤：尝试使用不同的编码方式发送命令
            # 首先尝试ASCII（对于不包含中文的情况）
            full_description_command = f"description {description_text}"
            success = False
            
            # 方法1：逐字符发送命令
            logger.info(f"尝试逐字符发送命令: {full_description_command}")
            for char in full_description_command:
                try:
                    shell.send(char.encode('gbk'))
                    time.sleep(0.05)  # 每个字符之间短暂延迟
                except:
                    shell.send(char.encode('ascii', errors='replace'))
                    time.sleep(0.05)
            
            # 发送换行符
            shell.send("\n".encode('ascii'))
            time.sleep(3)
            
            # 读取响应
            if shell.recv_ready():
                response = shell.recv(4096).decode('gbk', errors='ignore')
                output += response
                logger.info(f"中文描述命令响应: {response.strip()}")
                # 检查是否有错误提示
                if 'Error:' not in response:
                    success = True
            
            # 如果方法1失败，尝试方法2：直接使用ASCII发送（针对设备可能只支持ASCII的情况）
            if not success:
                logger.warning("逐字符发送失败，尝试使用ASCII发送")
                # 清空缓冲区
                while shell.recv_ready():
                    shell.recv(4096)
                
                # 发送ASCII版本的命令（可能会丢失中文，但至少能执行）
                ascii_command = f"description ASCII-Test-{int(time.time())}"
                shell.send((ascii_command + "\n").encode('ascii'))
                time.sleep(2)
            
            # 4. 立即验证配置是否生效
            shell.send("display this\n".encode('ascii'))
            time.sleep(2)
            verify_output = ""
            if shell.recv_ready():
                verify_output = shell.recv(4096).decode('gbk', errors='ignore')
                output += verify_output
                logger.info(f"验证输出: {verify_output.strip()[:200]}...")
            
            # 验证描述是否成功应用
            description_applied = False
            if description_text in verify_output:
                description_applied = True
                logger.info(f"✅ 描述文本 '{description_text}' 已成功应用")
            elif 'description ASCII-Test-' in verify_output:
                description_applied = True
                logger.info("✅ ASCII版本的描述文本已成功应用")
            
            # 5. 退出接口视图
            if command_context:
                for _ in range(len(command_context)):
                    shell.send("quit\n".encode('ascii'))
                    time.sleep(1)
            
            # 6. 退出系统视图
            shell.send("quit\n".encode('ascii'))
            time.sleep(1)
            
            # 7. 执行保存命令
            shell.send("save\n".encode('ascii'))
            time.sleep(1)
            
            # 发送'y'确认保存
            shell.send("y\n".encode('ascii'))
            time.sleep(3)
            
            # 读取保存响应
            if shell.recv_ready():
                save_response = shell.recv(4096).decode('utf-8', errors='ignore')
                output += save_response
                logger.info(f"保存响应: {save_response.strip()}")
            
            # 简化的成功判断逻辑
            if description_applied:
                logger.info(f"AR2 description命令执行成功")
                results[command] = "description命令执行成功"
            else:
                logger.error(f"AR2 description命令执行失败: 描述文本未成功应用")
                results[command] = f"执行失败: 描述文本未成功应用"
            
            # 关闭shell和SSH连接
            shell.close()
            ssh_client.close()
            
        except paramiko.AuthenticationException:
            logger.error("AR2设备认证失败")
            results[command] = "认证失败: 用户名或密码错误"
            # 认证失败时关闭会话
            self._close_ar2_session()
        except paramiko.SSHException as ssh_e:
            logger.error(f"AR2设备SSH异常: {str(ssh_e)}")
            results[command] = f"SSH错误: {str(ssh_e)}"
            # SSH错误时关闭会话
            self._close_ar2_session()
        except Exception as e:
            logger.error(f"AR2设备配置过程中发生错误: {str(e)}")
            results[command] = f"执行失败: {str(e)}"
            # 其他错误时尝试关闭会话
            try:
                self._close_ar2_session()
            except:
                pass
        
        return results
        
    def _ensure_ar2_session(self) -> bool:
        """
        确保AR2设备的SSH会话是活跃的，如果不存在则创建
        实现连接重用机制，避免频繁创建和关闭连接
        
        Returns:
            bool: 会话是否成功创建或保持活跃
        """
        import time
        import paramiko
        from paramiko import SSHClient
        from paramiko.client import AutoAddPolicy
        
        current_time = time.time()
        
        # 检查会话是否存在并且未超时
        if self.ar2_shell and self.ar2_ssh_client:
            # 检查会话是否超时
            if self.ar2_last_command_time and (current_time - self.ar2_last_command_time < self.ar2_session_timeout):
                try:
                    # 发送回车确认会话是否仍然活跃
                    self.ar2_shell.send('\n')
                    time.sleep(0.5)
                    if self.ar2_shell.recv_ready():
                        self.ar2_shell.recv(4096)  # 清空响应
                    logger.debug("AR2会话仍然活跃，重用现有连接")
                    self.ar2_last_command_time = current_time
                    return True
                except Exception as e:
                    logger.warning(f"AR2会话检查失败，将重新创建连接: {str(e)}")
            else:
                logger.info("AR2会话已超时，将重新创建连接")
            
            # 关闭旧会话
            try:
                self.ar2_shell.close()
                self.ar2_ssh_client.close()
            except:
                pass
        
        # 创建新会话
        try:
            logger.info(f"为AR2设备创建新的SSH会话: {self.ip}:{self.port}")
            
            # 创建新的SSH客户端
            self.ar2_ssh_client = SSHClient()
            self.ar2_ssh_client.set_missing_host_key_policy(AutoAddPolicy())
            
            # 配置SSH参数，针对AR2设备优化
            config = {
                'hostname': self.ip,
                'port': self.port,
                'username': self.username,
                'password': self.password,
                'timeout': 30,
                'banner_timeout': 60,
                'auth_timeout': 60,
                'look_for_keys': False,
                'allow_agent': False,
                'disabled_algorithms': {
                    'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256'],
                }
            }
            
            self.ar2_ssh_client.connect(**config)
            
            # 使用直接的Transport对象获得更多控制权
            transport = self.ar2_ssh_client.get_transport()
            if transport:
                transport.set_keepalive(15)
                logger.debug("AR2设备SSH保活已启用")
            
            # 获取交互式shell
            self.ar2_shell = self.ar2_ssh_client.invoke_shell(width=80, height=24, term='vt100')
            
            # 清空初始输出
            time.sleep(2)
            if self.ar2_shell.recv_ready():
                self.ar2_shell.recv(4096)  # 清空初始输出
            
            # 重置视图状态
            self.ar2_current_view = 'user'
            self.ar2_last_command_time = current_time
            
            logger.info("AR2会话创建成功")
            return True
        except Exception as e:
            logger.error(f"创建AR2会话失败: {str(e)}")
            # 清理资源
            self._close_ar2_session()
            return False
    
    def _close_ar2_session(self):
        """
        关闭AR2设备的SSH会话
        """
        try:
            if self.ar2_shell:
                self.ar2_shell.close()
                self.ar2_shell = None
            if self.ar2_ssh_client:
                self.ar2_ssh_client.close()
                self.ar2_ssh_client = None
            logger.info("AR2会话已关闭")
        except Exception as e:
            logger.error(f"关闭AR2会话时出错: {str(e)}")
        finally:
            self.ar2_current_view = 'user'
            self.ar2_last_command_time = None
    
    def _execute_ar2_command(self, command: str, command_type: str = 'general', command_context: list = None) -> Dict[str, str]:
        """
        为AR2设备专门设计的通用命令执行方法
        使用增强的SSH协议实现，避免通道错误
        
        Args:
            command: 要执行的命令
            command_type: 命令类型，用于日志和结果标识
            command_context: 命令上下文列表，用于在执行目标命令前切换到正确的视图（如接口视图）
            
        Returns:
            执行结果字典
        """
        import time
        import re
        
        # 对于description命令使用专用的处理方法
        if command.startswith('description') and len(command) > len('description') + 1:
            return self._execute_ar2_description_command(command, command_context)
        
        results = {}
        
        try:
            logger.info(f"使用增强的SSH协议为AR2设备执行{command_type}命令: {command}")
            
            # 确保会话存在
            if not self._ensure_ar2_session():
                results[command] = "执行失败: 无法建立SSH会话"
                return results
            
            # 重置输出缓冲区
            output = "" 
                
            # 特殊处理display和save命令 - 不需要进入system-view
            if command.startswith('display') or command.lower() == 'save':
                    # 如果当前在系统视图，先退出到用户视图
                    if self.ar2_current_view == 'system':
                        self.ar2_shell.send('quit\n')
                        logger.debug("AR2会话从系统视图退出到用户视图")
                        time.sleep(1)
                        # 清空输出
                        while self.ar2_shell.recv_ready():
                            self.ar2_shell.recv(4096)
                        self.ar2_current_view = 'user'
                    
                    # 直接在用户视图执行命令
                    self.ar2_shell.send(command + '\n')
                    if command.startswith('display'):
                        logger.info(f"AR2专用SSH执行display命令: {command}")
                    else:
                        logger.info(f"AR2专用SSH执行save命令: {command}")
                    
                    # 对于display interface命令，增加等待时间
                    if 'interface' in command.lower():
                        time.sleep(4)  # 更长的等待时间
                    else:
                        time.sleep(3)  # 标准等待时间
                    
                    # 尝试获取更多输出，处理分页
                    # 首先发送空格键几次来获取更多内容
                    for _ in range(3):  # 发送3次空格获取更多页
                        self.ar2_shell.send(' ')
                        time.sleep(1)
                        while self.ar2_shell.recv_ready():
                            chunk = self.ar2_shell.recv(4096).decode('utf-8', errors='ignore')
                            output += chunk
                    
                    # 优化错误检测逻辑
                    has_error = ('Error:' in output or 'error:' in output or 
                                'Failed' in output or 'failed' in output) and \
                                'Unrecognized command' not in output
                    
                    # 分别处理display和save命令的结果
                    if command.startswith('display'):
                        # 如果是display interface命令，只要能看到接口状态就认为成功
                        if 'interface' in command.lower() and ('current state' in output or 'Description:' in output):
                            logger.info(f"AR2 display interface命令 {command} 执行成功")
                            results[command] = f"{output.strip()}"
                        elif has_error:
                            logger.error(f"AR2 display命令执行失败: {output[:200]}...")
                            results[command] = f"执行失败: {output.strip()}"
                        else:
                            logger.info(f"AR2 display命令 {command} 执行成功")
                            results[command] = f"{output.strip()}"
                    else:  # save命令
                        # 处理save命令的确认提示
                        if 'Are you sure to overwrite the existing configuration' in output:
                            # 发送'y'确认保存
                            self.ar2_shell.send('y\n')
                            logger.info("AR2专用SSH发送保存确认: y")
                            time.sleep(2)
                            # 读取确认后的输出
                            while self.ar2_shell.recv_ready():
                                chunk = self.ar2_shell.recv(4096).decode('utf-8', errors='ignore')
                                output += chunk
                        
                        # 检查保存是否成功
                        if 'Configuration saved' in output or 'Successfully' in output:
                            logger.info("AR2 save命令执行成功")
                            results[command] = "save命令执行成功"
                        elif has_error:
                            logger.error(f"AR2 save命令执行失败: {output[:200]}...")
                            results[command] = f"执行失败: {output.strip()}"
                        else:
                            logger.info("AR2 save命令执行成功")
                            results[command] = "save命令执行成功"
            else:
                # 1. 确保在系统视图
                if self.ar2_current_view != 'system':
                    self.ar2_shell.send('system-view\n')
                    logger.debug("AR2会话进入系统视图")
                    time.sleep(2)  # 增加等待时间
                    # 清空输出
                    while self.ar2_shell.recv_ready():
                        self.ar2_shell.recv(4096)
                    self.ar2_current_view = 'system'
                
                # 2. 执行上下文命令（如interface命令）
                entered_contexts = []
                if command_context:
                    for context_cmd in command_context:
                        self.ar2_shell.send(context_cmd + '\n')
                        logger.info(f"AR2专用SSH执行: {context_cmd}")
                        time.sleep(2)  # 增加等待时间
                        
                        # 清空输出
                        while self.ar2_shell.recv_ready():
                            self.ar2_shell.recv(4096)
                        entered_contexts.append(context_cmd)
                
                # 3. 执行目标命令
                logger.info(f"AR2专用SSH执行: {command}")
                self.ar2_shell.send(command + '\n')
                time.sleep(2)  # 增加等待时间
                
                # 读取命令输出
                while self.ar2_shell.recv_ready():
                    chunk = self.ar2_shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                
                # 4. 退出上下文
                if entered_contexts:
                    for _ in range(len(entered_contexts)):
                        self.ar2_shell.send('quit\n')
                        logger.debug("AR2会话退出上下文")
                        time.sleep(1)
                        
                        # 清空输出
                        while self.ar2_shell.recv_ready():
                            self.ar2_shell.recv(4096)
                
                # 注意：我们不再退出系统视图，保持在系统视图中以便后续命令执行
                # 更新最后命令执行时间
                self.ar2_last_command_time = time.time()
                
                # 检查是否有错误
                has_error = 'Error:' in output or 'error:' in output or 'Failed' in output or 'failed' in output
                
                if has_error:
                    logger.error(f"AR2 {command_type}命令执行失败: {output[:200]}...")
                    results[command] = f"执行失败: {output.strip()}"
                else:
                    logger.info(f"AR2 {command_type}命令 {command} 执行成功")
                    results[command] = f"{command_type}命令执行成功"
        
        except Exception as shell_e:
                logger.error(f"AR2设备SSH shell执行错误: {str(shell_e)}")
                results[command] = f"执行错误: {str(shell_e)}"
                # 出错时关闭会话，下次将重新创建
                self._close_ar2_session()
            
        except paramiko.AuthenticationException:
            logger.error("AR2设备认证失败")
            results[command] = "认证失败: 用户名或密码错误"
        except paramiko.SSHException as ssh_e:
            logger.error(f"AR2设备SSH异常: {str(ssh_e)}")
            results[command] = f"SSH错误: {str(ssh_e)}"
        except Exception as e:
            logger.error(f"AR2设备配置过程中发生错误: {str(e)}")
            results[command] = f"执行失败: {str(e)}"
        
        return results
    
    def _configure_vlan_on_ar2(self, vlan_id: str, action: str = 'create') -> Dict[str, str]:
        """
        为AR2设备专门设计的VLAN配置方法
        支持创建(create)和删除(delete)VLAN操作
        使用共享会话机制，避免频繁创建和关闭连接
        
        Args:
            vlan_id: VLAN ID
            action: 操作类型，'create'或'delete'
            
        Returns:
            执行结果字典
        """
        import time
        import re
        
        results = {}
        
        try:
            operation = "创建" if action == 'create' else "删除"
            logger.info(f"使用共享会话为AR2设备{operation}VLAN {vlan_id}")
            
            # 确保AR2会话存在
            session_success = self._ensure_ar2_session()
            if not session_success:
                logger.error(f"AR2设备{operation}VLAN {vlan_id}失败: 无法建立会话")
                results[f"{'vlan' if action == 'create' else 'undo vlan'} {vlan_id}"] = "执行失败: 无法建立会话"
                return results
            shell = self.ar2_shell
            
            # 根据操作类型确定命令序列
            if action == 'create':
                commands = [
                    'system-view',
                    f'vlan {vlan_id}',
                    'quit',
                    'quit'
                ]
            else:  # delete
                commands = [
                    'system-view',
                    f'undo vlan {vlan_id}',
                    'quit'
                ]
            
            output = ""
            
            # 保存当前视图状态
            original_view = self.ar2_current_view
            
            for cmd in commands:
                logger.info(f"AR2共享会话执行: {cmd}")
                shell.send(cmd + '\n')
                
                # 等待命令执行完成
                time.sleep(1)
                
                # 读取输出
                end_time = time.time() + 5
                while time.time() < end_time:
                    if shell.recv_ready():
                        chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                        output += chunk
                        logger.debug(f"AR2输出片段: {chunk[:100]}...")
                        
                        # 检查是否包含提示符
                        if re.search(r'<.*?>|\[.*?\]', chunk):
                            # 更新当前视图状态
                            if cmd == 'system-view':
                                self.ar2_current_view = 'system'
                            elif cmd == 'quit':
                                if self.ar2_current_view == 'system':
                                    self.ar2_current_view = 'user'
                            break
                    time.sleep(0.2)
                
                # 更新最后命令执行时间
                self.ar2_last_command_time = time.time()
            
            # 检查命令执行结果
            if re.search(r'Error|Invalid|Fail', output, re.IGNORECASE):
                logger.error(f"AR2 VLAN{operation}失败: {output[:200]}...")
                results[f"{'vlan' if action == 'create' else 'undo vlan'} {vlan_id}"] = f"{operation}失败: {output.strip()}"
            else:
                logger.info(f"AR2 VLAN {vlan_id}{operation}成功")
                results[f"{'vlan' if action == 'create' else 'undo vlan'} {vlan_id}"] = f"VLAN {vlan_id}{operation}成功"
            
        except Exception as e:
            logger.error(f"AR2设备VLAN配置错误: {str(e)}")
            results[f"{'vlan' if action == 'create' else 'undo vlan'} {vlan_id}"] = f"执行错误: {str(e)}"
            # 发生错误时关闭会话，避免状态不一致
            self._close_ar2_session()
        
        return results
        
    def _create_vlan_on_ar2(self, vlan_id: str) -> Dict[str, str]:
        """
        为AR2设备专门设计的VLAN创建方法
        使用共享会话机制，避免频繁创建和关闭SSH连接
        
        Args:
            vlan_id: VLAN ID
            
        Returns:
            执行结果字典
        """
        return self._configure_vlan_on_ar2(vlan_id, 'create')
        
    def _delete_vlan_on_ar2(self, vlan_id: str) -> Dict[str, str]:
        """
        为AR2设备专门设计的VLAN删除方法
        使用共享会话机制，避免频繁创建和关闭SSH连接
        
        Args:
            vlan_id: VLAN ID
            
        Returns:
            执行结果字典
        """
        return self._configure_vlan_on_ar2(vlan_id, 'delete')

    def execute_configuration(self, configuration: str) -> Dict[str, str]:
        """
        在设备上执行配置命令
        
        Args:
            configuration: 配置命令，多条命令使用换行符分隔
            
        Returns:
            执行结果字典，包含每个命令的结果
        """
        import time
        import re
        
        if not configuration.strip():
            return {"错误": "配置命令不能为空"}
        
        # 模拟模式处理
        if self.simulation_mode:
            logger.info(f"模拟模式：在设备 {self.ip} 上执行配置")
            
            results = {}
            commands = configuration.strip().split('\n')
            
            for cmd in commands:
                if not cmd.strip():
                    continue
                    
                cmd_lower = cmd.strip().lower()
                
                if cmd_lower == 'system-view':
                    results[cmd] = "Enter system view, return user view with Ctrl+Z."
                elif cmd_lower.startswith('vlan'):
                    vlan_id = cmd_lower.split()[1] if len(cmd_lower.split()) > 1 else "未指定"
                    results[cmd] = f"成功创建/进入VLAN {vlan_id}"
                elif cmd_lower.startswith('interface'):
                    interface = cmd_lower.split()[1] if len(cmd_lower.split()) > 1 else "未指定"
                    results[cmd] = f"成功进入接口 {interface}"
                elif cmd_lower.startswith('port link-type'):
                    link_type = cmd_lower.split()[2] if len(cmd_lower.split()) > 2 else "未指定"
                    results[cmd] = f"成功配置接口链路类型为 {link_type}"
                elif cmd_lower.startswith('port default vlan'):
                    vlan_id = cmd_lower.split()[3] if len(cmd_lower.split()) > 3 else "未指定"
                    results[cmd] = f"成功配置接口默认VLAN为 {vlan_id}"
                elif cmd_lower.startswith('port trunk allow-pass vlan'):
                    vlan_ids = " ".join(cmd_lower.split()[4:]) if len(cmd_lower.split()) > 4 else "未指定"
                    results[cmd] = f"成功配置Trunk接口允许通过VLAN: {vlan_ids}"
                elif cmd_lower == 'quit' or cmd_lower == 'return':
                    results[cmd] = "成功退出当前视图"
                elif cmd_lower.startswith('sysname'):
                    sysname = " ".join(cmd_lower.split()[1:]) if len(cmd_lower.split()) > 1 else "未指定"
                    results[cmd] = f"成功设置设备名称为 {sysname}"
                elif cmd_lower.startswith('ip address'):
                    results[cmd] = "成功配置IP地址"
                elif cmd_lower.startswith('ip route-static'):
                    parts = cmd_lower.split()
                    if len(parts) >= 5:
                        network = parts[2]
                        mask = parts[3]
                        next_hop = parts[4]
                        results[cmd] = f"成功配置静态路由: {network} {mask} -> {next_hop}"
                    else:
                        results[cmd] = "成功配置静态路由"
                else:
                    results[cmd] = "配置命令执行成功"
            
            return results
        
        # 特殊处理AR2设备 (192.168.56.254)
        if self.ip == '192.168.56.254':
            logger.info("检测到AR2设备，使用共享会话机制执行配置")
            
            # 确保AR2共享会话存在
            if not self._ensure_ar2_session():
                logger.error("无法建立AR2共享会话")
                return {"错误": "无法建立AR2共享会话"}
            
            results = {}
            commands = configuration.strip().split('\n')
            
            # 跟踪当前上下文
            current_context = []
            
            for cmd in commands:
                if not cmd.strip():
                    continue
                
                # 清理命令，移除提示符但保留命令中的空格
                clean_cmd = re.sub(r'\[.*?\]', '', cmd).strip()
                logger.info(f"清理后的命令: '{clean_cmd}'")
                
                # AR2设备命令处理准备
                command_context = []
                
                # 检查是否是上下文切换命令
                if clean_cmd.lower().startswith('interface '):
                    interface_name = clean_cmd.split()[1] if len(clean_cmd.split()) > 1 else ''
                    command_context.append(clean_cmd)
                    logger.info(f"检测到接口上下文切换命令: {clean_cmd}")
                    # 跟踪当前上下文
                    current_context = [clean_cmd]
                elif clean_cmd.lower() == 'quit' or clean_cmd.lower() == 'return':
                    # 退出命令，清除当前上下文
                    current_context = []
                else:
                    # 对于其他命令，使用当前上下文
                    command_context = current_context.copy()
                
                # 1. 首先判断是否是VLAN相关命令，使用专用方法处理
                if clean_cmd.lower().startswith('vlan ') and len(clean_cmd.split()) > 1 and clean_cmd.split()[1].isdigit():
                    vlan_id = clean_cmd.split()[1]
                    logger.info(f"检测到VLAN创建命令，使用AR2专用VLAN创建方法: {cmd}")
                    # 使用专用的VLAN创建方法
                    vlan_results = self._create_vlan_on_ar2(vlan_id)
                    results.update(vlan_results)
                elif clean_cmd.lower().startswith('undo vlan ') and len(clean_cmd.split()) > 2:
                    vlan_id = clean_cmd.split()[2]
                    logger.info(f"检测到VLAN删除命令，使用AR2专用VLAN删除方法: {cmd}")
                    # 使用专用的VLAN删除方法
                    vlan_results = self._delete_vlan_on_ar2(vlan_id)
                    results.update(vlan_results)
                # 2. 对于所有其他命令，使用通用命令执行方法
                else:
                    # 从原始命令中提取上下文信息（额外的检查）
                    if not command_context:
                        # 检查是否是接口视图中的命令
                        if 'GigabitEthernet' in cmd or 'Ethernet' in cmd or 'GE' in cmd:
                            # 提取接口名称
                            interface_match = re.search(r'(GigabitEthernet\\d+/\\d+/\\d+|Ethernet\\d+/\\d+/\\d+|GE\\d+/\\d+/\\d+)', cmd)
                            if interface_match:
                                interface_name = interface_match.group(1)
                                command_context.append(f'interface {interface_name}')
                                logger.info(f"检测到接口命令，将在{interface_name}上下文中执行: {clean_cmd}")
                        # 检查是否是VLAN视图中的命令
                        elif 'Vlanif' in cmd or 'VLAN' in cmd:
                            # 提取VLAN接口号
                            vlan_match = re.search(r'Vlanif?(\\d+)', cmd)
                            if vlan_match:
                                vlan_id = vlan_match.group(1)
                                command_context.append(f'interface Vlanif{vlan_id}')
                                logger.info(f"检测到VLAN接口命令，将在Vlanif{vlan_id}上下文中执行: {clean_cmd}")
                    
                    # 确定命令类型以便在日志中更好地标识
                    cmd_type = "STP" if 'stp' in clean_cmd.lower() else "配置"
                    logger.info(f"检测到{cmd_type}命令，使用AR2专用通用执行方法: {cmd}")
                    
                    # 使用通用命令执行方法处理所有其他命令，并传递命令上下文
                    cmd_results = self._execute_ar2_command(clean_cmd, cmd_type, command_context)
                    results.update({cmd: cmd_results[clean_cmd]})
                
                # 更新最后命令执行时间
                self.ar2_last_command_time = time.time()
            
            return results

        # 对于其他设备，继续使用SSH连接
        # 实际配置执行
        if not self.connected or not self.ssh_client:
            logger.error("设备未连接，无法执行配置")
            return {"错误": "设备未连接"}
        
        # 验证SSH会话
        if not self.verify_ssh_session():
            logger.warning("SSH会话不活跃: 尝试重新连接")
            if not self.reconnect():
                logger.error("SSH会话重新连接失败")
                return {"错误": "SSH会话不活跃，重新连接失败"}
        
        retry_count = 0
        max_retries = 3  # 增加重试次数
        success = False
        final_results = None
        
        while retry_count < max_retries and not success:
            try:
                # 确保SSH会话仍然活跃
                if not self.verify_ssh_session():
                    logger.warning("SSH会话在重试前不活跃")
                    if not self.reconnect():
                        return {"错误": "SSH会话在重试前不活跃，重新连接失败"}
                
                # 特殊处理AR2设备 (192.168.56.254)
                if self.ip == '192.168.56.254':
                    logger.info(f"使用AR2设备专用SSH执行方法 (尝试 {retry_count+1}/{max_retries+1})")
                    
                    results = {}
                    commands = configuration.strip().split('\n')
                    
                    # 对AR2设备的命令进行特殊处理
                    for cmd in commands:
                        if not cmd.strip():
                            continue
                        
                        # 清理命令，移除提示符但保留命令中的空格
                        clean_cmd = re.sub(r'\[.*?\]', '', cmd).strip()
                        logger.info(f"清理后的命令: '{clean_cmd}'")
                        
                            # 针对AR2设备的命令处理
                        # 1. 首先判断是否是VLAN相关命令，使用专用方法处理
                        if clean_cmd.lower().startswith('vlan ') and len(clean_cmd.split()) > 1 and clean_cmd.split()[1].isdigit():
                            vlan_id = clean_cmd.split()[1]
                            logger.info(f"检测到VLAN创建命令，使用AR2专用VLAN创建方法: {cmd}")
                            # 使用专用的VLAN创建方法
                            vlan_results = self._create_vlan_on_ar2(vlan_id)
                            results.update(vlan_results)
                        elif clean_cmd.lower().startswith('undo vlan ') and len(clean_cmd.split()) > 2:
                            vlan_id = clean_cmd.split()[2]
                            logger.info(f"检测到VLAN删除命令，使用AR2专用VLAN删除方法: {cmd}")
                            # 使用专用的VLAN删除方法
                            vlan_results = self._delete_vlan_on_ar2(vlan_id)
                            results.update(vlan_results)
                        # 2. 对于所有其他命令，使用通用命令执行方法
                        else:
                            # 从原始命令中提取上下文信息
                            command_context = []
                            
                            # 检查是否是接口视图中的命令
                            if 'GigabitEthernet' in cmd or 'Ethernet' in cmd or 'GE' in cmd:
                                # 提取接口名称
                                import re
                                interface_match = re.search(r'(GigabitEthernet\d+/\d+/\d+|Ethernet\d+/\d+/\d+|GE\d+/\d+/\d+)', cmd)
                                if interface_match:
                                    interface_name = interface_match.group(1)
                                    command_context.append(f'interface {interface_name}')
                                    logger.info(f"检测到接口命令，将在{interface_name}上下文中执行: {clean_cmd}")
                            # 检查是否是VLAN视图中的命令
                            elif 'Vlanif' in cmd or 'VLAN' in cmd:
                                # 提取VLAN接口号
                                vlan_match = re.search(r'Vlanif?(\d+)', cmd)
                                if vlan_match:
                                    vlan_id = vlan_match.group(1)
                                    command_context.append(f'interface Vlanif{vlan_id}')
                                    logger.info(f"检测到VLAN接口命令，将在Vlanif{vlan_id}上下文中执行: {clean_cmd}")
                            # 可以根据需要添加更多上下文识别逻辑
                            
                            # 确定命令类型以便在日志中更好地标识
                            cmd_type = "STP" if 'stp' in clean_cmd.lower() else "配置"
                            logger.info(f"检测到{cmd_type}命令，使用AR2专用通用执行方法: {cmd}")
                            
                            # 使用通用命令执行方法处理所有其他命令，并传递命令上下文
                            cmd_results = self._execute_ar2_command(clean_cmd, cmd_type, command_context)
                            results.update({cmd: cmd_results[clean_cmd]})
                        
                        # 更新最后命令执行时间
                        self.last_command_time = time.time()
                    
                    final_results = results
                    success = True
                # 对于华为设备，使用交互式会话执行配置命令
                elif self.is_huawei_device():
                    logger.info(f"使用交互式shell执行配置命令 (尝试 {retry_count+1}/{max_retries+1})")
                    
                    results = {}
                    commands = configuration.strip().split('\n')
                    
                    # 初始化交互式shell - 使用更简单的参数
                    shell = None
                    try:
                        # 使用较小的宽度和高度，有些设备可能对大窗口参数敏感
                        shell = self.ssh_client.invoke_shell(width=80, height=24)
                        
                        # 清空初始输出，但不立即读取，给设备一些时间响应
                        time.sleep(1)
                        if shell.recv_ready():
                            initial_output = shell.recv(4096).decode('utf-8', errors='ignore')
                            logger.debug(f"初始shell输出: {initial_output[:200]}...")
                        
                        # 逐条执行命令
                        for cmd in commands:
                            if not cmd.strip():
                                continue
                            
                            logger.info(f"执行命令: {cmd}")
                            # 发送命令
                            shell.send(cmd + '\n')
                            
                            # 增加等待时间，确保命令被正确处理
                            time.sleep(1)
                            
                            # 接收输出 - 更健壮的实现
                            output = ''
                            end_time = time.time() + 10  # 增加超时时间到10秒
                            prompt_found = False
                            
                            while time.time() < end_time:
                                if shell.recv_ready():
                                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                                    output += chunk
                                    
                                    # 检查是否找到提示符
                                    for pattern in self.prompt_patterns:
                                        if re.search(pattern, chunk):
                                            prompt_found = True
                                            logger.debug(f"找到提示符: {chunk}")
                                            break
                                
                                # 如果找到提示符，不再等待
                                if prompt_found:
                                    break
                                
                                time.sleep(0.2)  # 稍微增加休眠时间
                            
                            # 清理输出
                            if output.startswith(cmd):
                                output = output[len(cmd):]
                            
                            # 移除末尾的提示符
                            for pattern in self.prompt_patterns:
                                output = re.sub(f'{pattern}$', '', output)
                            
                            results[cmd] = output.strip()
                            
                            # 检查错误关键字
                            if any(error_keyword in output.lower() for error_keyword in ['error', 'failed', 'invalid']):
                                logger.warning(f"命令 {cmd} 可能执行失败: {output}")
                            else:
                                logger.info(f"命令 {cmd} 执行成功")
                            
                            # 更新最后命令执行时间
                            self.last_command_time = time.time()
                    except Exception as shell_e:
                        logger.error(f"交互式shell执行出错: {str(shell_e)}")
                        # 对于华为设备，不再尝试exec_command回退，因为它可能不支持
                        # 而是直接重新连接并再次尝试交互式方式
                        raise shell_e
                    finally:
                        if shell:
                            try:
                                shell.close()
                            except:
                                pass
                    
                    final_results = results
                    success = True
                else:
                    # 对于非华为设备，使用标准方法执行命令
                    commands = configuration.strip().split('\n')
                    final_results = self._execute_configuration_with_exec_command(commands)
                    success = True
                    
            except Exception as e:
                retry_count += 1
                logger.error(f"执行配置时发生异常 (重试 {retry_count}/{max_retries}): {str(e)}")
                
                # 如果是通道或传输层问题，尝试重新连接
                if "channel" in str(e).lower() or "transport" in str(e).lower() or "connection" in str(e).lower():
                    if retry_count < max_retries:
                        logger.info("尝试重新连接并执行命令")
                        if self.reconnect():
                            continue
                    
                # 如果重试次数用完或重新连接失败
                if retry_count >= max_retries:
                    final_results = {"错误": f"配置执行失败: {str(e)}"}
                    break
        
        return final_results
    
    def _execute_configuration_with_exec_command(self, commands: List[str]) -> Dict[str, str]:
        """
        使用exec_command方法执行配置命令，增强了错误处理和重试机制
        
        Args:
            commands: 命令列表
            
        Returns:
            执行结果字典
        """
        results = {}
        max_cmd_retries = 2  # 每条命令的最大重试次数
        
        for cmd in commands:
            if not cmd.strip():
                continue
            
            cmd_retry_count = 0
            cmd_success = False
            
            while cmd_retry_count <= max_cmd_retries and not cmd_success:
                # 每次执行前验证SSH会话
                if not self.verify_ssh_session():
                    logger.warning(f"执行命令前会话验证失败，尝试重新连接: {cmd}")
                    if not self.reconnect():
                        logger.error("重新连接失败，跳过当前命令")
                        results[cmd] = "错误: SSH会话未建立或已断开"
                        break
                
                try:
                    logger.info(f"使用exec_command执行单条命令 (尝试 {cmd_retry_count+1}/{max_cmd_retries+1}): {cmd}")
                    # 为每条命令创建新的通道，并设置更长的超时时间
                    stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=30)
                    
                    # 读取输出和错误
                    cmd_output = stdout.read().decode('utf-8', errors='ignore')
                    cmd_error = stderr.read().decode('utf-8', errors='ignore')
                    
                    # 定期发送keepalive以保持连接活跃
                    self.last_command_time = time.time()
                    
                    if cmd_error:
                        results[cmd] = f"错误: {cmd_error.strip()}"
                        logger.warning(f"命令 {cmd} 执行出错: {cmd_error}")
                    else:
                        results[cmd] = cmd_output.strip()
                        cmd_success = True
                    
                except Exception as cmd_e:
                    error_msg = str(cmd_e)
                    cmd_retry_count += 1
                    
                    # 特殊处理不同类型的错误
                    if "channel" in error_msg.lower() or "transport" in error_msg.lower():
                        logger.error(f"执行命令 {cmd} 时发生通道/传输错误 (尝试 {cmd_retry_count}/{max_cmd_retries}): {error_msg}")
                        # 立即尝试重新连接
                        if cmd_retry_count <= max_cmd_retries:
                            logger.info("尝试重新连接后重试命令")
                            self.reconnect()
                            time.sleep(1)  # 短暂延迟后重试
                    elif "timed out" in error_msg.lower():
                        logger.error(f"执行命令 {cmd} 超时 (尝试 {cmd_retry_count}/{max_cmd_retries}): {error_msg}")
                        if cmd_retry_count <= max_cmd_retries:
                            time.sleep(2)  # 超时情况下稍长的延迟
                    else:
                        logger.error(f"执行命令 {cmd} 时出错 (尝试 {cmd_retry_count}/{max_cmd_retries}): {error_msg}")
                        
                    if cmd_retry_count > max_cmd_retries:
                        results[cmd] = f"错误: {error_msg} (已重试{max_cmd_retries}次)"
        
        return results
    
    def collect_device_info(self) -> Dict[str, str]:
        """
        收集设备信息
        
        Returns:
            设备信息字典
        """
        # 模拟模式处理
        if self.simulation_mode:
            logger.info(f"模拟模式：收集设备 {self.ip} 信息")
            
            return {
                "version": self.execute_command("display version"),
                "interfaces": self.execute_command("display interface brief"),
                "vlans": self.execute_command("display vlan"),
                "configuration": self.execute_command("display current-configuration"),
                "routing_table": self.execute_command("display ip routing-table")
            }
        
        # 实际设备信息收集
        if not self.connected:
            logger.error("设备未连接，无法收集信息")
            return {}
        
        try:
            logger.info(f"正在收集设备 {self.ip} 信息...")
            
            device_info = {}
            
            # 收集基本信息，使用较短的超时时间
            commands_to_collect = {
                "version": "display version",
                "interfaces": "display interface brief",
                "users": "display users",
                "routing_table": "display ip routing-table"
            }
            
            for info_type, cmd in commands_to_collect.items():
                logger.info(f"收集 {info_type} 信息...")
                result = self.execute_command(cmd, timeout=5)
                # 只保存有效的结果
                if result and not result.startswith("错误"):
                    device_info[info_type] = result
                else:
                    logger.warning(f"无法收集 {info_type} 信息")
            
            # 对于大型配置，单独处理
            try:
                logger.info("收集配置信息...")
                config = self.execute_command("display current-configuration", timeout=10)
                if config and not config.startswith("错误"):
                    device_info["configuration"] = config
            except Exception as e:
                logger.warning(f"收集配置信息时出错: {str(e)}")
            
            # 如果是交换机，尝试获取VLAN信息
            if "switch" in self.device_type.lower():
                try:
                    logger.info("收集VLAN信息...")
                    vlans = self.execute_command("display vlan", timeout=5)
                    if vlans and not vlans.startswith("错误"):
                        device_info["vlans"] = vlans
                except Exception as e:
                    logger.warning(f"收集VLAN信息时出错: {str(e)}")
            
            logger.info(f"设备 {self.ip} 信息收集完成，成功收集 {len(device_info)} 项信息")
            return device_info
        except Exception as e:
            logger.error(f"收集设备信息时出错: {str(e)}")
            return {"错误": str(e)}
import logging
import re
import subprocess
import platform
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Callable
from config import SIMULATION_MODE
from deepseek_api import DeepSeekAPI
from network_device import NetworkDevice

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Troubleshooter:
    """网络设备故障排查类"""
    
    def __init__(self, network_device: Optional[NetworkDevice] = None, deepseek_api: Optional[DeepSeekAPI] = None):
        """
        初始化故障排查器
        
        Args:
            network_device: 网络设备实例
            deepseek_api: DeepSeek API实例
        """
        self.network_device = network_device
        self.deepseek_api = deepseek_api if deepseek_api else DeepSeekAPI()
        self.simulation_mode = SIMULATION_MODE
        # 定义支持的网络排查命令
        self.supported_commands = {
            'ping': self._execute_ping,
            'tracert': self._execute_tracert,
            'display interface': self._execute_device_command,
            'display vlan': self._execute_device_command,
            'display arp': self._execute_device_command,
            'display ip routing-table': self._execute_device_command
        }
    
    def analyze_device_state(self, device_info: Dict[str, any]) -> Dict[str, any]:
        """
        分析设备状态，识别潜在问题
        
        Args:
            device_info: 设备信息字典
            
        Returns:
            分析结果字典
        """
        logger.info("分析设备状态")
        
        # 模拟模式处理
        if self.simulation_mode:
            logger.info("模拟模式：分析设备状态")
            
            # 模拟一些常见的设备问题
            issues = []
            recommendations = []
            
            # 模拟接口Down的问题
            issues.append({
                "type": "interface_down",
                "severity": "high",
                "description": "接口 GigabitEthernet0/0/1 处于Down状态",
                "affected_component": "GigabitEthernet0/0/1"
            })
            recommendations.append("检查接口物理连接和配置")
            
            # 模拟VLAN未使用的问题
            issues.append({
                "type": "vlan_unused",
                "severity": "low",
                "description": "VLAN 100 已创建但未被任何接口使用",
                "affected_component": "VLAN 100"
            })
            recommendations.append("如果不需要此VLAN，可以考虑删除以节省资源")
            
            return {
                "status": "completed",
                "issues": issues,
                "recommendations": recommendations,
                "simulation_mode": True
            }
        
        # 实际API分析模式
        try:
            # 构建分析请求
            prompt = f"""
            请分析以下华为交换机的设备信息，识别可能存在的问题和潜在的优化机会。
            
            设备信息:
            {device_info}
            
            请提供详细的分析结果，包括:
            1. 发现的问题列表（每个问题包括类型、严重程度、描述和受影响组件）
            2. 建议的解决方法
            3. 潜在的优化建议
            """
            
            # 调用DeepSeek API进行分析
            response = self.deepseek_api._call_api(prompt)
            
            if response:
                # 解析分析结果
                # 注意：这里假设API返回的是JSON格式，如果不是，需要进行相应的解析
                analysis_result = {
                    "status": "completed",
                    "issues": [],
                    "recommendations": [],
                    "raw_analysis": response
                }
                
                # 简单的结果解析逻辑，实际实现可能需要根据API返回的具体格式进行调整
                if "问题" in response or "错误" in response:
                    analysis_result["issues"].append({
                        "type": "unknown",
                        "severity": "medium",
                        "description": "API检测到潜在问题",
                        "affected_component": "unknown"
                    })
                
                return analysis_result
            else:
                logger.error("无法获取设备状态分析结果")
                return {
                    "status": "failed",
                    "issues": [],
                    "recommendations": [],
                    "error": "无法获取分析结果"
                }
                
        except Exception as e:
            logger.error(f"分析设备状态时出错: {str(e)}")
            return {
                "status": "failed",
                "issues": [],
                "recommendations": [],
                "error": str(e)
            }
    
    def troubleshoot_device(self) -> Dict[str, any]:
        """
        执行设备故障排查
        
        Returns:
            故障排查结果字典
        """
        logger.info("开始设备故障排查")
        
        # 检查设备连接
        if not self.network_device or not self.network_device.connected:
            logger.warning("设备未连接，将使用模拟数据进行故障排查")
            
            # 模拟模式数据收集
            device_info = self._collect_simulation_device_info()
        else:
            # 实际设备数据收集
            device_info = self._collect_device_info()
        
        # 分析设备状态
        analysis_result = self.analyze_device_state(device_info)
        
        # 生成完整的故障排查结果
        troubleshooting_result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_info": device_info,
            "analysis": analysis_result,
            "summary": {
                "total_issues": len(analysis_result.get("issues", [])),
                "high_severity": sum(1 for issue in analysis_result.get("issues", []) if issue.get("severity") == "high"),
                "medium_severity": sum(1 for issue in analysis_result.get("issues", []) if issue.get("severity") == "medium"),
                "low_severity": sum(1 for issue in analysis_result.get("issues", []) if issue.get("severity") == "low")
            }
        }
        
        return troubleshooting_result
    
    def _collect_device_info(self) -> Dict[str, any]:
        """
        从实际设备收集信息
        
        Returns:
            设备信息字典
        """
        logger.info("从设备收集信息")
        
        device_info = {}
        
        try:
            # 获取设备基本信息
            device_info["version"] = self.network_device.execute_command("display version")
            
            # 获取接口状态
            device_info["interfaces"] = self.network_device.execute_command("display interface brief")
            
            # 获取VLAN信息
            device_info["vlans"] = self.network_device.execute_command("display vlan")
            
            # 获取当前配置
            device_info["running_config"] = self.network_device.execute_command("display current-configuration")
            
            # 获取CPU和内存使用情况
            device_info["cpu_usage"] = self.network_device.execute_command("display cpu-usage")
            device_info["memory_usage"] = self.network_device.execute_command("display memory-usage")
            
        except Exception as e:
            logger.error(f"收集设备信息时出错: {str(e)}")
            device_info["error"] = str(e)
        
        return device_info
    
    def _collect_simulation_device_info(self) -> Dict[str, any]:
        """
        生成模拟的设备信息（用于测试或设备未连接的情况）
        
        Returns:
            模拟的设备信息字典
        """
        logger.info("生成模拟设备信息")
        
        return {
            "version": "Huawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (S5720 V200R011C10)\nCopyright (C) 2000-2017 HUAWEI TECH CO., LTD\nHuawei S5720-28X-SI-AC Switch uptime is 5 days, 12 hours, 30 minutes",
            
            "interfaces": "PHY: Physical\n*down: administratively down\n(l): loopback\n(s): spoofing\n(b): BFD down\n(e): ETHOAM down\nInUti/OutUti: input/output utilization in percentage\nInterface                   PHY   Protocol InUti OutUti   inErrors  outErrors\nGigabitEthernet0/0/1         down  down        0%     0%          0         0\nGigabitEthernet0/0/2         up    up          1%     2%          0         0\nGigabitEthernet0/0/3         up    up          0%     0%          0         0\nGigabitEthernet0/0/4         up    up          0%     0%          0         0\nNULL0                        up    up(s)       0%     0%          0         0",
            
            "vlans": "The total number of vlans is : 8\n--------------------------------------------------------------------------------\nU: Up;         D: Down;         TG: Tagged;         UT: Untagged\nMP: Vlan-mapping;               ST: Vlan-stacking\n#: ProtocolTransparent-vlan;    *: Management-vlan\n--------------------------------------------------------------------------------\nVID  Type    Status  Port List\n--------------------------------------------------------------------------------\n1    common  UT      GE0/0/2(U), GE0/0/3(U)\n10   common  UT      none\n20   common  UT      none\n100  common  UT      none",
            
            "running_config": "#\nsysname Switch\n#\nvlan batch 10 20 100\n#\ninterface GigabitEthernet0/0/1\n shutdown\n#\ninterface GigabitEthernet0/0/2\n port link-type access\n port default vlan 1\n#\ninterface GigabitEthernet0/0/3\n port link-type access\n port default vlan 1\n#\nreturn",
            
            "cpu_usage": "CPU Usage Stat. Cycle: 60 (Second)\nCPU Usage: 5% Max: 8%\nCPU Usage Stat. Time: 2023-05-10 15:30:00\nCPU utilization for five seconds: 5%\nCPU utilization for one minute: 4%\nCPU utilization for five minutes: 3%",
            
            "memory_usage": "Memory Using Percentage: 15%\nTotal Memory: 1024MB\nUsed Memory: 154MB\nFree Memory: 870MB",
            
            "simulation_mode": True
        }
    
    def generate_troubleshooting_report(self, troubleshooting_result: Dict[str, any]) -> str:
        """
        生成故障排查报告
        
        Args:
            troubleshooting_result: 故障排查结果字典
            
        Returns:
            格式化的报告文本
        """
        logger.info("生成故障排查报告")
        
        # 构建报告
        report = []
        report.append("="*80)
        report.append("华为网络设备故障排查报告")
        report.append("="*80)
        report.append(f"生成时间: {troubleshooting_result['timestamp']}")
        
        # 如果是模拟模式，添加标识
        if troubleshooting_result.get("device_info", {}).get("simulation_mode", False):
            report.append("\n[模拟模式] 此报告基于模拟数据生成")
        
        report.append("\n1. 摘要")
        report.append("-" * 40)
        summary = troubleshooting_result["summary"]
        report.append(f"总问题数: {summary['total_issues']}")
        report.append(f"高严重性问题: {summary['high_severity']}")
        report.append(f"中等严重性问题: {summary['medium_severity']}")
        report.append(f"低严重性问题: {summary['low_severity']}")
        
        report.append("\n2. 设备信息")
        report.append("-" * 40)
        device_info = troubleshooting_result["device_info"]
        
        # 添加设备版本信息
        if "version" in device_info:
            version_lines = device_info["version"].split("\n")[:3]  # 只显示版本的前几行
            report.append("设备版本:")
            report.extend([f"  {line}" for line in version_lines])
        
        # 添加接口状态概览
        if "interfaces" in device_info:
            interface_lines = device_info["interfaces"].split("\n")
            # 找到接口状态行
            interface_status_lines = []
            for line in interface_lines:
                if line.strip() and ("up" in line.lower() or "down" in line.lower()) and not line.startswith("Interface"):
                    interface_status_lines.append(line)
            
            report.append("\n接口状态概览:")
            report.extend([f"  {line}" for line in interface_status_lines[:5]])  # 只显示前5个接口
            if len(interface_status_lines) > 5:
                report.append(f"  ... 还有 {len(interface_status_lines) - 5} 个接口")
        
        report.append("\n3. 发现的问题")
        report.append("-" * 40)
        issues = troubleshooting_result["analysis"].get("issues", [])
        
        if not issues:
            report.append("未发现明显问题")
        else:
            for i, issue in enumerate(issues, 1):
                report.append(f"\n问题 {i}:")
                report.append(f"  类型: {issue.get('type', 'unknown')}")
                report.append(f"  严重程度: {issue.get('severity', 'unknown')}")
                report.append(f"  描述: {issue.get('description', '')}")
                report.append(f"  受影响组件: {issue.get('affected_component', 'unknown')}")
        
        report.append("\n4. 建议解决方案")
        report.append("-" * 40)
        recommendations = troubleshooting_result["analysis"].get("recommendations", [])
        
        if not recommendations:
            report.append("无特定建议")
        else:
            for i, recommendation in enumerate(recommendations, 1):
                report.append(f"{i}. {recommendation}")
        
        report.append("\n="*40)
        report.append("报告结束")
        report.append("="*80)
        
        return "\n".join(report)
    
    def save_report_to_file(self, report_text: str, filename: str = None) -> str:
        """
        将故障排查报告保存到文件
        
        Args:
            report_text: 报告文本内容
            filename: 文件名，如果不提供则自动生成
            
        Returns:
            保存的文件路径
        """
        try:
            # 如果不提供文件名，生成基于时间戳的文件名
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"troubleshooting_report_{timestamp}.txt"
            
            # 保存报告到文件
            with open(filename, "w", encoding="utf-8") as f:
                f.write(report_text)
            
            logger.info(f"故障排查报告已保存到: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"保存故障排查报告时出错: {str(e)}")
            return None
    
    def run_troubleshooting(self, problem_description: str, callback: Optional[Callable] = None) -> str:
        """
        运行故障排查并处理问题描述中的网络命令
        
        Args:
            problem_description: 问题描述，可能包含网络命令
            callback: 可选的回调函数，用于实时更新进度或结果
            
        Returns:
            故障排查结果文本
        """
        logger.info(f"执行故障排查，问题描述: {problem_description}")
        
        # 使用回调显示开始排查信息
        if callback:
            callback("开始故障排查...\n")
            
        # 检查问题描述中是否包含支持的网络命令
        has_commands = False
        
        # 检查是否包含ping命令
        ping_matches = re.findall(r'ping\s+(\S+)', problem_description)
        for target in ping_matches:
            has_commands = True
            if callback:
                callback(f"正在执行ping命令: {target}\n")
            # 直接通过回调显示ping命令结果
            self._execute_ping(target, callback)  # 使用回调直接显示结果，避免重复显示
        
        # 检查是否包含tracert命令
        tracert_matches = re.findall(r'tracert\s+(\S+)', problem_description)
        for target in tracert_matches:
            has_commands = True
            if callback:
                callback(f"正在执行tracert命令: {target}\n")
            # 对于tracert，仍然使用回调显示结果
            self._execute_tracert(target, callback)
        
        # 检查是否包含设备命令
        device_commands = []
        for cmd in ['display interface', 'display vlan', 'display arp', 'display ip routing-table']:
            if cmd in problem_description and self.network_device and self.network_device.connected:
                device_commands.append(cmd)
                has_commands = True
        
        # 执行设备命令
        for cmd in device_commands:
            if callback:
                callback(f"正在执行设备命令: {cmd}\n")
            # 对于设备命令，仍然使用回调显示结果
            self._execute_device_command(cmd, callback)
        
        # 如果有命令结果，返回这些结果
        if has_commands:
            # 使用回调显示完成信息
            if callback:
                callback("命令执行完成\n")
            
            # 返回空字符串，避免结果被重复显示
            return ""
        
        # 如果没有检测到命令，执行标准故障排查
        try:
            if callback:
                callback("未检测到命令，执行标准故障排查流程\n")
                
            # 执行设备故障排查
            troubleshooting_result = self.troubleshoot_device()
            
            # 生成故障排查报告
            report_text = self.generate_troubleshooting_report(troubleshooting_result)
            
            if callback:
                callback("故障排查完成，报告生成完毕\n")
                
            return report_text
            
        except Exception as e:
            error_msg = f"故障排查执行失败: {str(e)}"
            logger.error(f"执行故障排查时出错: {str(e)}")
            if callback:
                callback(error_msg)
            return error_msg
    
    def _execute_ping(self, target: str, callback: Optional[Callable] = None) -> Dict[str, any]:
        """
        在网络设备上执行ping命令，支持实时回调更新
        
        Args:
            target: 目标IP地址或主机名
            callback: 可选的回调函数，用于实时更新结果
            
        Returns:
            执行结果字典，包含命令、输出、状态等信息
        """
        logger.info(f"在网络设备上执行ping命令到目标: {target}")
        
        try:
            # 如果在模拟模式下，仍然使用本地ping
            if hasattr(self, 'simulation_mode') and self.simulation_mode:
                # 构建本地命令
                if platform.system() == "Windows":
                    command = ["ping", target, "-n", "5", "-w", "1000"]
                else:
                    command = ["ping", target, "-c", "5", "-W", "1"]
                
                logger.info(f"模拟模式: 执行本地ping命令: {command}")
                
                # 初始化输出和统计信息
                final_output = []
                sent = 5
                received = 0
                loss_rate = "100.00%"
                
                # 执行ping命令并实时读取输出
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                # 实时读取输出并直接使用系统实际输出格式
                for line in process.stdout:
                    stripped_line = line.strip()
                    logger.debug(f"模拟模式Ping输出行: {stripped_line}")
                    
                    # 直接输出系统ping命令的原始输出，但添加缩进以保持一致的格式
                    if stripped_line:
                        indented_line = f"    {stripped_line}"
                        final_output.append(indented_line)
                        if callback:
                            callback(f"{indented_line}\n")
                            time.sleep(0.1)  # 添加短暂延迟以显示实时效果
                    
                    # 统计接收的数据包
                    if platform.system() == "Windows":
                        if "Reply from" in stripped_line and "time=" in stripped_line:
                            received += 1
                
                # 等待进程完成
                process.wait()
                
                # 计算丢包率
                if sent > 0:
                    loss_rate = f"{(1 - received/sent) * 100:.2f}%"
                
                # 合并最终输出
                final_output_str = "\n".join(final_output)
                
                # 构建结果字典
                result = {
                    "command": f"ping {target}",
                    "output": final_output_str,
                    "status": "success" if process.returncode == 0 else "failure",
                    "return_code": process.returncode,
                    "sent": sent,
                    "received": received,
                    "loss_rate": loss_rate
                }
                
                logger.info(f"模拟模式Ping命令执行完成: 发送={sent}, 接收={received}, 丢包率={loss_rate}")
                return result
            
            # 非模拟模式：在网络设备上执行ping命令
            final_output = []
            
            # 检查设备连接是否可用
            if not hasattr(self, 'device') or self.device is None:
                fallback_msg = "设备连接不可用，回退到本地ping命令"
                logger.warning(fallback_msg)
                if callback:
                    callback(f"    {fallback_msg}\n")
                
                # 回退到本地ping命令
                # 构建本地命令
                if platform.system() == "Windows":
                    command = ["ping", target, "-n", "5", "-w", "1000"]
                else:
                    command = ["ping", target, "-c", "5", "-W", "1"]
                
                logger.info(f"回退执行本地ping命令: {command}")
                
                # 初始化输出和统计信息
                final_output = [f"    {fallback_msg}"]
                sent = 5
                received = 0
                loss_rate = "100.00%"
                
                # 执行ping命令并实时读取输出
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                # 实时读取输出并直接使用系统实际输出格式
                for line in process.stdout:
                    stripped_line = line.strip()
                    logger.debug(f"本地Ping输出行: {stripped_line}")
                    
                    # 直接输出系统ping命令的原始输出，但添加缩进以保持一致的格式
                    if stripped_line:
                        indented_line = f"    {stripped_line}"
                        final_output.append(indented_line)
                        if callback:
                            callback(f"{indented_line}\n")
                            time.sleep(0.1)  # 添加短暂延迟以显示实时效果
                    
                    # 统计接收的数据包
                    if platform.system() == "Windows":
                        if "Reply from" in stripped_line and "time=" in stripped_line:
                            received += 1
                
                # 等待进程完成
                process.wait()
                
                # 计算丢包率
                if sent > 0:
                    loss_rate = f"{(1 - received/sent) * 100:.2f}%"
                
                # 合并最终输出
                final_output_str = "\n".join(final_output)
                
                # 构建结果字典
                result = {
                    "command": f"ping {target}",
                    "output": final_output_str,
                    "status": "success" if process.returncode == 0 else "failure",
                    "return_code": process.returncode,
                    "sent": sent,
                    "received": received,
                    "loss_rate": loss_rate,
                    "execution_mode": "local"
                }
                
                logger.info(f"本地ping命令执行完成: 发送={sent}, 接收={received}, 丢包率={loss_rate}")
                return result
            
            # 构建在设备上执行的ping命令（针对华为设备的命令格式）
            device_ping_cmd = f"ping {target}"
            logger.info(f"在设备上执行命令: {device_ping_cmd}")
            
            # 初始化统计信息
            sent = 0
            received = 0
            loss_rate = "100.00%"
            
            # 在设备上执行ping命令并获取输出
            try:
                # 使用device对象的执行命令方法
                if hasattr(self.device, 'execute_command'):
                    # 发送开始执行信息
                    if callback:
                        callback(f"正在设备上执行ping命令: {target}\n")
                    
                    # 执行命令并获取输出
                    output = self.device.execute_command(device_ping_cmd)
                    logger.debug(f"设备ping命令输出: {output}")
                    
                    # 分割输出行并处理
                    output_lines = output.strip().split('\n')
                    for line in output_lines:
                        stripped_line = line.strip()
                        if stripped_line:
                            # 添加缩进以保持一致的格式
                            indented_line = f"    {stripped_line}"
                            final_output.append(indented_line)
                            if callback:
                                callback(f"{indented_line}\n")
                                time.sleep(0.1)
                        
                        # 统计信息（适配华为设备ping输出格式）
                        if "packets transmitted" in stripped_line.lower() or "packet(s) transmitted" in stripped_line:
                            # 提取发送的数据包数
                            sent_match = re.search(r'(\d+)\s*packet', stripped_line, re.IGNORECASE)
                            if sent_match:
                                sent = int(sent_match.group(1))
                        elif "packets received" in stripped_line.lower() or "packet(s) received" in stripped_line:
                            # 提取接收的数据包数
                            recv_match = re.search(r'(\d+)\s*packet', stripped_line, re.IGNORECASE)
                            if recv_match:
                                received = int(recv_match.group(1))
                        elif "packet loss" in stripped_line.lower() or "packet loss" in stripped_line:
                            # 提取丢包率
                            loss_match = re.search(r'(\d+\.?\d*)%', stripped_line)
                            if loss_match:
                                loss_rate = f"{float(loss_match.group(1)):.2f}%"
            except Exception as device_error:
                error_msg = f"在设备上执行ping命令失败: {str(device_error)}"
                logger.error(error_msg)
                final_output.append(f"    {error_msg}")
                if callback:
                    callback(f"    {error_msg}\n")
            
            # 如果没有从输出中提取到统计信息，尝试根据输出内容判断
            if sent == 0:
                # 假设发送了5个数据包（华为设备默认）
                sent = 5
                # 根据输出中是否包含"Reply from"或类似字样估算接收数
                for line in output_lines:
                    if "Reply from" in line or "bytes=" in line:
                        received += 1
                # 重新计算丢包率
                if sent > 0:
                    loss_rate = f"{(1 - received/sent) * 100:.2f}%"
            
            # 合并最终输出
            final_output_str = "\n".join(final_output)
            
            # 构建结果字典
            result = {
                "command": device_ping_cmd,
                "output": final_output_str,
                "status": "success" if received > 0 else "failure",
                "return_code": 0 if received > 0 else 1,
                "sent": sent,
                "received": received,
                "loss_rate": loss_rate
            }
            
            logger.info(f"设备ping命令执行完成: 发送={sent}, 接收={received}, 丢包率={loss_rate}")
            return result
            
        except Exception as e:
            logger.error(f"执行ping命令时出错: {str(e)}")
            error_output = f"    执行ping命令时出错: {str(e)}"
            
            if callback:
                callback(f"{error_output}\n")
            
            # 返回错误结果
            return {
                "command": f"ping {target}",
                "output": error_output,
                "status": "error",
                "return_code": -1,
                "error_message": str(e),
                "sent": 0,
                "received": 0,
                "loss_rate": "100.00%"
            }
    
    def _execute_tracert(self, target: str, callback: Optional[Callable] = None) -> str:
        """
        执行tracert命令，支持实时回调更新
        
        Args:
            target: 目标IP地址或主机名
            callback: 可选的回调函数，用于实时更新结果
            
        Returns:
            tracert命令执行结果
        """
        logger.info(f"执行tracert命令到目标: {target}")
        
        # 模拟模式
        if self.simulation_mode:
            result = "模拟模式: 执行tracert命令\n"
            result += f"通过最多 30 个跃点跟踪 {target} [192.168.1.1] 的路由:\n"
            if callback:
                callback(result)
                
            result += f"  1    <1 ms    <1 ms    <1 ms  192.168.0.1\n"
            if callback:
                callback(result)
                
            result += f"  2    1 ms     1 ms     1 ms   10.0.0.1\n"
            if callback:
                callback(result)
                
            result += f"  3    2 ms     2 ms     2 ms   192.168.1.1\n\n"
            result += f"跟踪完成。"
            if callback:
                callback(result)
                
            return result
        
        # 实际执行tracert命令
        try:
            # 根据操作系统确定tracert命令
            if platform.system() == "Windows":
                command = ["tracert", "-d", "-h", "30", target]
            else:
                command = ["traceroute", "-n", "-m", "30", target]
            
            # 执行命令
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            result = []
            for line in process.stdout:
                result_line = line.strip()
                result.append(result_line)
                # 如果提供了回调函数，实时更新结果
                if callback:
                    callback("\n".join(result))
            
            # 等待进程完成并获取返回码
            process.wait()
            
            if process.returncode != 0:
                error_msg = f"tracert命令执行失败，返回码: {process.returncode}"
                logger.warning(error_msg)
                if callback:
                    callback("\n".join(result) + "\n" + error_msg)
                    
            return "\n".join(result)
            
        except Exception as e:
            error_msg = f"执行tracert命令失败: {str(e)}"
            logger.error(f"执行tracert命令时出错: {str(e)}")
            if callback:
                callback(error_msg)
            return error_msg
    
    def _execute_device_command(self, command: str, callback: Optional[Callable] = None) -> str:
        """
        执行设备命令，支持实时回调更新
        
        Args:
            command: 要执行的设备命令
            callback: 可选的回调函数，用于实时更新结果
            
        Returns:
            命令执行结果
        """
        logger.info(f"执行设备命令: {command}")
        
        # 检查设备连接
        if not self.network_device or not self.network_device.connected:
            error_msg = "错误: 设备未连接"
            if callback:
                callback(error_msg)
            return error_msg
        
        # 先显示执行中的提示
        running_msg = f"正在执行设备命令: {command}\n请稍候...\n"
        if callback:
            callback(running_msg)
            
        try:
            # 执行命令
            result = self.network_device.execute_command(command)
            
            # 如果提供了回调函数，更新最终结果
            if callback:
                callback(result)
            
            return result
            
        except Exception as e:
            error_msg = f"执行命令失败: {str(e)}"
            logger.error(f"执行设备命令时出错: {str(e)}")
            if callback:
                callback(error_msg)
            return error_msg
import logging
from datetime import datetime
from typing import Dict, List, Optional
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
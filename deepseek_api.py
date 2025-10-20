import requests
import re
from typing import Dict, Any, Optional, List
import logging
from config import (
    DEEPSEEK_API_KEY, 
    DEEPSEEK_API_URL, 
    SIMULATION_MODE,
    SIMULATION_COMMANDS,
    HUAWEI_CONFIG_TEMPLATES
)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DeepSeekAPI:
    """DeepSeek API客户端，用于自然语言转配置命令"""
    
    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None, 
                 simulation_mode: Optional[bool] = None):
        """初始化DeepSeek API客户端
        
        Args:
            api_key: DeepSeek API密钥
            api_url: DeepSeek API URL
            simulation_mode: 是否使用模拟模式
        """
        # 使用传入的参数或从配置文件中获取默认值
        self.api_key = api_key if api_key is not None else DEEPSEEK_API_KEY
        self.api_url = api_url if api_url is not None else DEEPSEEK_API_URL
        self.simulation_mode = simulation_mode if simulation_mode is not None else SIMULATION_MODE
        
        # 如果没有有效的API密钥，自动切换到模拟模式
        if not self.api_key:
            self.simulation_mode = True
            logger.warning("未提供DeepSeek API密钥，自动切换到模拟模式")
    
    def _call_api(self, prompt: str, max_tokens: int = 1000) -> str:
        """调用DeepSeek API生成响应
        
        Args:
            prompt: 提示文本
            max_tokens: 最大生成token数
            
        Returns:
            生成的配置命令或错误信息
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # 根据官方文档，构建正确的API URL
        # 官方文档指出base_url可以是 https://api.deepseek.com 或 https://api.deepseek.com/v1
        # 但实际调用时需要添加 /chat/completions 路径
        base_url = self.api_url.rstrip('/')
        
        # 确保URL格式正确，根据官方文档添加必要的路径
        if not (base_url.endswith('/v1/chat/completions') or base_url.endswith('/chat/completions')):
            if base_url.endswith('/v1'):
                api_url = f"{base_url}/chat/completions"
            else:
                api_url = f"{base_url}/v1/chat/completions"
        else:
            api_url = base_url
        
        logger.info(f"使用标准格式API URL: {api_url}")
        
        # 使用符合OpenAI兼容格式的payload
        payload = {
            "model": "deepseek-chat",  # 使用官方推荐的模型名称
            "messages": [
                {"role": "system", "content": "You are a helpful assistant"},  # 添加system消息以符合标准格式
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": max_tokens,
            "stream": False  # 非流式输出
        }
        
        try:
            logger.info(f"正在调用DeepSeek API: {prompt[:50]}...")
            logger.info(f"API URL: {api_url}")
            logger.info(f"请求头: Content-Type={headers['Content-Type']}, Authorization=Bearer ******")
            
            response = requests.post(api_url, headers=headers, json=payload, timeout=30)
            
            logger.info(f"API响应状态码: {response.status_code}")
            
            # 检查HTTP状态码
            if response.status_code == 200:
                data = response.json()
                logger.info(f"API响应数据结构: {list(data.keys())}")
                
                # 尝试不同的响应解析方式，适应不同API格式
                if "choices" in data and len(data["choices"]) > 0:
                    if "message" in data["choices"][0] and "content" in data["choices"][0]["message"]:
                        return data["choices"][0]["message"]["content"]
                    elif "text" in data["choices"][0]:
                        return data["choices"][0]["text"]
                    else:
                        logger.error(f"API响应格式不匹配: {data['choices'][0]}")
                        return f"API响应格式不匹配: {str(data['choices'][0])[:100]}..."
                else:
                    logger.error(f"API响应缺少choices字段: {data}")
                    return f"API响应格式错误: 缺少预期的响应内容"
            elif response.status_code == 401:
                error_msg = "401 Unauthorized: API密钥无效或已过期"
                logger.error(f"调用DeepSeek API时出错: {error_msg}")
                raise Exception(error_msg)
            elif response.status_code == 402:
                error_msg = "402 Payment Required: API调用余额不足，请检查API密钥"
                logger.error(f"调用DeepSeek API时出错: {error_msg}")
                # 在余额不足情况下提供更友好的回退选项
                print("\n⚠️  注意: API调用余额不足，将自动切换到模拟模式继续操作\n")
                self.simulation_mode = True
                return "模拟模式回退: 由于API调用余额不足，将使用模拟数据进行操作"
            elif response.status_code == 403:
                error_msg = "403 Forbidden: 权限不足，无法访问此资源"
                logger.error(f"调用DeepSeek API时出错: {error_msg}")
                raise Exception(error_msg)
            elif response.status_code == 404:
                error_msg = f"404 Not Found: API接口地址不存在，请检查URL: {self.api_url}"
                logger.error(f"调用DeepSeek API时出错: {error_msg}")
                raise Exception(error_msg)
            elif response.status_code == 429:
                error_msg = "429 Too Many Requests: API调用频率超限，请稍后再试"
                logger.error(f"调用DeepSeek API时出错: {error_msg}")
                raise Exception(error_msg)
            else:
                # 尝试获取响应内容作为错误信息
                try:
                    error_details = response.json()
                    error_msg = f"HTTP错误 {response.status_code}: {error_details}"
                except:
                    error_msg = f"HTTP错误 {response.status_code}: {response.text[:200]}..."
                logger.error(f"调用DeepSeek API时出错: {error_msg}")
                raise Exception(error_msg)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"API请求异常: {str(e)}")
            raise Exception(f"网络连接错误: {str(e)}")
        except KeyError as e:
            logger.error(f"API响应格式错误: {str(e)}")
            return "API响应格式错误: 返回数据结构不符合预期"
        except Exception as e:
            logger.error(f"调用DeepSeek API时出错: {str(e)}")
            raise
    
    def generate_config_from_natural_language(self, natural_language: str) -> str:
        """将自然语言转换为配置命令
        
        Args:
            natural_language: 自然语言描述的配置需求
            
        Returns:
            生成的配置命令
        """
        logger.info(f"将自然语言转换为配置命令: {natural_language}")
        
        # 检查是否在模拟模式下
        if self.simulation_mode:
            logger.info("使用模拟模式生成配置命令")
            
            # 检查是否有预定义的模拟命令
            for key, commands in SIMULATION_COMMANDS.items():
                if key in natural_language:
                    return commands
            
            # 增加telnet配置的模拟命令支持
            if any(keyword in natural_language.lower() for keyword in ["telnet", "远程登录"]):
                # 尝试提取接口号
                interface_match = re.search(r'(g\s*\d+/\d+/\d+)', natural_language.lower())
                interface = interface_match.group(1).replace(' ', '') if interface_match else "GigabitEthernet0/0/0"
                
                return f"system-view\naaa\nlocal-user admin password cipher Admin@123\nlocal-user admin privilege level 15\nlocal-user admin service-type telnet\nquit\ntelnet server enable\ninterface {interface}\nip address 192.168.1.1 255.255.255.0\nquit"
            
            # 如果没有预定义的命令，尝试使用关键词生成配置
            # 调整条件判断顺序，先检查更具体的配置类型
            # 优化关键词匹配，使其更健壮地处理中文输入和不同格式
            if any(keyword in natural_language.lower() for keyword in ["access模式", "access接口", "access类型"]) and any(intf_keyword in natural_language.lower() for intf_keyword in ["接口", "interface"]):
                # 尝试提取接口号和VLAN ID
                # 修复接口号提取的正则表达式
                interface_match = re.search(r'(?:接口|interface)\s*(gigabitethernet\d+/\d+/\d+)', natural_language.lower())
                vlan_match = re.search(r'vlan\s*(\d+)', natural_language.lower())
                
                interface = interface_match.group(1) if interface_match else "GigabitEthernet0/0/1"
                vlan_id = vlan_match.group(1) if vlan_match else "10"
                
                return f"system-view\ninterface {interface}\nport link-type access\nport default vlan {vlan_id}\nquit"
            
            elif any(keyword in natural_language.lower() for keyword in ["trunk模式", "trunk接口", "trunk类型"]) and any(intf_keyword in natural_language.lower() for intf_keyword in ["接口", "interface"]):
                # 尝试提取接口号
                interface_match = re.search(r'(?:接口|interface)\s*(gigabitethernet\d+/\d+/\d+)', natural_language.lower())
                interface = interface_match.group(1) if interface_match else "GigabitEthernet0/0/1"
                
                return f"system-view\ninterface {interface}\nport link-type trunk\nport trunk allow-pass vlan 2 to 4094\nquit"
            
            elif "vlan" in natural_language.lower():
                # 检查是否包含删除VLAN的关键词
                if any(keyword in natural_language.lower() for keyword in ["删除vlan", "删除 vlan", "移除vlan", "移除 vlan", "undo vlan"]):
                    # 尝试提取所有数字作为VLAN ID
                    vlan_ids = re.findall(r'\b\d+\b', natural_language)
                    if vlan_ids:
                        # 去重并保留原始顺序
                        unique_vlan_ids = []
                        seen = set()
                        for vlan_id in vlan_ids:
                            if vlan_id not in seen:
                                seen.add(vlan_id)
                                unique_vlan_ids.append(vlan_id)
                        # 生成独立的删除命令，使用分号加空格分隔
                        commands = []
                        for vlan_id in unique_vlan_ids:
                            commands.append(f"undo vlan {vlan_id}")
                        return "; ".join(commands)
                # 检查是否包含查看VLAN的关键词
                elif any(keyword in natural_language.lower() for keyword in ["查看vlan", "查看 vlan", "display vlan", "显示vlan", "显示 vlan"]):
                    # 查看VLAN信息的命令，不需要进入系统视图
                    return "display vlan"
                # 明确检查是否包含创建VLAN的关键词
                elif any(keyword in natural_language.lower() for keyword in ["创建vlan", "创建 vlan", "新建vlan", "新建 vlan", "add vlan"]):
                    # 尝试提取单个VLAN ID，支持中文格式如"vlan20"或"vlan 20"
                    vlan_match = re.search(r'vlan\s*(\d+)', natural_language.lower())
                    vlan_id = vlan_match.group(1) if vlan_match else "10"
                    return f"system-view\nvlan {vlan_id}\nquit"
                # 默认情况，尝试提取单个VLAN ID
                vlan_match = re.search(r'vlan\s*(\d+)', natural_language.lower())
                vlan_id = vlan_match.group(1) if vlan_match else "10"
                return f"system-view\nvlan {vlan_id}\nquit"
            
            # 如果没有匹配任何预定义模式，返回一个通用的配置模板
            return "system-view\n# 模拟模式下的默认配置命令\nquit"
        
        # 非模拟模式下，调用DeepSeek API
        prompt = f'''
请将以下自然语言描述转换为HUAWEI交换机配置命令：
{natural_language}

请只返回纯配置命令，不要包含任何解释、说明或标记文本。对于多个VLAN删除请求，请为每个VLAN生成独立的'undo vlan'命令，使用分号分隔。
'''
        
        return self._call_api(prompt)
    
    def validate_config(self, config: str) -> Dict[str, Any]:
        """验证配置命令的正确性
        
        Args:
            config: 要验证的配置命令
            
        Returns:
            验证结果，包含valid（是否有效）、errors（错误列表）、corrected_commands（修正后的命令）
        """
        logger.info("验证配置命令")
        
        # 检查是否在模拟模式下
        if self.simulation_mode:
            logger.info("使用模拟模式验证配置命令")
            
            # 简单的模拟验证逻辑
            errors = []
            
            # 检查是否有system-view和quit命令
            if "system-view" not in config and "sys" not in config:
                errors.append("缺少进入系统视图的命令 'system-view' 或 'sys'")
            
            # 检查是否有错误的命令格式
            invalid_patterns = [r'^\s*$', r'^#.*$']  # 空行和注释行不算错误
            lines = config.split('\n')
            for i, line in enumerate(lines):
                if line.strip() and not any(re.match(pattern, line) for pattern in invalid_patterns):
                    # 简单检查命令格式，实际应用中可能需要更复杂的验证
                    pass
            
            # 生成修正后的命令（如果有错误）
            corrected_commands = config
            if errors:
                if "缺少进入系统视图的命令" in errors[0]:
                    if "system-view" not in config:
                        corrected_commands = "system-view\n" + config
            
            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "corrected_commands": corrected_commands if errors else None
            }
        
        # 非模拟模式下，调用DeepSeek API进行验证
        prompt = f'''
请验证以下HUAWEI交换机配置命令是否正确：
{config}

如果有错误，请指出错误并提供修正后的命令。

请以JSON格式返回验证结果，包含以下字段：
- valid: 布尔值，表示命令是否有效
- errors: 字符串数组，如果有错误，请列出每个错误
- corrected_commands: 字符串，如果命令有错误，请提供修正后的命令
'''
        
        try:
            result = self._call_api(prompt)
            
            # 尝试解析JSON响应
            try:
                import json
                validation_result = json.loads(result)
                
                # 确保返回格式正确
                if isinstance(validation_result, dict):
                    # 确保包含必要的字段
                    if "valid" not in validation_result:
                        validation_result["valid"] = False
                        validation_result["errors"] = ["API返回的验证结果缺少必要字段"]
                    if "errors" not in validation_result:
                        validation_result["errors"] = []
                    if "corrected_commands" not in validation_result:
                        validation_result["corrected_commands"] = None
                    
                    return validation_result
            except json.JSONDecodeError:
                # 如果返回的不是JSON，尝试使用正则表达式提取信息
                valid = True
                errors = []
                corrected_commands = None
                
                # 检查是否明确指出无效
                if any(invalid_marker in result.lower() for invalid_marker in ["无效", "错误", "false", "invalid"]):
                    valid = False
                
                # 尝试提取错误信息（包括中文和英文格式）
                if not valid:
                    # 尝试多种可能的错误信息格式
                    error_patterns = [
                        r'错误列表：\[(.*?)\]',  # 中文格式
                        r'errors?：?\[(.*?)\]',  # 英文格式
                        r'错误[:：]?(.*?)[\n;]',  # 简单错误格式
                        r'error[:：]?(.*?)[\n;]'  # 简单英文错误格式
                    ]
                    
                    for pattern in error_patterns:
                        matches = re.findall(pattern, result, re.DOTALL | re.IGNORECASE)
                        for match in matches:
                            if match.strip() and match.strip() not in errors:
                                errors.append(match.strip())
                    
                    # 如果没有找到具体错误，添加一个通用错误
                    if not errors:
                        errors.append("配置命令存在问题，请检查")
                    
                    # 尝试提取修正后的命令
                    corrected_patterns = [
                        r'修正后命令：\[(.*?)\]',  # 中文格式
                        r'corrected_commands?：?\[(.*?)\]',  # 英文格式
                        r'正确的命令[:：]?(.*?)(\n\n|$)',  # 简单中文格式
                        r'correct command[:：]?(.*?)(\n\n|$)'  # 简单英文格式
                    ]
                    
                    for pattern in corrected_patterns:
                        match = re.search(pattern, result, re.DOTALL | re.IGNORECASE)
                        if match:
                            corrected_commands = match.group(1).strip()
                            break
                
                return {
                    "valid": valid,
                    "errors": errors,
                    "corrected_commands": corrected_commands
                }
        except Exception as e:
            logger.error(f"验证配置命令时出错: {str(e)}")
            return {
                "valid": False,
                "errors": [f"验证过程中发生错误: {str(e)}"],
                "corrected_commands": None
            }
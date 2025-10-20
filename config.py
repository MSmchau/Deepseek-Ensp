# DeepSeek API配置
DEEPSEEK_API_KEY = "sk-c6f905086e174f72979f317fae5f82d3"  # 请替换为您的DeepSeek API密钥
DEEPSEEK_API_URL = "https://api.deepseek.com/v1"  # DeepSeek API接口地址，符合官方文档要求

# 设备连接配置
DEVICE_TYPE = "AR2"  # 设备类型
DEFAULT_DEVICE_IP = "192.168.56.254"  # 默认设备IP地址
DEFAULT_DEVICE_PORT = 22  # 默认SSH端口
DEFAULT_DEVICE_USERNAME = "admin"  # 默认用户名
DEFAULT_DEVICE_PASSWORD = "admin@123"  # 默认密码

# 模拟模式配置
SIMULATION_MODE = False  # 设置为True可以在没有API密钥的情况下模拟API响应

# 华为设备语法模板
HUAWEI_CONFIG_TEMPLATES = {
    "create_vlan": "vlan {vlan_id}\nquit",
    "interface_description": "interface {interface}\ndescription {description}\nquit",
    "interface_access_vlan": "interface {interface}\nport link-type access\nport default vlan {vlan_id}\nquit",
    "interface_trunk_vlan": "interface {interface}\nport link-type trunk\nport trunk allow-pass vlan {vlan_ids}\nquit",
    "create_loopback": "interface LoopBack{vlan_id}\nip address {ip_address} {mask}\nquit",
    "save_config": "save\ny",
    "display_vlan": "display vlan"
}

# 模拟配置命令映射
SIMULATION_COMMANDS = {
    "配置vlan10": "system-view\nvlan 10\nquit",
    "创建vlan10": "system-view\nvlan 10\nquit",
    "设置接口g0/0/1为access模式": "system-view\ninterface GigabitEthernet 0/0/1\nport link-type access\nquit",
    "将接口g0/0/1加入vlan10": "system-view\ninterface GigabitEthernet 0/0/1\nport default vlan 10\nquit",
    "配置trunk": "system-view\ninterface GigabitEthernet 0/0/2\nport link-type trunk\nport trunk allow-pass vlan 10 20\nquit"
}

# 日志配置
LOG_LEVEL = "INFO"  # 日志级别：DEBUG, INFO, WARNING, ERROR, CRITICAL
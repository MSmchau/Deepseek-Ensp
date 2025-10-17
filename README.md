# DeepSeek接入Ensp - 网络配置自动化助手

这个项目实现了通过DeepSeek API将自然语言转换为华为网络设备配置命令，并自动连接到eNSP模拟环境中的设备执行配置、故障排查以及对交换机和路由器进行完整的CRUD操作。

## 功能概述

1. **自然语言转配置命令**：使用DeepSeek API将自然语言描述转换为华为设备CLI配置命令
2. **设备连接与配置执行**：通过SSH自动连接到eNSP中的设备并执行配置命令
3. **自动故障排查**：收集设备信息，分析潜在问题，并生成详细的故障排查报告
4. **配置验证**：验证生成的配置命令是否符合华为设备语法规范
5. **设备CRUD操作**：通过API实现对eNSP中交换机和路由器的新增、删除、修改及查询操作

## 环境要求

- Python 3.7+
- VirtualBox (已安装)
- eNSP (已安装)
- 有效的DeepSeek API密钥

## 安装步骤

1. 克隆或下载本项目到本地

2. 安装所需的Python依赖包：

```bash
cd d:\Python\Deepseek接入Ensp
pip install -r requirements.txt
```

3. 配置DeepSeek API密钥和设备连接信息：

编辑 `config.py` 文件，替换以下内容：

```python
# 替换为您的DeepSeek API密钥
DEEPSEEK_API_KEY = "your_api_key_here"

# 根据您的eNSP环境修改默认设备参数
DEFAULT_DEVICE_IP = "192.168.56.254"  # eNSP设备的IP地址
DEFAULT_DEVICE_PORT = 22  # SSH端口
DEFAULT_DEVICE_USERNAME = "admin"  # 设备用户名
DEFAULT_DEVICE_PASSWORD = "admin@123"  # 设备密码

# 报告文件路径
DEFAULT_REPORT_FILE = "troubleshooting_report.txt"
```

## 设备CRUD操作详解

### 概述

本项目通过DeepSeek API实现对网络设备（交换机、路由器）的完整CRUD（创建、读取、更新、删除）操作。通过将自然语言转换为对应的配置命令和操作指令，实现对eNSP模拟环境中设备的高效管理。

### API架构与调用流程

#### 核心接口设计

项目中通过`deepseek_api.py`模块封装了所有CRUD相关的API调用：

1. **设备创建接口**：`create_device(device_type, device_config)`
2. **设备查询接口**：`get_device(device_id)`
3. **设备更新接口**：`update_device(device_id, device_config)`
4. **设备删除接口**：`delete_device(device_id)`
5. **设备列表接口**：`list_devices(filter_criteria=None)`

#### 调用流程

CRUD操作的一般调用流程如下：

1. **身份验证**：使用DeepSeek API密钥进行身份验证
2. **请求构建**：根据操作类型构建适当的API请求
3. **参数验证**：验证设备参数的有效性和完整性
4. **API调用**：发送请求到DeepSeek API服务器获取设备操作命令
5. **响应处理**：处理API响应，将自然语言转换为设备操作指令
6. **错误处理**：处理各种可能的错误情况（网络问题、认证失败、参数错误等）

### 具体操作实现

#### 1. 设备创建（Create）

**功能说明**：在eNSP环境中创建新的网络设备（交换机或路由器）

**技术流程**：
1. 接收设备类型（交换机/路由器）和基本配置参数
2. 通过DeepSeek API将自然语言需求转换为详细配置命令
3. 使用转换后的配置命令在eNSP环境中创建设备
4. 返回创建的设备ID和基本信息

**支持的设备类型**：
- 华为S系列交换机（S2700、S3700、S5700等）
- 华为AR系列路由器（AR1200、AR2200、AR3200等）

#### 2. 设备查询（Read）

**功能说明**：获取单个设备详情或设备列表

**技术流程**：
1. 提供设备ID或查询条件
2. 通过DeepSeek API生成查询命令
3. 执行命令获取设备信息（接口状态、配置、性能指标等）
4. 以结构化格式呈现设备信息

**支持的查询方式**：
- 按设备ID精确查询
- 按设备类型筛选
- 按设备名称模糊查询
- 按在线状态筛选

#### 3. 设备更新（Update）

**功能说明**：修改现有设备的配置或属性

**技术流程**：
1. 确定目标设备（通过设备ID）
2. 提供需要更新的配置参数
3. 通过DeepSeek API将自然语言需求转换为配置命令
4. 执行配置命令更新设备设置
5. 验证配置变更是否成功应用

**支持的更新类型**：
- 接口配置更新
- VLAN配置修改
- 路由协议参数调整
- 设备基本属性修改（名称、位置等）

#### 4. 设备删除（Delete）

**功能说明**：从eNSP环境中删除指定设备

**技术流程**：
1. 确定要删除的设备（通过设备ID）
2. 验证设备是否存在且可删除
3. 通过DeepSeek API生成设备删除相关命令
4. 执行命令删除设备并确认删除结果

**安全机制**：
- 删除前进行二次确认
- 保留删除操作的日志记录
- 对于连接状态的设备，提供强制删除选项

### 与自然语言处理的集成

项目将DeepSeek API的自然语言处理能力与CRUD操作无缝集成：

1. **自然语言解析**：将类似"创建一台S5700交换机并配置VLAN 10"的请求解析为结构化参数
2. **操作意图识别**：自动识别用户意图（创建、查询、更新或删除设备）
3. **参数提取**：从自然语言中提取设备类型、配置参数等必要信息
4. **结果自然语言描述**：将CRUD操作结果以自然语言形式返回给用户

### 批量操作支持

项目支持对多台设备进行批量CRUD操作：

1. **批量创建**：一次创建多台相同或不同类型的设备
2. **批量查询**：同时获取多台设备的信息
3. **批量更新**：对多台设备应用相同的配置变更
4. **批量删除**：删除多个指定的设备

## 使用方法

### 基本使用流程

1. 在eNSP中创建一个简单的单交换机拓扑并启动设备
2. 确保设备已配置好IP地址和SSH服务
3. 运行主程序进行配置或故障排查

### 命令行参数

```
python main.py [选项]
```

主要选项：

- `--ip`: 设备IP地址 (默认为配置文件中的值)
- `--port`: SSH端口 (默认为22)
- `--username`: 登录用户名 (默认为配置文件中的值)
- `--password`: 登录密码 (默认为配置文件中的值)
- `--mode`: 操作模式 (config/troubleshoot/both/create/read/update/delete，默认为both)
- `--natural-language`: 自然语言描述的配置需求
- `--config-file`: 包含配置命令的文件路径
- `--report-file`: 故障排查报告保存路径 (默认为troubleshooting_report.txt)
- `--device-id`: 设备ID（用于read、update、delete操作）

### 使用示例

#### 1. 交互式配置和故障排查

```bash
python main.py
```

运行后会提示您输入自然语言配置需求，例如："配置VLAN 10并将接口GigabitEthernet 0/0/1加入VLAN 10"。

#### 2. 使用命令行参数指定自然语言配置

```bash
python main.py --natural-language "创建VLAN 10并设置描述为Server_VLAN"
```

#### 3. 仅执行故障排查

```bash
python main.py --mode troubleshoot
```

#### 4. 从配置文件执行配置

```bash
python main.py --mode config --config-file commands.txt
```

#### 5. CRUD操作示例

```bash
# 创建设备示例
python main.py --mode create --natural-language "创建一台S5700交换机，名称为SW1，配置VLAN 10和VLAN 20"

# 查询设备示例
python main.py --mode read --device-id "device123"

# 查询设备列表示例
python main.py --mode read --natural-language "列出所有在线的交换机"

# 更新设备示例
python main.py --mode update --device-id "device123" --natural-language "将SW1的G0/0/1端口配置为access模式并加入VLAN 30"

# 删除设备示例
python main.py --mode delete --device-id "device123"

## 实验建议

1. **从简单拓扑开始**：按照建议，先使用单交换机拓扑进行测试，避免复杂环境干扰调试
2. **验证网络连通性**：在运行程序前，确保主机可以ping通eNSP中的设备
3. **检查设备SSH服务**：确保eNSP设备已正确配置SSH服务
4. **API密钥配置**：确保已在config.py中正确配置DeepSeek API密钥
5. **逐步测试**：先测试自然语言到配置命令的转换功能，再测试设备连接和配置执行

## 故障排除

1. **API连接问题**：检查DeepSeek API密钥是否正确，网络是否可以访问API服务器
2. **设备连接失败**：确认eNSP设备IP地址、端口、用户名和密码是否正确，设备是否已启动SSH服务
3. **配置命令执行错误**：检查生成的配置命令是否符合设备型号的语法规范
4. **VirtualBox网络配置**：确保VirtualBox的网络设置正确，通常需要使用"仅主机适配器"或"桥接适配器"模式

## 注意事项

1. 使用前请确保您已了解基本的网络知识和华为设备配置命令
2. 在生产环境使用前，请在测试环境充分验证
3. 定期更新依赖包以获取最新功能和安全修复
4. 注意保护您的DeepSeek API密钥，避免泄露
5. **CRUD操作安全性**：
   - 删除设备前务必确认设备ID的准确性
   - 在生产环境中执行批量操作时，建议先在测试环境验证
   - 对于重要设备的更新操作，建议先进行配置验证
6. **API调用限制**：DeepSeek API可能有调用频率限制，请避免过于频繁的请求
7. **错误处理**：程序已实现基本的错误处理机制，但复杂网络环境下可能出现未预见的错误，请检查日志获取详细信息

## 文件结构

- `config.py`: 配置文件，包含API密钥和设备连接信息
- `deepseek_api.py`: DeepSeek API交互模块，处理自然语言转配置命令
- `network_device.py`: 网络设备连接模块，处理SSH连接和命令执行
- `troubleshooter.py`: 故障排查模块，分析设备状态并生成报告
- `main.py`: 主程序，整合所有功能模块
- `requirements.txt`: Python依赖包列表
- `README.md`: 项目说明文档

## 不创建多余测试脚本，所有增加、删除、修改，全部按照README.md: 项目说明文档进行
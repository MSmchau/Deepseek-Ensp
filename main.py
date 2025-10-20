import argparse
import logging
import time
import traceback
from typing import Optional
from config import (
    DEEPSEEK_API_KEY, 
    DEEPSEEK_API_URL, 
    SIMULATION_MODE,
    DEFAULT_DEVICE_IP, 
    DEFAULT_DEVICE_PORT, 
    DEFAULT_DEVICE_USERNAME, 
    DEFAULT_DEVICE_PASSWORD
)
from deepseek_api import DeepSeekAPI
from network_device import NetworkDevice
from troubleshooter import Troubleshooter

# 已经在文件顶部配置了日志

def process_config_command(natural_language: str, simulation_mode: bool, device_connected: bool, args=None):
    """
    处理配置命令的函数
    
    Args:
        natural_language: 自然语言描述的配置需求
        simulation_mode: 是否使用模拟模式
        device_connected: 设备是否已连接
        args: 命令行参数对象
    
    Returns:
        tuple: (commands, success) - 配置命令列表和操作是否成功的标志
    """
    logger.info(f"处理配置需求: {natural_language}")
    print("正在生成配置命令...")
    
    # 初始化DeepSeek API客户端
    try:
        deepseek_api = DeepSeekAPI(
            api_key=DEEPSEEK_API_KEY,
            api_url=DEEPSEEK_API_URL,
            simulation_mode=simulation_mode
        )
        
        # 验证API配置状态
        if deepseek_api.simulation_mode and not simulation_mode:
            logger.warning("虽然指定了实际模式，但系统自动切换到模拟模式，可能是API密钥配置有问题")
    except Exception as e:
        logger.error(f"DeepSeek API客户端初始化失败: {str(e)}")
        # 强制使用模拟模式
        simulation_mode = True
        deepseek_api = DeepSeekAPI(simulation_mode=True)
    
    # 初始化网络设备（如果已连接）
    device = None
    if device_connected and hasattr(args, 'ip'):
        try:
            device = NetworkDevice(
                ip=args.ip,
                port=getattr(args, 'port', DEFAULT_DEVICE_PORT),
                username=getattr(args, 'username', DEFAULT_DEVICE_USERNAME),
                password=getattr(args, 'password', DEFAULT_DEVICE_PASSWORD)
            )
            # 这里假设设备已经连接，所以不再次调用connect()
        except Exception as e:
            logger.error(f"初始化网络设备失败: {str(e)}")
            device = None
    
    # 如果提供了配置文件，从文件读取配置命令
    config_commands = None
    if hasattr(args, 'config_file') and args.config_file:
        try:
            with open(args.config_file, 'r', encoding='utf-8') as f:
                config_commands = f.read().strip()
                print(f"\n从配置文件读取命令成功: {args.config_file}")
                logger.info(f"从配置文件读取的命令: {config_commands}")
        except Exception as e:
            logger.error(f"读取配置文件失败: {str(e)}")
            print(f"❌ 读取配置文件失败: {str(e)}")
            # 如果读取失败，继续使用API生成命令
    
    try:
        # 只有在没有从配置文件读取到命令时，才使用DeepSeek API生成配置命令
        if config_commands is None:
            config_commands = deepseek_api.generate_config_from_natural_language(natural_language)
        
        # 显示生成的配置命令
        logger.info(f"配置命令内容: {config_commands}")
        print("\n配置命令:")
        print("=" * 60)
        print(config_commands)
        print("=" * 60)
        
        # 验证配置命令
        print("\n验证配置命令...")
        is_valid = deepseek_api.validate_config(config_commands)
        
        if is_valid:
            print("✅ 配置命令验证通过！")
            logger.info("配置命令验证通过")
            
            # 如果设备已连接，则尝试应用配置
            if device_connected and device:
                print("\n正在应用配置到设备...")
                try:
                    apply_result = device.execute_configuration(config_commands)
                    # 检查结果
                    success = all(not result.lower().startswith(('失败', '错误')) for result in apply_result.values())
                    if success:
                        print("✅ 配置已成功应用到设备！")
                        logger.info("配置已成功应用到设备")
                        # 显示详细结果
                        print("\n配置命令执行结果：")
                        for cmd, result in apply_result.items():
                            print(f"  {cmd} -> {result}")
                    else:
                        print("❌ 配置应用失败")
                        logger.error(f"配置应用失败: {apply_result}")
                        # 显示详细错误
                        print("\n配置命令执行结果：")
                        for cmd, result in apply_result.items():
                            print(f"  {cmd} -> {result}")
                    # 返回命令和成功标志
                    return config_commands.split('\n'), success
                except Exception as e:
                    print(f"❌ 应用配置到设备时出错: {str(e)}")
                    logger.error(f"应用配置到设备时出错: {str(e)}")
                    # 返回命令和失败标志
                    return config_commands.split('\n'), False
            else:
                # 设备未连接但命令验证通过
                return config_commands.split('\n'), True
        else:
            print("❌ 配置命令验证失败，请检查命令格式")
            logger.error("配置命令验证失败")
            return [], False
    except Exception as e:
        logger.error(f"生成配置命令失败: {str(e)}")
        print(f"\n❌ 生成配置命令失败: {str(e)}")
        
        # 在模拟模式下，即使API调用失败也提供一个模拟的配置命令
        if simulation_mode:
            print("\n在模拟模式下提供示例配置命令:")
            print("=" * 60)
            print("# 模拟配置命令示例\ninterface GigabitEthernet0/0\nip address 192.168.1.1 255.255.255.0\nquit")
            print("=" * 60)
        
        # 检查是否是API调用错误导致的
        if "402 Payment Required" in str(e):
            print("\n⚠️  API调用余额不足，请为您的API账户充值")
            print("系统将自动切换到模拟模式继续运行")
        elif "401 Unauthorized" in str(e):
            print("\n⚠️  API密钥无效或已过期，请检查config.py中的API密钥配置")
        
        return [], False

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='DeepSeek网络配置自动化助手')
    parser.add_argument('--ip', type=str, default=DEFAULT_DEVICE_IP, help='设备IP地址 (默认为配置文件中的值)')
    parser.add_argument('--port', type=int, default=DEFAULT_DEVICE_PORT, help='SSH端口 (默认为22)')
    parser.add_argument('--username', type=str, default=DEFAULT_DEVICE_USERNAME, help='登录用户名 (默认为配置文件中的值)')
    parser.add_argument('--password', type=str, default=DEFAULT_DEVICE_PASSWORD, help='登录密码 (默认为配置文件中的值)')
    parser.add_argument('--mode', type=str, choices=['config', 'troubleshoot', 'both'], default='both', help='操作模式 (config/troubleshoot/both，默认为both)')
    parser.add_argument('--natural-language', type=str, help='自然语言描述的配置需求')
    parser.add_argument('--config-file', type=str, help='包含配置命令的文件路径')
    parser.add_argument('--report-file', type=str, default='troubleshooting_report.txt', help='故障排查报告保存路径 (默认为troubleshooting_report.txt)')
    parser.add_argument('--simulation', action='store_true', help='强制使用模拟模式')
    parser.add_argument('--no-simulation', action='store_true', help='强制不使用模拟模式')
    parser.add_argument('--execute', action='store_true', help='自动执行配置命令，无需用户确认')
    parser.add_argument('--gui', action='store_true', help='启动图形用户界面')
    return parser.parse_args()

def main():
    """主函数"""
    logger.info("DeepSeek网络配置自动化助手启动")
    
    # 解析命令行参数
    args = parse_args()
    
    # 确定是否使用模拟模式
    simulation_mode = SIMULATION_MODE
    if args.simulation:
        simulation_mode = True
    elif args.no_simulation:
        simulation_mode = False
    
    # 显示模式信息
    if simulation_mode:
        logger.info("系统运行在模拟模式下")
        print("\n=== 模拟模式 ===")
        print("在模拟模式下，系统将使用预定义的命令和响应，无需实际的API调用或设备连接。")
        print("这对于测试和演示非常有用。\n")
    else:
        logger.info("系统运行在实际模式下")
        print("\n=== 实际模式 ===")
        print("在实际模式下，系统将尝试连接DeepSeek API和网络设备。")
        print("请确保已在config.py中正确配置API密钥和设备信息。\n")
    
    # 初始化DeepSeek API客户端
    try:
        deepseek_api = DeepSeekAPI(
            api_key=DEEPSEEK_API_KEY,
            api_url=DEEPSEEK_API_URL,
            simulation_mode=simulation_mode
        )
        
        # 验证API配置状态
        if deepseek_api.simulation_mode and not args.simulation:
            logger.warning("虽然指定了实际模式，但系统自动切换到模拟模式，可能是API密钥配置有问题")
            print("⚠️  注意: 虽然指定了实际模式，但系统自动切换到模拟模式")
            print("这可能是因为API密钥配置有问题或余额不足\n")
        elif not deepseek_api.simulation_mode:
            logger.info("成功初始化DeepSeek API客户端，使用实际API调用模式")
            print("✅ DeepSeek API客户端初始化成功，将使用实际API调用\n")
    except Exception as e:
        logger.error(f"DeepSeek API客户端初始化失败: {str(e)}")
        print(f"❌ DeepSeek API客户端初始化失败: {str(e)}")
        print("系统将自动切换到模拟模式继续运行\n")
        # 强制使用模拟模式
        simulation_mode = True
        deepseek_api = DeepSeekAPI(simulation_mode=True)
    
    # 初始化网络设备连接（如果需要）
    device: Optional[NetworkDevice] = None
    device_connected = False
    
    # 只有在非模拟模式且需要操作设备时才连接
    if not simulation_mode and (args.mode == 'config' or args.mode == 'troubleshoot' or args.mode == 'both'):
        try:
            logger.info(f"尝试连接设备 {args.ip}:{args.port}")
            device = NetworkDevice(
                ip=args.ip,
                port=args.port,
                username=args.username,
                password=args.password
            )
            if device.connect():
                logger.info(f"设备连接成功: {args.ip}")
                print(f"✓ 成功连接到设备 {args.ip}\n")
                device_connected = True
            else:
                logger.error(f"设备连接失败: {args.ip}")
                print(f"✗ 无法连接到设备 {args.ip}，将继续使用实际API模式但不执行设备操作\n")
                # 不回退到模拟模式，只禁用设备操作
        except Exception as e:
            logger.error(f"设备连接过程中出错: {str(e)}")
            print(f"✗ 设备连接出错: {str(e)}，将继续使用实际API模式但不执行设备操作\n")
            # 不回退到模拟模式，只禁用设备操作
    
    # process_config_command函数已移至模块级别
    
    def run_troubleshooting(natural_language: str, simulation_mode: bool, device_connected: bool, args=None):
        """运行故障排查的函数"""
        logger.info(f"处理故障排查需求: {natural_language}")
        print("正在生成故障排查命令...")
        
        try:
            # 初始化故障排查器
            troubleshooter = Troubleshooter(network_device=device, deepseek_api=deepseek_api)
            
            # 执行故障排查
            troubleshooting_result = troubleshooter.troubleshoot_device()
            
            # 生成故障排查报告
            report_text = troubleshooter.generate_troubleshooting_report(troubleshooting_result)
            
            # 显示报告
            print("\n故障排查报告:")
            print("=" * 80)
            print(report_text)
            print("=" * 80)
            
            # 保存报告到文件
            if hasattr(args, 'report_file') and args.report_file:
                # 使用命令行指定的报告文件路径
                try:
                    with open(args.report_file, 'w', encoding='utf-8') as f:
                        f.write(report_text)
                    print(f"✓ 报告已保存到: {args.report_file}")
                except Exception as e:
                    logger.error(f"保存报告到指定文件失败: {str(e)}")
                    print(f"✗ 保存报告到指定文件失败: {str(e)}")
            elif simulation_mode:
                print("\n[模拟模式] 报告不会自动保存")
            else:
                confirm = input("\n是否要将报告保存到文件？(y/n): ")
                if confirm.lower() == 'y':
                    try:
                        filename = troubleshooter.save_report_to_file(report_text)
                        if filename:
                            print(f"✓ 报告已保存到: {filename}")
                        else:
                            print("✗ 报告保存失败")
                    except Exception as e:
                        logger.error(f"保存报告时出错: {str(e)}")
                        print(f"✗ 保存报告时出错: {str(e)}")
        except Exception as e:
            logger.error(f"执行故障排查时出错: {str(e)}")
            print(f"❌ 执行故障排查时出错: {str(e)}")
            # 检查是否是API调用错误导致的
            if "402 Payment Required" in str(e):
                print("\n⚠️  API调用余额不足，请为您的API账户充值")
                print("系统将自动切换到模拟模式继续运行")
                deepseek_api.simulation_mode = True
                # 直接更新传入的参数值
                simulation_mode = True
                print("\n是否要使用模拟模式重试此故障排查需求？(y/n): ")
                retry_choice = input().lower()
                if retry_choice == 'y':
                    run_troubleshooting(natural_language, simulation_mode, device_connected, args)
            else:
                print("\n详细错误信息:")
                traceback.print_exc()
    
    # 根据mode参数决定执行配置还是故障排查
    if args.mode == "config" or args.mode == "both":
        # 使用命令行提供的自然语言需求或提示用户输入
        natural_language = args.natural_language or input("请输入配置需求: ")
        process_config_command(natural_language, simulation_mode, device_connected, args)
    
    if args.mode == "troubleshoot" or args.mode == "both":
        # 执行故障排查
        natural_language = args.natural_language or "执行网络设备故障排查"
        run_troubleshooting(natural_language, simulation_mode, device_connected, args)
    
    # 如果没有指定mode参数，进入交互模式
    elif not args.mode:
        print("\n=== DeepSeek网络配置自动化助手 ===")
        print("当前模式:", "模拟模式" if simulation_mode else "实际API调用模式")
        print("设备连接状态:", "已连接" if device_connected else "未连接")
        print("请选择以下操作之一：")
        print("1. 输入自然语言配置需求 - 通过自然语言描述生成网络设备配置命令")
        print("2. 执行设备故障排查 - 自动收集设备信息并分析可能的故障")
        print("3. 退出 - 关闭程序")
        
        while True:
            choice = input("\n请选择操作 (1/2/3): ")
            
            if choice == '1':
                # 自然语言配置
                natural_language = input("请输入配置需求: ")
                process_config_command(natural_language, simulation_mode, device_connected, args)
                # 配置流程完全结束后，提示用户按任意键返回主菜单
                input("\n配置流程已完成，按任意键返回主菜单...")
                
            elif choice == '2':
                # 故障排查
                natural_language = input("请输入故障排查需求 (默认为全面排查): ") or "执行网络设备故障排查"
                run_troubleshooting(natural_language, simulation_mode, device_connected, args)
                # 故障排查流程完全结束后，提示用户按任意键返回主菜单
                input("\n故障排查已完成，按任意键返回主菜单...")
                
            elif choice == '3':
                # 退出
                print("感谢使用DeepSeek网络配置自动化助手，再见！")
                break
            
            else:
                print("无效的选择，请重新输入。")
    
    # 断开设备连接
    if device and device_connected:
        try:
            device.disconnect()
            logger.info("设备连接已断开")
        except:
            pass

if __name__ == "__main__":
    try:
        # 先解析参数看是否需要启动GUI
        args = parse_args()
        
        # 如果指定了--gui参数，启动图形用户界面
        if args.gui:
            # 延迟导入gui模块，避免在不需要GUI时加载PyQt5
            from gui import start_gui
            print("启动图形用户界面...")
            start_gui()
        else:
            # 否则执行命令行模式
            main()
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
        print("\n程序已终止")
    except Exception as e:
        logger.error(f"程序运行出错: {str(e)}")
        print(f"\n错误: {str(e)}")
        # 显示错误详情
        logger.error(traceback.format_exc())
        print("\n详细错误信息:")
        traceback.print_exc()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AR2设备配置备份脚本
用于备份AR2路由器的当前配置到本地文件
"""

import os
import time
import logging
from datetime import datetime
from network_device import NetworkDevice
from config import DEFAULT_DEVICE_IP, DEFAULT_DEVICE_USERNAME, DEFAULT_DEVICE_PASSWORD

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("backup.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AR2_Backup")

def _backup_ar2_config_direct(output_dir="./backups"):
    """
    直接使用paramiko为AR2设备备份配置，使用专门优化的SSH连接参数
    
    Args:
        output_dir: 备份文件保存目录
        
    Returns:
        str: 备份文件路径，如果失败则返回None
    """
    import paramiko
    import time
    import re
    
    logger.info("使用直接SSH方式备份AR2设备配置...")
    
    # 创建备份目录
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logger.info(f"创建备份目录: {output_dir}")
        except Exception as e:
            logger.error(f"创建备份目录失败: {str(e)}")
            return None
    
    # 生成备份文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"ar2_config_{timestamp}.txt"
    backup_filepath = os.path.join(output_dir, backup_filename)
    
    # 创建SSH客户端
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # 配置SSH参数，针对AR2设备优化
        logger.info(f"连接到AR2设备: {DEFAULT_DEVICE_IP}")
        
        # 直接使用Transport对象获得更多控制权
        transport = paramiko.Transport((DEFAULT_DEVICE_IP, 22))
        transport.set_keepalive(15)
        transport.use_compression(False)
        
        # 增加超时设置
        transport.banner_timeout = 60
        transport.auth_timeout = 60
        
        # 连接认证
        transport.connect(username=DEFAULT_DEVICE_USERNAME, password=DEFAULT_DEVICE_PASSWORD)
        logger.info("成功连接到AR2设备")
        
        # 创建交互式shell
        channel = transport.open_session()
        channel.get_pty(width=1000, height=1000)
        channel.invoke_shell()
        
        # 等待提示符出现
        output = b''
        while True:
            if channel.recv_ready():
                output += channel.recv(4096)
                if b'>' in output or b']' in output:
                    break
            time.sleep(0.1)
        
        logger.info("成功获取设备提示符")
        
        # 发送配置备份命令
        channel.send("display current-configuration\n")
        
        # 收集输出，设置较长的超时
        output = b''
        end_time = time.time() + 120  # 120秒超时，增加超时时间
        more_occurrences = 0
        
        while time.time() < end_time:
            if channel.recv_ready():
                chunk = channel.recv(4096)
                output += chunk
                
                # 检测是否需要分页
                if b'---- More ----' in chunk:
                    logger.info(f"检测到分页提示，已出现 {more_occurrences+1} 次")
                    more_occurrences += 1
                    # 发送空格继续显示下一页
                    channel.send(" ")
                
                # 检查是否找到提示符（配置输出结束）
                if b'>' in chunk or b']' in chunk:
                    # 如果有分页提示，这可能不是真正的结束
                    if b'---- More ----' in output[-200:]:
                        continue
                    # 确保这是输出结束的提示符，而不是中间的
                    if len(chunk) > 10 and b'---- More ----' not in chunk:
                        continue
                    logger.info("检测到输出结束提示符")
                    break
            time.sleep(0.1)
        
        logger.info(f"配置收集完成，共处理 {more_occurrences} 次分页")
        
        # 解码输出
        config = output.decode('utf-8', errors='ignore')
        
        # 清理输出：移除命令本身、提示符和分页痕迹
        import re
        
        # 首先移除分页相关的痕迹和控制字符
        # 移除 ---- More ---- 和后面的控制字符
        config = re.sub(r'---- More ----.*?\n', '', config, flags=re.DOTALL)
        # 移除所有控制字符（除了换行符）
        config = re.sub(r'[\x00-\x09\x0b-\x1f\x7f]', '', config)
        # 移除剩余的分页标记
        config = re.sub(r'---- More ----', '', config)
        
        config_lines = config.split('\n')
        cleaned_config = []
        command_found = False
        
        for line in config_lines:
            # 跳过命令行本身
            if not command_found:
                if line.strip().lower().startswith('display current-configuration'):
                    command_found = True
                continue
            # 跳过最后的提示符
            if line.strip().startswith('<') and line.strip().endswith('>'):
                continue
            # 清理行内容，移除前后空白
            cleaned_line = line.strip()
            if cleaned_line:
                cleaned_config.append(cleaned_line)
        
        config_text = '\n'.join(cleaned_config)
        
        if len(config_text) < 100:
            logger.error(f"获取的配置过短，可能不完整: {len(config_text)} 字符")
            return None
        
        logger.info(f"成功获取配置，共 {len(config_text)} 字符")
        
        # 保存配置到文件
        try:
            with open(backup_filepath, 'w', encoding='utf-8') as f:
                f.write("#" * 80 + "\n")
                f.write(f"# AR2设备配置备份\n")
                f.write(f"# 备份时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 设备IP: {DEFAULT_DEVICE_IP}\n")
                f.write("#" * 80 + "\n\n")
                f.write(config_text)
                
            logger.info(f"配置已成功备份到: {backup_filepath}")
            return backup_filepath
            
        except Exception as e:
            logger.error(f"保存配置文件失败: {str(e)}")
            return None
            
    except paramiko.AuthenticationException:
        logger.error("认证失败: 用户名或密码错误")
        return None
    except Exception as e:
        logger.error(f"备份过程中发生异常: {str(e)}")
        return None
    finally:
        # 确保关闭连接
        try:
            if 'channel' in locals():
                channel.close()
            if 'transport' in locals():
                transport.close()
            ssh_client.close()
            logger.info("已断开与AR2设备的连接")
        except:
            pass

def backup_ar2_config(output_dir="./backups"):
    """
    备份AR2设备配置的主函数，尝试多种方法
    
    Args:
        output_dir: 备份文件保存目录
        
    Returns:
        str: 备份文件路径，如果失败则返回None
    """
    logger.info("开始备份AR2设备配置...")
    
    # 首先尝试使用专门为AR2优化的直接备份方法
    backup_file = _backup_ar2_config_direct(output_dir)
    if backup_file:
        return backup_file
    
    # 如果直接方法失败，尝试使用NetworkDevice类（备选方案）
    logger.info("尝试使用NetworkDevice类进行备份...")
    
    try:
        device = NetworkDevice(
            ip=DEFAULT_DEVICE_IP,
            username=DEFAULT_DEVICE_USERNAME,
            password=DEFAULT_DEVICE_PASSWORD,
            device_type='ar2'
        )
        
        if device.connect():
            config = device.execute_command("display current-configuration", timeout=60)
            if config and not config.startswith("错误"):
                # 生成备份文件名
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_filename = f"ar2_config_{timestamp}.txt"
                backup_filepath = os.path.join(output_dir, backup_filename)
                
                # 保存配置
                with open(backup_filepath, 'w', encoding='utf-8') as f:
                    f.write("#" * 80 + "\n")
                    f.write(f"# AR2设备配置备份\n")
                    f.write(f"# 备份时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# 设备IP: {DEFAULT_DEVICE_IP}\n")
                    f.write("#" * 80 + "\n\n")
                    f.write(config)
                
                logger.info(f"通过NetworkDevice成功备份配置到: {backup_filepath}")
                return backup_filepath
    except Exception as e:
        logger.error(f"使用NetworkDevice备份失败: {str(e)}")
    finally:
        if 'device' in locals():
            device.disconnect()
    
    logger.error("所有备份方法都失败了")
    return None

def verify_backup(backup_filepath):
    """
    验证备份文件的完整性
    
    Args:
        backup_filepath: 备份文件路径
        
    Returns:
        bool: 验证是否通过
    """
    if not os.path.exists(backup_filepath):
        logger.error("备份文件不存在")
        return False
    
    try:
        # 检查文件大小
        file_size = os.path.getsize(backup_filepath)
        logger.info(f"备份文件大小: {file_size} 字节")
        
        if file_size < 100:
            logger.warning("备份文件过小，可能不完整")
            return False
        
        # 检查文件内容
        with open(backup_filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 检查是否包含华为配置的特征
        if "sysname" not in content and "interface" not in content and "return" not in content:
            logger.warning("备份文件内容可能不完整")
            return False
        
        logger.info("备份文件验证通过")
        return True
        
    except Exception as e:
        logger.error(f"验证备份文件失败: {str(e)}")
        return False

if __name__ == "__main__":
    logger.info("AR2配置备份脚本启动")
    
    # 执行备份
    backup_file = backup_ar2_config()
    
    if backup_file:
        # 验证备份
        if verify_backup(backup_file):
            logger.info("AR2配置备份任务成功完成")
            print(f"✓ 配置备份成功")
            print(f"  备份文件: {backup_file}")
        else:
            logger.warning("AR2配置备份可能不完整")
            print(f"! 配置备份已完成，但验证未通过")
            print(f"  备份文件: {backup_file}")
    else:
        logger.error("AR2配置备份任务失败")
        print(f"✗ 配置备份失败，请查看日志了解详情")
    
    logger.info("AR2配置备份脚本结束")
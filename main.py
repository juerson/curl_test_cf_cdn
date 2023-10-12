import ipaddress
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging


def init_logger(name="root", level="INFO"):
    """
    初始化日志。

    Args:
        name: 日志名称。
        level: 日志级别。

    Returns:
        日志对象。
    """

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 创建一个 handler 对象，将日志记录到控制台。
    console_handler = logging.StreamHandler()

    # 设置日志格式。
    formatter = logging.Formatter(fmt="%(asctime)s %(levelname)-2s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    console_handler.setFormatter(formatter)

    # 将 handler 对象添加到 logger 对象。
    logger.addHandler(console_handler)

    return logger


# curl命令执行函数
def is_ip_reachable(ip):
    try:
        result = subprocess.run(["curl", "-o", "/dev/null", "-s", "-w", "%{http_code}", f"http://{ip}/cdn-cgi/trace"],stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        return ip, result.stdout.decode().strip() == "200"
    except subprocess.TimeoutExpired:
        return ip, False


def generate_ip_and_check_ip_type(ip_address):
    ips = set()

    try:
        ip_addr = ipaddress.ip_address(ip_address)
        ips.add(str(ip_addr))
    except Exception as e:
        if "does not appear to be an IPv4 or IPv6 address" in str(e):
            try:
                version = ipaddress.ip_network(ip_address).version
                if version == 4:
                    ip_network = ipaddress.ip_network(ip_address)
                    ips = ips.union({str(ip)
                                    for ip in ip_network.hosts()})  # 合并两个集合
            except Exception as e:
                pass

    return ips


def read_ips_file():
    with open("ips-v4.txt", mode='r', encoding='utf-8') as f:
        return [line.strip() for line in f if line != ""]


def write_to_file(data, file_name="output.txt"):
    with open(file_name, mode='w', encoding='utf-8') as wf:
        wf.writelines([f"{line}\n" for line in data])


if __name__ == '__main__':
    start_time = time.time()
    # 初始化日志
    logger = init_logger()
    # 读取文件中的内容
    ipadd = read_ips_file()
    """第一个线程池：多线程地生成cdir段中的所有ip，减少生成ip的时间"""
    # 创建第一个线程池
    pool_generate = ThreadPoolExecutor(20)
    # 提交连接任务
    ips_futures = []
    for item in ipadd:
        ips_futures.append(pool_generate.submit(
            generate_ip_and_check_ip_type, item))
    ips = set()
    for future in as_completed(ips_futures):
        ips = ips.union({item for item in future.result()})

    # 等待所有任务执行完毕，后面要使用到ips
    pool_generate.shutdown(wait=True)

    """第二个线程池：用于执行curl命令函数"""
    # 创建第二个线程池
    pool_method = ThreadPoolExecutor(100)
    # 提交连接任务
    futures = []
    for ip in ips:
        futures.append(pool_method.submit(is_ip_reachable, ip))

    results = []
    # 异步获取线程池中的任务结果。
    for future in as_completed(futures):
        ip, state = future.result()
        logger.info(f"scan {ip} --> {state}")
        if state:
            results.append(ip)
    # 等待所有的任务执行完毕
    pool_method.shutdown(wait=True)

    """将结果写入文本文件中"""
    output_file = "output.txt"
    write_to_file(data=results, file_name=output_file)
    elapsed_time = time.time() - start_time
    print(f'\n程序耗时：{elapsed_time:.2f}s')

import whois
import requests
import urllib3
import re
import tld
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
import argparse
from tqdm import tqdm
import json
urllib3.disable_warnings()

# 域名可以注册的结果
AllBrokenDomain = []
# 可以接管的存储桶
AllBrokenBucket = []


def menu():
    """
    帮助文档

    :return:
    """
    parser = argparse.ArgumentParser(
        description="输入URL列表，输出每个URL包含的链接中是否存在可以接管的Broken Link"
    )

    parser.add_argument(
        '-i', '--input',
        type=str,
        help='输入文件的路径',
        required=True
    )

    parser.add_argument(
        '-t', '--threads',
        type=int,
        help='并发线程数，默认5',
        required=False,
        default=5
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        help='输出文件的路径',
        required=False
    )

    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='保存JSON格式的结果'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='启用详细模式'
    )

    args = parser.parse_args()
    return args


def getHtmlSourceAndParseUrl(url) -> list:
    """
    输入URL，自动访问并返回网页中包含的其他url链接，将结果保存到全局变量 AllExtractUrls 中

    :param url: 需要请求的链接
    :return:
    """
    result = []
    urlRegex = re.compile(r'https?:\/\/[0-9a-zA-Z\-\.]+')
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100"
    }
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=3)
        result = urlRegex.findall(resp.text)

    except Exception as ex:
        if args.verbose:
            logger.debug(f"Error in getHtmlSourceAndParseUrl: {ex}")

    return result


def checkDomainRegistration(domain):
    """
    通过 whois 检查域名是否被注册，是否可以被接管

    :param domain: 域名
    :return:
    """
    global AllBrokenDomain
    try:
        w = whois.whois(domain)
        if w.domain_name:
            return False
        elif w.text == "Socket not responding: timed out" or w.text == 'Socket not responding: [Errno 54] Connection reset by peer':
            return False
        else:
            AllBrokenDomain.append(domain)
    except Exception as e:
        if args.verbose:
            logger.debug(f"Error: {e}")
        # 找不到记录
        if "No match for" in str(e) or "Domain not found." in str(e):
            AllBrokenDomain.append(domain)
        return True


def batchCheckDomainRegistration(domains):
    """
    checkDomainRegistration的多线程运行

    :param domains: 一个域名列表
    :return: None
    """
    # 初始化
    global AllBrokenDomain
    AllBrokenDomain = []
    # 并发数
    pool = ThreadPoolExecutor(max_workers=args.threads)
    # 下发任务
    allTask = [pool.submit(checkDomainRegistration, domain) for domain in domains]
    # 等待全部执行完成
    wait(allTask, return_when=ALL_COMPLETED)


def checkBucketNotFound(url):
    """
    输入URL，检查是否可以进行存储桶接管

    :param url: 完整的URL链接
    :return: True 可以接管，False 不可以接管
    """
    global AllBrokenBucket
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100"
    }
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=3)
        if "The specified bucket does not exist" in resp.text:
            AllBrokenBucket.append(url)
        else:
            return False
    except Exception as ex:
        return False


def batchCheckBucketNotFound(urls):
    """
    checkBucketNotFound的多线程运行

    :param urls: 一个url列表
    :return: None
    """
    # 初始化
    global AllBrokenBucket
    AllBrokenBucket = []
    # 并发数
    pool = ThreadPoolExecutor(max_workers=args.threads)
    # 下发任务
    allTask = [pool.submit(checkBucketNotFound, url) for url in urls]
    # 等待全部执行完成
    wait(allTask, return_when=ALL_COMPLETED)


def genVulnJson(vulnUrl, detail):
    template = {
        "漏洞名": "Broken Link Found",
        "漏洞等级": "高危",
        "漏洞URL": vulnUrl,
        "问题说明": f"发现在URL {vulnUrl} 中存在未注册的域名/存储桶 {detail}； Broken Link（失效链接）是指在网页或应用中点击后无法正常访问的链接，通常返回404错误页面或其他类似提示。这种问题可能由于链接目标被移除、网址更改、拼写错误或服务器不可用等原因导致。",
        "漏洞危害": "未注册的域名、存储桶意味着任何人都可以注册它，并在其上托管任意内容。如果该域名被恶意方注册并放置恶意代码，任何加载该脚本的用户都会受到攻击。",
        "安全建议": "最好移除或禁止加载来自该域名的脚本，同时通过 CSP 限制允许加载的脚本来源，防止潜在的恶意加载。",
        "请求数据包": "",
        "响应数据包": "",
        "扫描类型": "漏洞扫描",
        "目标域名": "",
        "资产名": ""
    }
    return template


if __name__ == '__main__':
    # 初始化帮助参数
    args = menu()

    # 读取URL列表
    with open(args.input, "r") as f:
        urls = f.read().splitlines()

    for url in tqdm(urls, ncols=30):
        # 从URL中提取链接
        parseUrls = list(set(getHtmlSourceAndParseUrl(url)))

        # 检查域名是否可以注册接管
        checkDomains = list(set([tld.get_fld(url, fix_protocol=True, fail_silently=True) for url in parseUrls]))
        checkDomains = [domain for domain in checkDomains if domain is not None and "gov.cn" not in domain]
        if args.verbose:
            logger.debug(f"提取域名列表：{checkDomains}")
        batchCheckDomainRegistration(checkDomains)
        if AllBrokenDomain:
            logger.info(f"Broken Domain: {url} -> {AllBrokenDomain}\n")
            # 写入结果
            if args.output:
                with open(args.output, "a+") as f:
                    if args.json:
                        f.write(json.dumps(genVulnJson(url, AllBrokenDomain)) + "\n")
                    else:
                        f.write(f"Broken Domain: {url} -> {AllBrokenDomain}\n")

        # 检查是否存在存储桶接管
        if args.verbose:
            logger.debug(f"解析URL列表：{parseUrls}")
        batchCheckBucketNotFound(parseUrls)
        if AllBrokenBucket:
            logger.info(f"Broken Bucket: {url} -> {AllBrokenBucket}\n")
            # 写入结果
            if args.output:
                with open(args.output, "a+") as f:
                    if args.json:
                        f.write(json.dumps(genVulnJson(url, AllBrokenBucket)) + "\n")
                    else:
                        f.write(f"Broken Bucket: {url} -> {AllBrokenBucket}\n")












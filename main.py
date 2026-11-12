import argparse
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import requests
import tld
import urllib3
import whois
from loguru import logger
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry


URL_RE = re.compile(r"https?://[0-9a-zA-Z\-.]+", re.IGNORECASE)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100"
)
DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024

STATUS_REGISTERED = "registered"
STATUS_UNREGISTERED = "unregistered"
STATUS_UNKNOWN = "unknown"
STATUS_ERROR = "error"

REGISTERED_FIELDS = (
    "domain_name",
    "registrar",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "status",
)

UNREGISTERED_PATTERNS = (
    "no match for",
    "domain not found",
    "no entries found",
    "no data found",
    "no matching record",
    "no object found",
    "domain is available",
    "available for registration",
    "not registered",
    "no information available",
    "no whois data",
)

UNKNOWN_WHOIS_PATTERNS = (
    "timed out",
    "timeout",
    "socket not responding",
    "connection reset",
    "connection refused",
    "connection error",
    "network is unreachable",
    "too many requests",
    "rate limit",
    "quota exceeded",
    "temporarily unavailable",
    "server busy",
    "service unavailable",
    "try again later",
)

BUCKET_MISSING_MARKERS = (
    "The specified bucket does not exist",
    "<Code>NoSuchBucket</Code>",
    "NoSuchBucket",
)


@dataclass(frozen=True)
class ScanConfig:
    threads: int = 5
    timeout: float = 3.0
    retries: int = 2
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    verify_tls: bool = False
    verbose: bool = False

    def __post_init__(self) -> None:
        if self.threads < 1:
            raise ValueError("threads must be greater than 0")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")
        if self.max_response_bytes < 1:
            raise ValueError("max_response_bytes must be greater than 0")


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status_code: Optional[int]
    text: str = ""
    truncated: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class DomainCheckResult:
    domain: str
    status: str
    detail: str = ""


@dataclass(frozen=True)
class BucketCheckResult:
    url: str
    broken: bool
    detail: str = ""


@dataclass(frozen=True)
class Finding:
    kind: str
    source_url: str
    target: str
    detail: str = ""


@dataclass
class PageScanResult:
    source_url: str
    extracted_urls: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _contains_any(text: str, patterns: Sequence[str]) -> bool:
    lowered = (text or "").lower()
    return any(pattern.lower() in lowered for pattern in patterns)


def _get_record_value(record, name: str):
    if isinstance(record, dict):
        return record.get(name)
    return getattr(record, name, None)


def _has_registration_data(record) -> bool:
    for name in REGISTERED_FIELDS:
        value = _get_record_value(record, name)
        if isinstance(value, (list, tuple, set)):
            if any(value):
                return True
        elif value:
            return True
    return False


def _classify_whois_text(text: str) -> Optional[str]:
    if _contains_any(text, UNKNOWN_WHOIS_PATTERNS):
        return STATUS_UNKNOWN
    if _contains_any(text, UNREGISTERED_PATTERNS):
        return STATUS_UNREGISTERED
    return None


def read_response_text(response, max_bytes: int) -> Tuple[str, bool]:
    """Read a streamed response without allowing it to grow without bound."""
    chunks = []
    total = 0
    truncated = False

    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            truncated = int(content_length) > max_bytes
        except ValueError:
            pass

    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue

        remaining = max_bytes - total
        if remaining <= 0:
            truncated = True
            break

        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break

        chunks.append(chunk)
        total += len(chunk)

    encoding = response.encoding or "utf-8"
    text = b"".join(chunks).decode(encoding, errors="replace")
    return text, truncated


class HttpClient:
    """Thread-local requests sessions with retries and bounded response reads."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._local = threading.local()

    def _get_session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        retry = Retry(
            total=self.config.retries,
            connect=self.config.retries,
            read=self.config.retries,
            status=self.config.retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=self.config.threads,
            pool_maxsize=self.config.threads,
        )
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": USER_AGENT})
        self._local.session = session
        return session

    def fetch_text(self, url: str) -> FetchResult:
        if not url or not url.strip():
            return FetchResult(url, url, None, error="empty URL")

        try:
            response = self._get_session().get(
                url,
                timeout=(self.config.timeout, self.config.timeout),
                verify=self.config.verify_tls,
                allow_redirects=True,
                stream=True,
            )
            with response:
                text, truncated = read_response_text(
                    response,
                    self.config.max_response_bytes,
                )
                return FetchResult(
                    requested_url=url,
                    final_url=response.url or url,
                    status_code=response.status_code,
                    text=text,
                    truncated=truncated,
                )
        except requests.RequestException as exc:
            if self.config.verbose:
                logger.debug(f"Request failed for {url}: {exc}")
            return FetchResult(url, url, None, error=str(exc))


def getHtmlSourceAndParseUrl(url: str, http_client: HttpClient) -> FetchResult:
    """Fetch a page and return its response plus the URLs found in its body."""
    return http_client.fetch_text(url)


def extract_urls(text: str) -> List[str]:
    return sorted(set(URL_RE.findall(text or "")))


def get_registrable_domain(url: str) -> Optional[str]:
    try:
        hostname = urlsplit(url).hostname
        if not hostname:
            return None
        domain = tld.get_fld(
            hostname.rstrip(".").lower(),
            fix_protocol=True,
            fail_silently=True,
        )
        return domain.lower() if domain else None
    except Exception:
        return None


def is_gov_cn_domain(domain: str) -> bool:
    return domain == "gov.cn" or domain.endswith(".gov.cn")


def extract_domains(urls: Sequence[str]) -> List[str]:
    domains = {
        domain
        for domain in (get_registrable_domain(url) for url in urls)
        if domain and not is_gov_cn_domain(domain)
    }
    return sorted(domains)


def checkDomainRegistration(domain: str) -> DomainCheckResult:
    """Classify a domain without treating transient WHOIS failures as broken."""
    try:
        record = whois.whois(domain)
    except Exception as exc:
        message = str(exc)
        status = _classify_whois_text(message) or STATUS_ERROR
        return DomainCheckResult(domain, status, message)

    if _has_registration_data(record):
        return DomainCheckResult(domain, STATUS_REGISTERED)

    text = str(_get_record_value(record, "text") or "")
    status = _classify_whois_text(text)
    if status:
        return DomainCheckResult(domain, status, text[:500])

    detail = text[:500] if text else "WHOIS response did not contain a definitive registration state"
    return DomainCheckResult(domain, STATUS_UNKNOWN, detail)


def checkBucketNotFound(url: str, http_client: HttpClient) -> BucketCheckResult:
    response = http_client.fetch_text(url)
    if response.error:
        return BucketCheckResult(url, False, response.error)

    if any(marker in response.text for marker in BUCKET_MISSING_MARKERS):
        return BucketCheckResult(url, True, f"HTTP {response.status_code}")

    detail = f"HTTP {response.status_code}"
    if response.truncated:
        detail += "; response body was truncated"
    return BucketCheckResult(url, False, detail)


def _run_page_checks(
    result: PageScanResult,
    config: ScanConfig,
    http_client: HttpClient,
    executor: ThreadPoolExecutor,
) -> PageScanResult:
    domains = extract_domains(result.extracted_urls)
    if config.verbose:
        logger.debug(f"提取域名列表：{domains}")
        logger.debug(f"解析URL列表：{result.extracted_urls}")

    if not domains and not result.extracted_urls:
        return result

    futures = {}
    for domain in domains:
        future = executor.submit(checkDomainRegistration, domain)
        futures[future] = ("domain", domain)
    for url in result.extracted_urls:
        future = executor.submit(checkBucketNotFound, url, http_client)
        futures[future] = ("bucket", url)

    for future in as_completed(futures):
        kind, target = futures[future]
        try:
            check_result = future.result()
        except Exception as exc:
            result.errors.append(f"{kind} check failed for {target}: {exc}")
            continue

        if kind == "domain":
            if check_result.status == STATUS_UNREGISTERED:
                result.findings.append(
                    Finding(
                        kind="domain",
                        source_url=result.source_url,
                        target=check_result.domain,
                        detail=check_result.detail,
                    )
                )
            elif config.verbose and check_result.status in (
                STATUS_UNKNOWN,
                STATUS_ERROR,
            ):
                logger.debug(
                    f"WHOIS {check_result.status}: "
                    f"{check_result.domain} -> {check_result.detail}"
                )
        elif check_result.broken:
            result.findings.append(
                Finding(
                    kind="bucket",
                    source_url=result.source_url,
                    target=check_result.url,
                    detail=check_result.detail,
                )
            )

    result.findings.sort(key=lambda finding: (finding.kind, finding.target))
    return result


def scan_page(
    page_url: str,
    config: ScanConfig,
    http_client: HttpClient,
    executor: Optional[ThreadPoolExecutor] = None,
) -> PageScanResult:
    """Scan one input page. Extracted URLs are checked, not crawled recursively."""
    result = PageScanResult(source_url=page_url)
    page = getHtmlSourceAndParseUrl(page_url, http_client)
    if page.error:
        result.errors.append(f"page request failed: {page.error}")
        return result

    if page.truncated:
        result.errors.append(
            f"page response exceeded {config.max_response_bytes} bytes and was truncated"
        )

    result.extracted_urls = extract_urls(page.text)
    if executor is not None:
        return _run_page_checks(result, config, http_client, executor)

    max_workers = max(
        1,
        min(config.threads, len(result.extracted_urls) + 1),
    )
    with ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="broken-link-checker",
    ) as owned_executor:
        return _run_page_checks(result, config, http_client, owned_executor)


def genVulnJson(source_url: str, findings: Sequence[Finding]) -> dict:
    targets = [finding.target for finding in findings]
    detail_text = "、".join(targets)
    return {
        "name": "Broken Link Found",
        "severity": "高危",
        "url": source_url,
        "description": (
            f"发现在URL {source_url} 中存在未注册的域名/存储桶 "
            f"{detail_text}； Broken Link（失效链接）是指在网页或应用中点击后无法正常访问的链接，"
            "通常返回404错误页面或其他类似提示。这种问题可能由于链接目标被移除、网址更改、"
            "拼写错误或服务器不可用等原因导致。"
        ),
        "impact": (
            "未注册的域名、存储桶意味着任何人都可以注册它，并在其上托管任意内容。"
            "如果该域名被恶意方注册并放置恶意代码，任何加载该脚本的用户都会受到攻击。"
        ),
        "recommendation": (
            "最好移除或禁止加载来自该域名的脚本，同时通过 CSP 限制允许加载的脚本来源，"
            "防止潜在的恶意加载。"
        ),
    }


def write_scan_result(
    result: PageScanResult,
    output_file=None,
    json_output: bool = False,
) -> None:
    groups = {
        "domain": [finding for finding in result.findings if finding.kind == "domain"],
        "bucket": [finding for finding in result.findings if finding.kind == "bucket"],
    }
    labels = {
        "domain": "Broken Domain",
        "bucket": "Broken Bucket",
    }

    for kind in ("domain", "bucket"):
        findings = groups[kind]
        if not findings:
            continue

        targets = [finding.target for finding in findings]
        message = f"{labels[kind]}: {result.source_url} -> {targets}"
        logger.info(message)

        if output_file is None:
            continue
        if json_output:
            output_file.write(
                json.dumps(
                    genVulnJson(result.source_url, findings),
                    ensure_ascii=False,
                )
                + "\n"
            )
        else:
            output_file.write(message + "\n")


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("cannot be negative")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def menu(argv=None):
    parser = argparse.ArgumentParser(
        description="输入URL列表，输出每个URL包含的链接中是否存在可以接管的Broken Link"
    )
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        help="输入文件的路径",
        required=True,
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=positive_int,
        help="并发线程数，默认5",
        default=5,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="输出文件的路径",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="保存JSON格式的结果",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="启用详细模式",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=3.0,
        help="连接和读取超时时间，默认3秒",
    )
    parser.add_argument(
        "--retries",
        type=non_negative_int,
        default=2,
        help="HTTP请求重试次数，默认2",
    )
    parser.add_argument(
        "--max-response-mb",
        type=positive_float,
        default=5.0,
        help="单个响应最多读取的MB数，默认5",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="启用TLS证书校验，默认关闭以兼容原有行为",
    )
    return parser.parse_args(argv)


def config_from_args(args) -> ScanConfig:
    return ScanConfig(
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        max_response_bytes=int(args.max_response_mb * 1024 * 1024),
        verify_tls=args.verify_tls,
        verbose=args.verbose,
    )


def main(argv=None) -> int:
    args = menu(argv)
    if not args.verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = config_from_args(args)
    http_client = HttpClient(config)

    with open(args.input, "r", encoding="utf-8") as input_file:
        urls = input_file.read().splitlines()

    output_file = None
    try:
        if args.output:
            output_file = open(args.output, "a", encoding="utf-8")

        with ThreadPoolExecutor(
            max_workers=config.threads,
            thread_name_prefix="broken-link-checker",
        ) as executor:
            for page_url in tqdm(urls, ncols=30):
                page_url = page_url.strip()
                if not page_url:
                    continue

                result = scan_page(page_url, config, http_client, executor)
                if config.verbose:
                    for error in result.errors:
                        logger.debug(error)
                write_scan_result(result, output_file, args.json)
    finally:
        if output_file is not None:
            output_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

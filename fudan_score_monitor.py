#!/usr/bin/env python3
"""
复旦研究生院盲审评阅结果监控脚本
- 自动登录复旦统一身份认证 (UIS)
- 定期调用研究生院后端 API 查询评阅信息
- 检测到新评阅结果时通过 Server酱 推送微信通知

配置方式：复制 .env.example -> .env，填写真实信息
"""

import os
import re
import time
import json
import base64
import html
import logging
import ssl
from datetime import datetime
from pathlib import Path
from typing import List, Dict

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# ── .env 文件加载 ─────────────────────────────────────────────
def load_dotenv(path: str = None):
    """简易 .env 加载器，不依赖 python-dotenv"""
    if path is None:
        path = Path(__file__).parent / ".env"
    else:
        path = Path(path)
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = val

load_dotenv()

# ── 日志配置 ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── 配置 ─────────────────────────────────────────────────────
FUDAN_USERNAME  = os.getenv("FUDAN_USERNAME", "")
FUDAN_PASSWORD  = os.getenv("FUDAN_PASSWORD", "")

SENDKEY = os.getenv("SENDKEY", "")
SERVERCHAN_API = f"https://sctapi.ftqq.com/{SENDKEY}.send" if SENDKEY else ""

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "1800"))  # 默认 30 分钟
MAX_RETRY      = int(os.getenv("MAX_RETRY", "3"))

# ── 复旦研究生院系统常量 ──────────────────────────────────────
# CAS service 参数：指向研究生院系统
GSAPP_CAS_SERVICE = "https://yzsfwapp.fudan.edu.cn/gsapp/sys/wdxwxxfudan/*default/index.do"
# 研究生院后端 API 基地址
GSAPP_BASE = "https://yzsfwapp.fudan.edu.cn/gsapp"

# ── UIS 认证常量 ─────────────────────────────────────────────
BASE = "https://id.fudan.edu.cn"
IDP  = f"{BASE}/idp"
UA   = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


# ═══════════════════════════════════════════════════════════════
#  UIS 统一身份认证登录
# ═══════════════════════════════════════════════════════════════

def build_session() -> Session:
    se = Session()
    se.headers.update({"User-Agent": UA})

    # ── SSL 适配：复旦 IDP 服务器 TLS 配置特殊 ──
    # 创建兼容性 SSL context，放宽证书验证 + 兼容旧版 TLS
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 跳过证书验证（教育网常见）
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")  # 降低安全级别以兼容旧 cipher

    # 将自定义 SSL context 绑定到 session 的所有 HTTPS 请求
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── 自动重试适配器 ──
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    se.mount("https://", adapter)
    se.mount("http://", adapter)

    # 全局默认：禁用 SSL 验证
    se.verify = False

    return se


def _rsa_encrypt(plaintext: str, public_key_b64: str) -> str:
    der = base64.b64decode(public_key_b64)
    key = RSA.import_key(der)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def uis_login(
    username: str,
    password: str,
    service: str = GSAPP_CAS_SERVICE,
) -> Session:
    """
    复旦 UIS 统一身份认证登录 → 返回已认证的 Session
    service 参数决定 CAS ticket 兑换到哪个子系统
    """
    se = build_session()
    referer = f"{BASE}/ac/"

    # Step 1: 获取 lck token
    log.info("Step 1/6: 获取 lck token ...")
    r = se.get(
        f"{BASE}/authserver/login",
        params={"service": service},
        allow_redirects=True,
    )
    match = re.search(r"lck=([\w_-]+)", r.url)
    if not match:
        raise RuntimeError(f"无法提取 lck token，URL: {r.url}")
    lck = match.group(1)
    referer = r.url

    # Step 2: queryAuthMethods
    log.info("Step 2/6: 查询认证方式 ...")
    r2 = se.post(
        f"{IDP}/authn/queryAuthMethods",
        json={"lck": lck},
        headers={"Referer": referer},
    )
    r2.raise_for_status()
    body2 = r2.json()
    if str(body2.get("code")) not in ("200", "4339"):
        raise RuntimeError(f"queryAuthMethods 失败: {body2.get('message')}")

    entity_id    = body2.get("entityId") or service.rstrip("/")
    request_type = body2.get("requestType", "chain_type")
    modules = body2.get("data") or []
    chain = next(
        (m for m in modules if "userAndPwd" in (m.get("moduleCodes") or [])),
        modules[0] if modules else {},
    )
    auth_chain_code = chain.get("authChainCode", "")

    # Step 3: 获取 RSA 公钥
    log.info("Step 3/6: 获取 RSA 公钥 ...")
    r3 = se.post(f"{IDP}/authn/getJsPublicKey", headers={"Referer": referer})
    r3.raise_for_status()
    body3 = r3.json()
    if str(body3.get("code")) != "200":
        raise RuntimeError(f"获取公钥失败: {body3.get('message')}")
    pub_b64 = (
        body3["data"]["data"] if isinstance(body3.get("data"), dict)
        else body3["data"]
    )

    # Step 4: 提交密码
    log.info("Step 4/6: 提交账号密码 ...")
    encrypted_pwd = _rsa_encrypt(password, pub_b64)
    r4 = se.post(
        f"{IDP}/authn/authExecute",
        json={
            "authModuleCode": "userAndPwd",
            "authChainCode":  auth_chain_code,
            "entityId":       entity_id,
            "requestType":    request_type,
            "lck":            lck,
            "authPara": {
                "loginName":  username,
                "password":   encrypted_pwd,
                "verifyCode": "",
            },
        },
        headers={"Referer": referer},
    )
    r4.raise_for_status()
    body4 = r4.json()

    if str(body4.get("code")) != "200":
        raise RuntimeError(f"密码认证失败 (code={body4.get('code')}): {body4.get('message')}")

    login_token = body4.get("loginToken")
    page_level  = body4.get("pageLevelNo", 0)

    if not login_token:
        raise RuntimeError("登录失败：未获取到 loginToken")

    # Step 6: CAS ticket 兑换
    log.info("Step 6/6: CAS ticket 兑换 ...")
    r6 = se.post(
        f"{IDP}/authCenter/authnEngine",
        data={"loginToken": login_token},
        headers={"Referer": referer},
        allow_redirects=False,
    )
    r6.raise_for_status()
    ticket_match = re.search(r'var\s+locationValue\s*=\s*"([^"]+)"', r6.text)
    if not ticket_match:
        raise RuntimeError("authnEngine 响应中未找到 ticket URL")
    ticket_url = html.unescape(ticket_match.group(1))

    # 跟随重定向，获取最终 session cookie
    r7 = se.get(ticket_url, allow_redirects=True)
    r7.raise_for_status()

    log.info("✅ UIS 登录成功！")
    return se


# ═══════════════════════════════════════════════════════════════
#  研究生院系统 API 调用
# ═══════════════════════════════════════════════════════════════

def gsapp_init(se: Session) -> bool:
    """
    初始化研究生院系统会话（访问首页，获取必要 cookie/token）
    研究生院前端是 Vue SPA，需要先访问入口页建立 session
    """
    try:
        r = se.get(GSAPP_CAS_SERVICE, timeout=15, allow_redirects=True)
        r.raise_for_status()
        # 确认 session cookie 存在（金智新版用 GS_SESSIONID 替代 JSESSIONID）
        has_session = any(k.upper() in ("JSESSIONID", "GS_SESSIONID")
                         for k in se.cookies.keys())
        if has_session:
            log.info(f"研究生院系统初始化完成，session cookie 已获取")
        else:
            log.warning(f"研究生院系统初始化完成，但未检测到 session cookie！")
            log.warning(f"  Cookies: {list(se.cookies.keys())}")
        return True
    except Exception as e:
        log.error(f"研究生院系统初始化失败: {e}")
        return False


def query_review_info(se: Session, username: str = "") -> List[Dict]:
    """
    查询盲审评阅信息

    API 调用链路（从金智 emap 前端 JS 逆向获取）：
      1. GET xwgg_xwsqzbcx.do  → 查询学位申请主表，获取 LWCJPCWID（论文成绩批次WID）
      2. GET queryPyjg.do       → 用 LWCJPCWID 查询评阅结果

    注意：金智 emap 后端要求 GET 请求（POST 返回 code=404）
    """
    MODULE_BASE = f"{GSAPP_BASE}/sys/wdxwxxfudan/modules/xsbdjcsq"

    # ── 金智 emap 前端必需请求头 ──
    ajax_headers = {
        "Referer": GSAPP_CAS_SERVICE,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
    }

    # ─── Step 1: 查询学位申请主表 ─────────────────────────────
    xh = username or se.headers.get("XH", "")
    # 从首页 HTML 的 pageMeta 中提取 USERID
    if not xh:
        try:
            r = se.get(GSAPP_CAS_SERVICE, timeout=15, allow_redirects=False)
            m = re.search(r'"USERID"\s*:\s*"(\d+)"', r.text)
            if m:
                xh = m.group(1)
        except Exception:
            pass

    log.info(f"查询学位申请主表 (XH={xh}) ...")
    try:
        r1 = se.get(
            f"{MODULE_BASE}/xwgg_xwsqzbcx.do",
            params={
                "pageSize": "100",
                "pageNumber": "1",
                "XH": xh,
                "SFYX": "1",
            },
            headers=ajax_headers,
            timeout=15,
        )
        r1.raise_for_status()
        body1 = r1.json()
    except Exception as e:
        log.error(f"查询学位申请主表失败: {e}")
        return []

    # 解析金智 emap 标准返回格式
    sq_data = None
    if isinstance(body1, dict):
        # 格式: { code: "0", datas: { xwgg_xwsqzbcx: { totalSize, pageSize, rows: [...] } } }
        code = str(body1.get("code", ""))
        if code == "404":
            log.error("主表 API 返回 404，可能请求方式错误或 session 过期")
            return []
        datas = body1.get("datas", body1)
        if isinstance(datas, dict):
            rows_container = datas.get("xwgg_xwsqzbcx", datas)
            if isinstance(rows_container, dict):
                rows = rows_container.get("rows", [])
                if rows:
                    sq_data = rows[0] if isinstance(rows, list) else rows
            elif isinstance(rows_container, list):
                sq_data = rows_container[0] if rows_container else None
        elif isinstance(datas, list) and datas:
            sq_data = datas[0]

    if not sq_data:
        log.warning("学位申请主表无数据，可能尚未提交学位申请")
        log.debug(f"主表原始响应: {json.dumps(body1, ensure_ascii=False)[:500]}")
        return []

    lwcjpcwid = sq_data.get("LWCJPCWID", "")
    xwpcdm = sq_data.get("XWPCDM", "")
    lwcjsftg = sq_data.get("LWCJSFTG", "")
    log.info(f"学位申请主表: LWCJPCWID={lwcjpcwid}, XWPCDM={xwpcdm}, LWCJSFTG={lwcjsftg}")

    # ─── Step 2: 查询评阅结果 ─────────────────────────────────
    log.info("查询评阅结果 ...")
    try:
        r2 = se.get(
            f"{MODULE_BASE}/queryPyjg.do",
            params={"lwcjpcwid": lwcjpcwid or "-999"},
            headers=ajax_headers,
            timeout=15,
        )
        r2.raise_for_status()
        body2 = r2.json()
    except Exception as e:
        log.error(f"查询评阅结果失败: {e}")
        return [sq_data]  # 至少返回主表数据

    # 解析评阅结果
    pyjg_list = []
    xspylx_map = {}
    if isinstance(body2, dict):
        # queryPyjg.do 返回格式: { pyjgList: [...], xspylxMap: {...}, success: true }
        pyjg_list = body2.get("pyjgList", [])
        xspylx_map = body2.get("xspylxMap", {})

    if pyjg_list:
        log.info(f"✅ 评阅结果查询成功，共 {len(pyjg_list)} 位评阅人")
        # 合并主表 + 评阅数据
        result = dict(sq_data)
        result["pyjg_list"] = pyjg_list
        result["xspylx_map"] = xspylx_map
        return [result]

    # 如果 pyjgList 为空，检查是否有其他格式
    if body2.get("success"):
        log.info("评阅结果已返回但 pyjgList 为空（可能评阅尚未开始）")
        result = dict(sq_data)
        result["pyjg_list"] = []
        result["xspylx_map"] = xspylx_map
        return [result]

    log.warning(f"评阅结果格式未知: {str(body2)[:200]}")
    return [sq_data]


# ═══════════════════════════════════════════════════════════════
#  变化检测
# ═══════════════════════════════════════════════════════════════

def compute_fingerprint(data: List[Dict]) -> str:
    """计算评阅数据的指纹（用于检测变化）"""
    import hashlib
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return hashlib.md5(raw.encode()).hexdigest()


def format_review_summary(data: List[Dict]) -> str:
    """格式化评阅信息，用于推送通知和日志展示"""
    if not data:
        return "暂无评阅数据"

    lines = []
    for i, item in enumerate(data, 1):
        if not isinstance(item, dict):
            lines.append(f"{i}. {item}")
            continue

        # ── 评阅结果详情 ──
        pyjg_list = item.get("pyjg_list", [])
        xspylx_map = item.get("xspylx_map", {})

        if pyjg_list:
            # 汇总结论（从 xspylxMap 获取）
            hb_pyjg = xspylx_map.get("HBPYJG", "")
            hb_pyjg_display = xspylx_map.get("HBPYJG_DISPLAY", "")
            pyjg_summary = xspylx_map.get("PYJG", "")

            if hb_pyjg_display:
                lines.append(f"**汇总评阅结论: {hb_pyjg_display}**")
            elif pyjg_summary:
                verdict_map = {"1": "优秀 ✅", "2": "良好 ✅", "3": "修改后通过 ⚠️", "4": "未通过 ❌"}
                lines.append(f"**评阅结论: {verdict_map.get(str(pyjg_summary), str(pyjg_summary))}**")
            else:
                lines.append(f"**评阅结论: 尚未出汇总结论**")

            lines.append(f"")

            # 每位评阅人的详细评分
            for j, py in enumerate(pyjg_list, 1):
                ztpj = str(py.get("ZTPJ", ""))
                ztpj_display = py.get("ZTPJ_DISPLAY", "")
                verdict_map = {"1": "优秀 ✅", "2": "良好 ✅", "3": "修改后通过 ⚠️", "4": "未通过 ❌"}
                verdict = verdict_map.get(ztpj, ztpj_display or ztpj)

                sjly = py.get("SJLY", "")
                sjly_text = "国评" if sjly == "2" else "校评" if sjly == "1" else ""
                pyrlx_display = py.get("PYRLX_DISPLAY", "")

                lines.append(f"**评阅人 {j}: {verdict}** ({sjly_text}/{pyrlx_display})")
                sfdb = py.get("SFDB_DISPLAY", "")
                if sfdb:
                    lines.append(f"  是否同意答辩: {sfdb}")

                # 分项评分
                scores = []
                for k in range(1, 9):
                    val = py.get(f"FXPJ{k}")
                    if val:
                        scores.append(str(val))
                if scores:
                    avg = sum(int(s) for s in scores) / len(scores)
                    lines.append(f"  分项分: {' / '.join(scores)}  (均分 {avg:.1f})")

                sfyy = py.get("SFYY_DISPLAY", "")
                if sfyy:
                    lines.append(f"  是否异议: {sfyy}")

        # ── 主表状态 ──
        main_fields = {}
        field_labels = {
            "XH": "学号", "XWPCDM_DISPLAY": "学位批次", "LWCJSFTG": "论文成绩是否通过",
            "LWCJZT": "论文成绩状态", "PYJG": "评阅结论代码", "PYJGSFTG": "评阅是否通过",
            "SQLX": "申请类型", "LWLX_DISPLAY": "论文类型", "LWKSSJ": "论文开始时间",
            "LWJSSJ": "论文结束时间",
        }
        for key, label in field_labels.items():
            if key in item and item[key] is not None and str(item[key]).strip():
                main_fields[label] = item[key]

        if main_fields:
            lines.append(f"")
            lines.append(f"**学位申请信息:**")
            for label, val in main_fields.items():
                lines.append(f"  - {label}: {val}")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
#  微信推送（Server酱）
# ═══════════════════════════════════════════════════════════════

def push_wechat(title: str, content: str = "") -> bool:
    if not SERVERCHAN_API or "YOUR_SENDKEY" in SERVERCHAN_API:
        log.error("未配置 SENDKEY，无法推送！")
        return False
    try:
        resp = requests.post(SERVERCHAN_API, data={"title": title, "desp": content}, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") == 0:
            log.info("✅ 微信推送成功")
            return True
        else:
            log.error(f"推送失败: {result}")
            return False
    except Exception as e:
        log.error(f"推送异常: {e}")
        return False


# ═══════════════════════════════════════════════════════════════
#  调试工具：抓取页面并保存（用于确认 API 路径）
# ═══════════════════════════════════════════════════════════════

def debug_dump(se: Session, output_dir: str = "./debug"):
    """
    调试模式：调用真实 API 并保存完整响应用于分析
    从金智 emap 前端 JS 逆向获取的真实 API 路径
    """
    import pathlib
    out = pathlib.Path(output_dir)
    out.mkdir(exist_ok=True)

    MODULE_BASE = f"{GSAPP_BASE}/sys/wdxwxxfudan/modules/xsbdjcsq"

    # ── 0. Session 诊断 ────────────────────────────────────
    log.info("── Session 诊断 ──")
    cookies_dict = dict(se.cookies)
    log.info(f"Cookies: {list(cookies_dict.keys())}")
    (out / "session_cookies.json").write_text(
        json.dumps(cookies_dict, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ── 1. 保存首页 HTML ───────────────────────────────────
    r = se.get(GSAPP_CAS_SERVICE, timeout=15)
    (out / "index.html").write_text(r.text, encoding="utf-8")
    log.info(f"已保存: index.html ({len(r.text)} bytes)")

    # 从首页提取 USERID
    userid_match = re.search(r'"USERID"\s*:\s*"(\d+)"', r.text)
    userid = userid_match.group(1) if userid_match else ""
    log.info(f"提取到 USERID: {userid}")

    # 更新后的 cookies
    cookies_dict2 = dict(se.cookies)
    log.info(f"首页后 Cookies: {list(cookies_dict2.keys())}")
    (out / "session_cookies_after_index.json").write_text(
        json.dumps(cookies_dict2, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ── 通用请求头（模拟前端 jQuery ajax） ──
    ajax_headers = {
        "Referer": GSAPP_CAS_SERVICE,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
    }

    # ── 2. 查询学位申请主表（前端 JS 确认的路径） ───────
    log.info("── 查询学位申请主表 (xwgg_xwsqzbcx.do) ──")
    try:
        r1 = se.post(
            f"{MODULE_BASE}/xwgg_xwsqzbcx.do",
            data={"pageSize": "100", "pageNumber": "1", "XH": userid, "SFYX": "1"},
            headers=ajax_headers,
            timeout=15,
        )
        (out / "api_xwsqzb.json").write_text(r1.text, encoding="utf-8")
        log.info(f"已保存: api_xwsqzb.json (status={r1.status_code}, {len(r1.text)} bytes)")
        log.info(f"  响应前200字: {r1.text[:200]}")
    except Exception as e:
        (out / "api_xwsqzb_error.txt").write_text(str(e), encoding="utf-8")
        log.error(f"学位申请主表查询失败: {e}")

    # ── 2b. 尝试 getXwxxInfo（xsbdjcsqcx_xwzb.do） ─────
    log.info("── 尝试 xsbdjcsqcx_xwzb.do（学位信息查询） ──")
    try:
        rb = se.post(
            f"{MODULE_BASE}/xsbdjcsqcx_xwzb.do",
            data={"XH": userid, "*order": "-SQSJ,-XWPCDM"},
            headers=ajax_headers,
            timeout=15,
        )
        (out / "api_xsbdjcsqcx_xwzb.json").write_text(rb.text, encoding="utf-8")
        log.info(f"已保存: api_xsbdjcsqcx_xwzb.json (status={rb.status_code}, {len(rb.text)} bytes)")
        log.info(f"  响应前200字: {rb.text[:200]}")
    except Exception as e:
        log.error(f"xsbdjcsqcx_xwzb 查询失败: {e}")

    # ── 3. 查询评阅结果 ──────────────────────────────────
    # 先从主表获取 lwcjpcwid
    lwcjpcwid = ""
    try:
        body1 = json.loads((out / "api_xwsqzb.json").read_text(encoding="utf-8"))
        # 金智 emap 标准返回: { datas: { xwgg_xwsqzbcx: { rows: [...] } } }
        datas = body1.get("datas", body1)
        if isinstance(datas, dict):
            rows_c = datas.get("xwgg_xwsqzbcx", datas)
            if isinstance(rows_c, dict):
                rows = rows_c.get("rows", [])
                if rows:
                    lwcjpcwid = rows[0].get("LWCJPCWID", "")
                    log.info(f"从主表提取: LWCJPCWID={lwcjpcwid}")
    except Exception as e:
        log.warning(f"解析主表数据失败: {e}")

    log.info(f"── 查询评阅结果 (queryPyjg.do, lwcjpcwid={lwcjpcwid or '-999'}) ──")
    try:
        r2 = se.post(
            f"{MODULE_BASE}/queryPyjg.do",
            data={"lwcjpcwid": lwcjpcwid or "-999"},
            headers=ajax_headers,
            timeout=15,
        )
        (out / "api_queryPyjg.json").write_text(r2.text, encoding="utf-8")
        log.info(f"已保存: api_queryPyjg.json (status={r2.status_code}, {len(r2.text)} bytes)")
        log.info(f"  响应前200字: {r2.text[:200]}")
    except Exception as e:
        (out / "api_queryPyjg_error.txt").write_text(str(e), encoding="utf-8")
        log.error(f"评阅结果查询失败: {e}")

    # ── 4. 全量 API 端点测试（从 JS 逆向获取） ──────────
    # 包含 sqxqBS.js 和 xsbdjcsqBS.js 中发现的所有端点
    extra_apis = [
        # sqxqBS.js 中的端点
        ("querySqzg",       f"{MODULE_BASE}/querySqzg.do",       {}),
        ("queryEnablePc",   f"{MODULE_BASE}/queryEnablePc.do",   {}),
        ("querySqsjRange",  f"{MODULE_BASE}/querySqsjRange.do",  {}),
        ("queryXsInfo",     f"{MODULE_BASE}/queryXsInfo.do",     {"XH": userid}),
        ("xwgg_xwpccx",     f"{MODULE_BASE}/xwgg_xwpccx.do",    {}),
        ("dbzslwcx",        f"{MODULE_BASE}/dbzslwcx.do",        {"XH": userid}),
        ("ssfsxg",          f"{MODULE_BASE}/ssfsxg.do",          {}),
        ("xwlwxscx",        f"{MODULE_BASE}/xwlwxscx.do",       {"BY2": "", "SFSY": "1"}),
        ("shrzcx",          f"{MODULE_BASE}/shrzcx.do",          {}),
        ("queryXwlwthyy",   f"{MODULE_BASE}/queryXwlwthyy.do",   {}),
        ("checkFileExistsByToken", f"{MODULE_BASE}/checkFileExistsByToken.do", {}),
        ("sendWeChat",      f"{MODULE_BASE}/sendWeChat.do",      {}),
        # xsbdjcsqBS.js 中的端点
        ("pyjglrcx",        f"{MODULE_BASE}/pyjglrcx.do",        {}),
        ("dbjglrcx_fd",     f"{MODULE_BASE}/dbjglrcx_fd.do",     {}),
        ("checkIsxwtg",     f"{MODULE_BASE}/checkIsxwtg.do",     {}),
        ("queryXwzxx",      f"{MODULE_BASE}/queryXwzxx.do",      {}),
        ("dbsqsjQuery",     f"{MODULE_BASE}/dbsqsjQuery.do",     {}),
        ("getSfxwsq",       f"{MODULE_BASE}/getSfxwsq.do",       {}),
        ("checkZsxxsffb",   f"{MODULE_BASE}/checkZsxxsffb.do",   {}),
        ("xsbdjcsqcx",      f"{MODULE_BASE}/xsbdjcsqcx.do",      {"pageSize": "1", "pageNumber": "1", "WID": ""}),
    ]
    for name, url, params in extra_apis:
        try:
            r = se.post(url, timeout=10, data=params, headers=ajax_headers)
            status = r.status_code
            # 判断是否有实际数据
            is_data = False
            try:
                j = r.json()
                code = str(j.get("code", ""))
                if code == "404":
                    fname = f"api_{name}_emap404.json"
                else:
                    is_data = True
                    fname = f"api_{name}.json"
            except Exception:
                if status == 404:
                    fname = f"api_{name}_404.txt"
                else:
                    is_data = True
                    fname = f"api_{name}_{status}.txt"
            (out / fname).write_text(r.text[:10000], encoding="utf-8")
            tag = "✅ 有数据!" if is_data else "❌"
            log.info(f"  {tag} {name}: {fname} (status={status}, {len(r.text)} bytes)")
        except Exception as e:
            (out / f"api_{name}_error.txt").write_text(str(e), encoding="utf-8")
            log.info(f"  ❌ {name}: 请求异常 - {e}")

    # ── 5. 直接访问 querySqzg.do（核心入口 API） ──────
    # 前端打开详情页时，先调用 querySqzg.do 获取 sqzgData
    # 这个 API 可能包含评阅相关的全部数据
    log.info("── 重点: querySqzg.do（申请资格数据，含 sqzgData） ──")
    try:
        rsq = se.post(
            f"{MODULE_BASE}/querySqzg.do",
            data={"XH": userid},
            headers=ajax_headers,
            timeout=15,
        )
        (out / "api_querySqzg.json").write_text(rsq.text, encoding="utf-8")
        log.info(f"已保存: api_querySqzg.json (status={rsq.status_code}, {len(rsq.text)} bytes)")
        log.info(f"  响应前300字: {rsq.text[:300]}")
    except Exception as e:
        log.error(f"querySqzg 查询失败: {e}")

    # ── 6. 尝试 GET 请求（部分 emap 端点可能用 GET） ──
    log.info("── 尝试 GET 请求 ──")
    for name, path in [("querySqzg_GET", "/querySqzg.do"), ("xwgg_xwsqzbcx_GET", "/xwgg_xwsqzbcx.do")]:
        try:
            r = se.get(f"{MODULE_BASE}{path}", params={"XH": userid}, headers=ajax_headers, timeout=10)
            (out / f"api_{name}.json").write_text(r.text[:10000], encoding="utf-8")
            log.info(f"  {name}: status={r.status_code}, {len(r.text)} bytes, 前100字: {r.text[:100]}")
        except Exception as e:
            log.info(f"  {name}: 失败 - {e}")

    log.info(f"\n{'='*50}")
    log.info(f"调试数据已保存到 {out.absolute()}/")
    log.info(f"请重点检查:")
    log.info(f"  1. api_xwsqzb.json - 学位申请主表")
    log.info(f"  2. api_queryPyjg.json - 评阅结果")
    log.info(f"  3. api_querySqzg.json - 申请资格数据（可能含评阅信息）")
    log.info(f"  4. 所有 ✅ 标记的文件 - 有实际数据的 API")
    log.info(f"  5. session_cookies*.json - 确认 JSESSIONID 存在")


# ═══════════════════════════════════════════════════════════════
#  主监控循环
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(description="复旦研究生院盲审评阅结果监控")
    parser.add_argument("-u", "--username",  default="xxx", help="学号（也可用环境变量 FUDAN_USERNAME）")
    parser.add_argument("-p", "--password",  default="xxx", help="密码（也可用环境变量 FUDAN_PASSWORD）")
    parser.add_argument("-s", "--sendkey",   default="xxx", help="Server酱 SendKey（也可用环境变量 SENDKEY）")
    parser.add_argument("--interval",        type=int, default=0, help="检查间隔秒数，默认 1800（30分钟）")
    parser.add_argument("--debug",           action="store_true", help="调试模式：登录后抓取所有 API 端点并保存")
    parser.add_argument("--output",           default="./debug", help="调试模式输出目录（默认 ./debug）")
    args = parser.parse_args()

    # 命令行参数优先级高于环境变量
    username   = args.username   or FUDAN_USERNAME
    password   = args.password   or FUDAN_PASSWORD
    sendkey    = args.sendkey    or SENDKEY
    interval   = args.interval   or CHECK_INTERVAL

    # 动态更新推送地址
    global SERVERCHAN_API
    if sendkey:
        SERVERCHAN_API = f"https://sctapi.ftqq.com/{sendkey}.send"

    # 参数检查
    if not username or not password:
        log.error("❌ 未提供账号或密码！")
        log.error("   方式一（命令行）：python fudan_score_monitor.py -u 学号 -p 密码")
        log.error("   方式二（.env）：复制 env.example.txt -> .env，填写后重新运行")
        log.error("   方式三（环境变量）：FUDAN_USERNAME=xxx FUDAN_PASSWORD=xxx python fudan_score_monitor.py")
        return

    if not sendkey:
        log.warning("⚠️  未设置 SENDKEY，微信推送不可用")
        log.warning("   前往 https://sct.ftqq.com/ 获取 SendKey，通过 --sendkey 或环境变量传入")

    # 调试模式
    if args.debug:
        log.info("🔍 调试模式：登录并抓取所有 API 端点 ...")
        se = uis_login(username, password)
        gsapp_init(se)
        debug_dump(se, output_dir=args.output)
        return

    log.info("=" * 50)
    log.info("🎓 复旦盲审评阅结果监控")
    log.info(f"   系统入口: {GSAPP_CAS_SERVICE}")
    log.info(f"   检查间隔: {interval} 秒 ({interval // 60} 分钟)")
    log.info("=" * 50)

    # 首次登录
    se = uis_login(username, password)
    gsapp_init(se)

    # 首次抓取，建立基准
    log.info("首次查询评阅信息，建立基准 ...")
    review_data = query_review_info(se, username)
    last_fingerprint = compute_fingerprint(review_data)
    log.info(f"基准指纹: {last_fingerprint[:8]}...，共 {len(review_data)} 条记录")

    if review_data:
        summary = format_review_summary(review_data)
        log.info(f"当前评阅数据:\n{summary[:500]}")
    else:
        log.warning("⚠️  未获取到评阅数据")
        log.warning("   请运行: python fudan_score_monitor.py --debug")

    log.info("✅ 基准已建立，仅在评阅结果变化时推送微信")

    # 循环监控
    round_num = 0
    while True:
        round_num += 1
        log.info(f"── 第 {round_num} 轮检查 ──")

        try:
            # 检查 session 是否有效，无效则重登录
            review_data = query_review_info(se, username)

            # 如果返回空数据，可能是 session 过期
            if not review_data:
                log.warning("返回空数据，尝试重新登录 ...")
                se = uis_login(username, password)
                gsapp_init(se)
                review_data = query_review_info(se, username)

            new_fingerprint = compute_fingerprint(review_data)

            if new_fingerprint != last_fingerprint:
                log.info("🎉 检测到评阅结果变化！")
                summary = format_review_summary(review_data)

                push_wechat(
                    "🎉 复旦盲审评阅结果已更新！",
                    f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    f"最新评阅信息:\n{summary}"
                )
                last_fingerprint = new_fingerprint
            else:
                log.info("暂无变化，继续监控 ...")

        except Exception as e:
            log.error(f"本轮检查出错: {e}")
            # 网络异常时尝试重登录
            try:
                log.info("尝试重新登录 ...")
                se = uis_login(username, password)
                gsapp_init(se)
            except Exception as e2:
                log.error(f"重登录也失败: {e2}")

        next_check = datetime.fromtimestamp(time.time() + interval).strftime("%H:%M:%S")
        log.info(f"下次检查: {next_check}（{interval // 60} 分钟后）\n")
        time.sleep(interval)


if __name__ == "__main__":
    main()

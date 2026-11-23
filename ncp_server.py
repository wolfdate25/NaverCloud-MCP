import os
import time
import hmac
import hashlib
import base64
import ssl
from typing import Optional
from urllib.parse import urlencode
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ncp-server")

BASE_URL   = "https://ncloud.apigw.ntruss.com"
ACCESS_KEY = os.environ["NCP_ACCESS_KEY"]
SECRET_KEY = os.environ["NCP_SECRET_KEY"]

# NCP VPC 자주 쓰는 서버 이미지 / 스펙 코드 매핑 (KR 리전, 2026-05-14 NCP API 검증).
# Rocky Linux 9 이미지는 KR·SGN·JPN·USWN 어디에도 제공되지 않으므로 매핑 없음.
# 가용 Rocky는 8.8 / 8.10 이며, 호환 Standard 스펙은 G2 세대 / 디스크 50GB SSD 기준.

# Rocky Linux 이미지 (alias → serverImageProductCode)
ROCKY_LINUX_IMAGES = {
    "rocky8.8":  "SW.VSVR.OS.LNX64.ROCKY.0808.B050",
    "rocky8.10": "SW.VSVR.OS.LNX64.ROCKY.0810.B050",
}

# Standard (G2) 스펙 — 2 ~ 32 vCPU (alias → serverProductCode)
# 형식: SVR.VSVR.STAND.C{cpu}.M{mem}.NET.SSD.B050.G002 (Rocky 8.x 호환 검증됨)
STANDARD_SPECS = {
    "s2-g2":  "SVR.VSVR.STAND.C002.M008.NET.SSD.B050.G002",   # 2 vCPU /   8 GB
    "s4-g2":  "SVR.VSVR.STAND.C004.M016.NET.SSD.B050.G002",   # 4 vCPU /  16 GB
    "s8-g2":  "SVR.VSVR.STAND.C008.M032.NET.SSD.B050.G002",   # 8 vCPU /  32 GB
    "s16-g2": "SVR.VSVR.STAND.C016.M064.NET.SSD.B050.G002",   # 16 vCPU /  64 GB
    "s32-g2": "SVR.VSVR.STAND.C032.M128.NET.SSD.B050.G002",   # 32 vCPU / 128 GB
}

def resolve_image_code(value: str) -> str:
    """alias("rocky8.10") 또는 풀 코드("SW.VSVR.OS...") 모두 허용 → 풀 코드 반환."""
    return ROCKY_LINUX_IMAGES.get(value, value)

def resolve_spec_code(value: str) -> str:
    """alias("s2-g2") 또는 풀 코드("SVR.VSVR.STAND...") 모두 허용 → 풀 코드 반환."""
    return STANDARD_SPECS.get(value, value)

def _sign(method: str, path: str) -> dict:
    timestamp = str(int(time.time() * 1000))
    message   = f"{method} {path}\n{timestamp}\n{ACCESS_KEY}"
    signature = base64.b64encode(
        hmac.new(SECRET_KEY.encode("utf-8"),
                  message.encode("utf-8"),
                  hashlib.sha256).digest()
    ).decode("utf-8")
    return {
        "x-ncp-apigw-timestamp":    timestamp,
        "x-ncp-iam-access-key":     ACCESS_KEY,
        "x-ncp-apigw-signature-v2": signature,
    }

class _SystemCAAdapter(requests.adapters.HTTPAdapter):
    """시스템 CA 묶음을 신뢰하고 VERIFY_X509_STRICT만 끈다 (인증서 검증은 유지).

    사내 TLS 검사 루트 CA가 AKI 확장이 없어 Python 3.13+ 엄격 검사에서 거부되는 문제 대응.
    """

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=CA_BUNDLE)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


CA_BUNDLE = os.environ.get("NCP_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
_http = requests.Session()
_http.mount("https://", _SystemCAAdapter())


def _get(path: str) -> dict:
    res = _http.get(BASE_URL + path, headers=_sign("GET", path))
    try:
        return res.json()
    except ValueError:
        return {"error": f"HTTP {res.status_code}", "body": res.text}

def _build_path(endpoint: str, params: dict) -> str:
    query = {k: v for k, v in params.items() if v is not None and v != ""}
    # NCP API는 기본적으로 XML로 응답한다. responseFormatType=json을 강제해
    # _get()의 res.json() 파싱이 성공하도록 한다.
    query.setdefault("responseFormatType", "json")
    return f"{endpoint}?{urlencode(query)}"


# ─────────────────────────────────────────────────────────────────────────────
# Response slimmers — NCP raw 응답에서 LLM에 유의미한 필드만 추려 토큰 절약.
# raw 봉투(get…ListResponse → …List)를 벗기고 enum 객체({code, codeName})는 code만 남긴다.
# ─────────────────────────────────────────────────────────────────────────────

def _code(v):
    """NCP enum 필드는 {"code":..., "codeName":...} 객체 또는 문자열로 옴 → code만 추출."""
    if isinstance(v, dict):
        return v.get("code", "")
    return v or ""


def _first_nic_ip(s: dict) -> str:
    for nic in s.get("networkInterfaceList") or []:
        if nic.get("ip"):
            return nic["ip"]
    return ""


def _slim_server(s: dict) -> dict:
    return {
        "no":          s.get("serverInstanceNo", ""),
        "name":        s.get("serverName", ""),
        "status":      _code(s.get("serverInstanceStatus")),
        "op":          _code(s.get("serverInstanceOperation")),
        "pubIp":       s.get("publicIp") or "",
        "priIp":       _first_nic_ip(s),
        "spec":        s.get("serverProductCode", ""),
        "image":       s.get("serverImageProductCode", ""),
        "vpcNo":       s.get("vpcNo", ""),
        "subnetNo":    s.get("subnetNo", ""),
        "zone":        _code(s.get("zoneCode")),
        "loginKey":    s.get("loginKeyName", ""),
        "termProtect": s.get("isProtectServerTermination", False),
    }


def _slim_vpc(v: dict) -> dict:
    return {
        "no":     v.get("vpcNo", ""),
        "name":   v.get("vpcName", ""),
        "cidr":   v.get("ipv4CidrBlock", ""),
        "status": _code(v.get("vpcStatus")),
        "region": _code(v.get("regionCode")),
    }


def _slim_subnet(s: dict) -> dict:
    return {
        "no":     s.get("subnetNo", ""),
        "name":   s.get("subnetName", ""),
        "vpcNo":  s.get("vpcNo", ""),
        "cidr":   s.get("subnet", ""),
        "zone":   _code(s.get("zoneCode")),
        "type":   _code(s.get("subnetType")),
        "usage":  _code(s.get("usageType")),
        "aclNo":  s.get("networkAclNo", ""),
        "status": _code(s.get("subnetStatus")),
    }


def _slim_acg(a: dict) -> dict:
    return {
        "no":      a.get("accessControlGroupNo", ""),
        "name":    a.get("accessControlGroupName", ""),
        "vpcNo":   a.get("vpcNo", ""),
        "default": a.get("isDefault", False),
        "status":  _code(a.get("accessControlGroupStatus")),
        "desc":    a.get("accessControlGroupDescription", ""),
    }


def _slim_nacl(a: dict) -> dict:
    return {
        "no":      a.get("networkAclNo", ""),
        "name":    a.get("networkAclName", ""),
        "vpcNo":   a.get("vpcNo", ""),
        "default": a.get("isDefault", False),
        "status":  _code(a.get("networkAclStatus")),
        "desc":    a.get("networkAclDescription", ""),
    }


def _slim_list(res: dict, response_key: str, list_key: str, slim_fn) -> dict:
    """NCP list 응답 봉투를 벗기고 항목을 slim_fn으로 다듬어 반환.

    에러 응답은 그대로 통과시킨다. totalRows가 노출된 항목 수보다 크면
    페이지네이션이 남은 것이므로 'total' 필드로 알린다.
    """
    if "error" in res:
        return res
    inner = res.get(response_key) or {}
    items = inner.get(list_key) or []
    out = {"count": len(items), "items": [slim_fn(x) for x in items]}
    total = inner.get("totalRows")
    if total is not None and total != len(items):
        out["total"] = total
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Provisioning helpers — provision_server 부트스트랩 전용 (단일 툴로 합치기 위함).
# ─────────────────────────────────────────────────────────────────────────────

def _get_vpc_status(vpc_no: str, region_code: str) -> str:
    res = _get(_build_path("/vpc/v2/getVpcDetail", {
        "regionCode": region_code, "vpcNo": vpc_no,
    }))
    vlist = (res.get("getVpcDetailResponse") or {}).get("vpcList") or []
    return _code(vlist[0].get("vpcStatus")) if vlist else ""


def _get_subnet_status(subnet_no: str, region_code: str) -> str:
    res = _get(_build_path("/vpc/v2/getSubnetDetail", {
        "regionCode": region_code, "subnetNo": subnet_no,
    }))
    slist = (res.get("getSubnetDetailResponse") or {}).get("subnetList") or []
    return _code(slist[0].get("subnetStatus")) if slist else ""


def _wait_for(get_status, target: str, timeout: int = 120, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if get_status() == target:
            return True
        time.sleep(interval)
    return False


def _find_vpc_by_name(name: str, region_code: str) -> Optional[dict]:
    res = _get(_build_path("/vpc/v2/getVpcList", {"regionCode": region_code}))
    for v in (res.get("getVpcListResponse") or {}).get("vpcList") or []:
        if v.get("vpcName") == name:
            return v
    return None


def _find_subnet_by_name(vpc_no: str, name: str, region_code: str) -> Optional[dict]:
    res = _get(_build_path("/vpc/v2/getSubnetList", {
        "regionCode": region_code, "vpcNo": vpc_no,
    }))
    for s in (res.get("getSubnetListResponse") or {}).get("subnetList") or []:
        if s.get("subnetName") == name:
            return s
    return None


def _get_my_ip() -> Optional[str]:
    """현재 호스트의 외부 공인 IP를 조회. provision_server의 'myip' 규칙용.

    조회 실패 시 None 반환 → 호출 측에서 myip 규칙을 건너뛴다.
    """
    try:
        r = _http.get("https://api.ipify.org", timeout=5)
        if r.status_code == 200:
            ip = r.text.strip()
            if ip:
                return ip
    except requests.RequestException:
        pass
    return None


def _get_default_acl_no(vpc_no: str, region_code: str) -> Optional[str]:
    """VPC 생성 시 NCP가 자동 생성하는 default Network ACL 번호를 조회."""
    res = _get(_build_path("/vpc/v2/getNetworkAclList", {
        "regionCode": region_code, "vpcNo": vpc_no,
    }))
    acls = (res.get("getNetworkAclListResponse") or {}).get("networkAclList") or []
    for a in acls:
        if a.get("isDefault") is True:
            return str(a.get("networkAclNo"))
    return str(acls[0].get("networkAclNo")) if acls else None


@mcp.tool()
def list_servers(region_code: str = "KR") -> dict:
    """NCP 서버 인스턴스 목록을 조회합니다.

    응답 항목 키: no, name, status, op, pubIp, priIp, spec, image,
    vpcNo, subnetNo, zone, loginKey, termProtect.
    """
    res = _get(_build_path("/vserver/v2/getServerInstanceList", {"regionCode": region_code}))
    return _slim_list(res, "getServerInstanceListResponse",
                      "serverInstanceList", _slim_server)

@mcp.tool()
def list_vpcs(region_code: str = "KR") -> dict:
    """VPC 목록을 조회합니다.

    응답 항목 키: no, name, cidr, status, region.
    """
    res = _get(_build_path("/vpc/v2/getVpcList", {"regionCode": region_code}))
    return _slim_list(res, "getVpcListResponse", "vpcList", _slim_vpc)

@mcp.tool()
def get_server_detail(server_instance_no: str,
                      region_code: str = "KR") -> dict:
    """특정 서버의 상세 정보를 조회합니다. (list_servers와 동일 스키마)"""
    path = _build_path("/vserver/v2/getServerInstanceList", {
        "regionCode": region_code,
        "serverInstanceNoList.1": server_instance_no,
    })
    res = _get(path)
    return _slim_list(res, "getServerInstanceListResponse",
                      "serverInstanceList", _slim_server)

@mcp.tool()
def create_vpc(vpc_name: str,
               ipv4_cidr_block: str,
               region_code: str = "KR") -> dict:
    """VPC를 생성합니다.

    Args:
        vpc_name: VPC 이름 (영소문자·숫자·하이픈, 3-30자)
        ipv4_cidr_block: VPC IPv4 CIDR (예: 10.0.0.0/16, /16~/28)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vpc/v2/createVpc", {
        "regionCode":    region_code,
        "vpcName":       vpc_name,
        "ipv4CidrBlock": ipv4_cidr_block,
    })
    return _get(path)

@mcp.tool()
def delete_vpc(vpc_no: str,
               region_code: str = "KR") -> dict:
    """VPC를 삭제합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-deletevpc

    ⚠️ 되돌릴 수 없습니다. VPC에 속한 모든 Subnet·NIC·ACG 등이 먼저 정리되어
    있어야 합니다. (서버는 NSTOP 상태에서도 VPC 삭제를 막으므로 종료 후 제거 필요.)

    Args:
        vpc_no: 삭제할 VPC 번호 (list_vpcs로 확인)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vpc/v2/deleteVpc", {
        "regionCode": region_code,
        "vpcNo":      vpc_no,
    })
    return _get(path)

@mcp.tool()
def list_subnets(vpc_no: str = "",
                 region_code: str = "KR") -> dict:
    """Subnet 목록을 조회합니다.

    Args:
        vpc_no: 특정 VPC의 Subnet만 조회 (선택)
        region_code: 리전 코드
    """
    path = _build_path("/vpc/v2/getSubnetList", {
        "regionCode": region_code,
        "vpcNo":      vpc_no,
    })
    res = _get(path)
    return _slim_list(res, "getSubnetListResponse", "subnetList", _slim_subnet)

@mcp.tool()
def create_subnet(vpc_no: str,
                  subnet_name: str,
                  subnet: str,
                  zone_code: str,
                  network_acl_no: str,
                  subnet_type_code: str = "PUBLIC",
                  usage_type: str = "GEN",
                  region_code: str = "KR") -> dict:
    """Subnet을 생성합니다.

    Args:
        vpc_no: 상위 VPC 번호 (list_vpcs로 확인)
        subnet_name: Subnet 이름 (영소문자·숫자·하이픈, 3-30자)
        subnet: Subnet CIDR (VPC CIDR 범위 내, 예: 10.0.1.0/24)
        zone_code: Zone 코드 (KR-1 · KR-2)
        network_acl_no: Network ACL 번호
        subnet_type_code: PUBLIC · PRIVATE
        usage_type: GEN · LOADB · BM · NATGW
        region_code: 리전 코드
    """
    path = _build_path("/vpc/v2/createSubnet", {
        "regionCode":     region_code,
        "vpcNo":          vpc_no,
        "subnetName":     subnet_name,
        "subnet":         subnet,
        "zoneCode":       zone_code,
        "networkAclNo":   network_acl_no,
        "subnetTypeCode": subnet_type_code,
        "usageType":      usage_type,
    })
    return _get(path)

@mcp.tool()
def delete_subnet(subnet_no: str,
                  region_code: str = "KR") -> dict:
    """Subnet을 삭제합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-deletesubnet

    ⚠️ 되돌릴 수 없습니다. Subnet에 NIC가 남아 있으면 삭제가 거부되므로,
    먼저 서버/NIC를 정리한 뒤 호출하세요.

    Args:
        subnet_no: 삭제할 Subnet 번호 (list_subnets로 확인)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vpc/v2/deleteSubnet", {
        "regionCode": region_code,
        "subnetNo":   subnet_no,
    })
    return _get(path)

@mcp.tool()
def list_network_acls(vpc_no: str = "",
                      network_acl_no_list: Optional[list] = None,
                      network_acl_name: str = "",
                      network_acl_status_code: str = "",
                      page_no: Optional[int] = None,
                      page_size: Optional[int] = None,
                      region_code: str = "KR") -> dict:
    """Network ACL 목록을 조회합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-getnetworkacllist

    Args:
        vpc_no: 특정 VPC의 NACL만 조회 (선택)
        network_acl_no_list: 특정 NACL 번호 필터 (선택, list[str])
        network_acl_name: NACL 이름 필터 (선택)
        network_acl_status_code: 상태 코드 필터 (INIT · RUN · SET · TERMTING, 선택)
        page_no: 페이지 번호 (0~N, 선택)
        page_size: 페이지당 개수 (1~1000, page_no 지정 시 필수)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    params: dict = {
        "regionCode":           region_code,
        "vpcNo":                vpc_no,
        "networkAclName":       network_acl_name,
        "networkAclStatusCode": network_acl_status_code,
    }
    if page_no is not None:
        params["pageNo"] = page_no
    if page_size is not None:
        params["pageSize"] = page_size
    if network_acl_no_list:
        for i, no in enumerate(network_acl_no_list, start=1):
            params[f"networkAclNoList.{i}"] = no
    path = _build_path("/vpc/v2/getNetworkAclList", params)
    res = _get(path)
    return _slim_list(res, "getNetworkAclListResponse",
                      "networkAclList", _slim_nacl)


@mcp.tool()
def create_network_acl(vpc_no: str,
                       network_acl_name: str = "",
                       network_acl_description: str = "",
                       region_code: str = "KR") -> dict:
    """Network ACL을 생성합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-createnetworkacl

    생성 직후 NACL은 default deny 규칙만 있다. inbound/outbound 규칙은
    별도 API(addNetworkAclInboundRule / addNetworkAclOutboundRule)로 추가한다.

    Args:
        vpc_no: 상위 VPC 번호 (list_vpcs로 확인) — 필수
        network_acl_name: NACL 이름 (영소문자·숫자·하이픈, 3-30자, 생략 시 자동 부여)
        network_acl_description: 설명 (0~1000B, 선택)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vpc/v2/createNetworkAcl", {
        "regionCode":              region_code,
        "vpcNo":                   vpc_no,
        "networkAclName":          network_acl_name,
        "networkAclDescription":   network_acl_description,
    })
    return _get(path)


@mcp.tool()
def delete_network_acl(network_acl_no: str,
                       region_code: str = "KR") -> dict:
    """Network ACL을 삭제합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-deletenetworkacl

    ⚠️ 되돌릴 수 없습니다. default NACL은 삭제할 수 없으며, Subnet에
    연결된 NACL도 삭제가 거부됩니다. 먼저 Subnet의 NACL을 다른 것으로
    교체한 뒤 호출하세요.

    Args:
        network_acl_no: 삭제할 NACL 번호 (list_network_acls로 확인)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vpc/v2/deleteNetworkAcl", {
        "regionCode":   region_code,
        "networkAclNo": network_acl_no,
    })
    return _get(path)


@mcp.tool()
def list_access_control_groups(vpc_no: str = "",
                               access_control_group_no_list: Optional[list] = None,
                               access_control_group_name: str = "",
                               access_control_group_status_code: str = "",
                               page_no: Optional[int] = None,
                               page_size: Optional[int] = None,
                               region_code: str = "KR") -> dict:
    """ACG(Access Control Group) 목록을 조회합니다.

    참고: https://api.ncloud-docs.com/docs/common-vapidatatype-accesscontrolgrouplist

    Args:
        vpc_no: 특정 VPC의 ACG만 조회 (선택)
        access_control_group_no_list: 특정 ACG 번호 필터 (선택, list[str])
        access_control_group_name: ACG 이름 필터 (선택)
        access_control_group_status_code: 상태 코드 필터 (선택)
            INIT · SET · RUN · TERMTING
        page_no: 페이지 번호 (0~N, 선택)
        page_size: 페이지당 개수 (1~1000, page_no 지정 시 필수)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    params: dict = {
        "regionCode":                   region_code,
        "vpcNo":                        vpc_no,
        "accessControlGroupName":       access_control_group_name,
        "accessControlGroupStatusCode": access_control_group_status_code,
    }
    if page_no is not None:
        params["pageNo"] = page_no
    if page_size is not None:
        params["pageSize"] = page_size
    if access_control_group_no_list:
        for i, no in enumerate(access_control_group_no_list, start=1):
            params[f"accessControlGroupNoList.{i}"] = no
    path = _build_path("/vserver/v2/getAccessControlGroupList", params)
    res = _get(path)
    return _slim_list(res, "getAccessControlGroupListResponse",
                      "accessControlGroupList", _slim_acg)


@mcp.tool()
def create_access_control_group(vpc_no: str,
                                access_control_group_name: str = "",
                                access_control_group_description: str = "",
                                region_code: str = "KR") -> dict:
    """ACG(Access Control Group)를 생성합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-createaccesscontrolgroup

    생성 직후 ACG는 inbound/outbound 규칙이 비어 있다. 규칙을 추가하려면
    add_acg_inbound_rule / add_acg_outbound_rule을 호출한다.

    Args:
        vpc_no: 상위 VPC 번호 (list_vpcs로 확인) — 필수
        access_control_group_name: ACG 이름 (영소문자·숫자·하이픈, 3-30자, 생략 시 자동 부여)
        access_control_group_description: 설명 (0~1000B, 선택)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vserver/v2/createAccessControlGroup", {
        "regionCode":                     region_code,
        "vpcNo":                          vpc_no,
        "accessControlGroupName":         access_control_group_name,
        "accessControlGroupDescription":  access_control_group_description,
    })
    return _get(path)


def _build_acg_rule_path(endpoint: str,
                        access_control_group_no: str,
                        rules: list,
                        region_code: str,
                        vpc_no: str = "") -> str:
    """ACG 규칙 추가용 path 생성 (inbound/outbound 공통)."""
    params: dict = {
        "regionCode":             region_code,
        "vpcNo":                  vpc_no,
        "accessControlGroupNo":   access_control_group_no,
    }
    params.update(_flatten_dict_list("accessControlGroupRuleList", rules))
    return _build_path(endpoint, params)


@mcp.tool()
def add_acg_inbound_rule(access_control_group_no: str,
                         rules: list,
                         region_code: str = "KR",
                         vpc_no: str = "") -> dict:
    """ACG에 inbound(수신) 규칙을 추가합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-addaccesscontrolgroupinboundrule

    Args:
        access_control_group_no: 대상 ACG 번호 (list_access_control_groups로 확인) — 필수
        rules: 규칙 리스트(list[dict]). 각 dict 키:
            - protocolTypeCode (필수): "TCP" · "UDP" · "ICMP"
            - ipBlock (선택): 출발지 IPv4 CIDR (예: "0.0.0.0/0", "10.0.0.0/24")
            - accessControlGroupSequence (선택): 출발지 ACG 번호 (다른 ACG를 출발지로 지정)
              ※ ipBlock 또는 accessControlGroupSequence 중 하나는 반드시 지정
            - portRange (TCP/UDP 필수): "22" 단일 포트, "1-65535" 범위. ICMP는 생략.
            - accessControlGroupRuleDescription (선택): 설명 (0~1000B)
            예: [
              {"protocolTypeCode": "TCP", "ipBlock": "0.0.0.0/0", "portRange": "22",
               "accessControlGroupRuleDescription": "SSH"},
              {"protocolTypeCode": "TCP", "ipBlock": "10.0.0.0/16", "portRange": "80-443"},
              {"protocolTypeCode": "ICMP", "ipBlock": "0.0.0.0/0"}
            ]
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_acg_rule_path(
        "/vserver/v2/addAccessControlGroupInboundRule",
        access_control_group_no, rules, region_code, vpc_no,
    )
    return _get(path)


@mcp.tool()
def add_acg_outbound_rule(access_control_group_no: str,
                          rules: list,
                          region_code: str = "KR",
                          vpc_no: str = "") -> dict:
    """ACG에 outbound(송신) 규칙을 추가합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpc-addaccesscontrolgroupoutboundrule

    Args:
        access_control_group_no: 대상 ACG 번호 — 필수
        rules: 규칙 리스트(list[dict]). 각 dict 키:
            - protocolTypeCode (필수): "TCP" · "UDP" · "ICMP"
            - ipBlock (선택): 목적지 IPv4 CIDR
            - accessControlGroupSequence (선택): 목적지 ACG 번호
              ※ ipBlock 또는 accessControlGroupSequence 중 하나는 반드시 지정
            - portRange (TCP/UDP 필수): "443", "1-65535" 등. ICMP는 생략.
            - accessControlGroupRuleDescription (선택): 설명
            예: [{"protocolTypeCode": "TCP", "ipBlock": "0.0.0.0/0", "portRange": "1-65535"}]
        region_code: 리전 코드
    """
    path = _build_acg_rule_path(
        "/vserver/v2/addAccessControlGroupOutboundRule",
        access_control_group_no, rules, region_code, vpc_no,
    )
    return _get(path)


def _get_default_acg_no(vpc_no: str, region_code: str = "KR") -> Optional[str]:
    """주어진 VPC의 default ACG 번호를 조회한다 (없으면 None).

    create_server가 NIC를 자동 구성할 때 사용. NCP는 createServerInstances
    호출 시 networkInterfaceList.1.accessControlGroupNoList.1을 사실상 필수로
    요구하므로, 사용자가 ACG를 명시하지 않은 경우 이 헬퍼로 VPC의 기본 ACG를
    찾아 채운다. 우선순위: isDefault=True → 첫 RUN 상태 ACG.
    """
    if not vpc_no:
        return None
    path = _build_path("/vserver/v2/getAccessControlGroupList", {
        "regionCode": region_code,
        "vpcNo":      vpc_no,
    })
    res = _get(path)
    acgs = (res.get("getAccessControlGroupListResponse", {})
              .get("accessControlGroupList", []))
    for a in acgs:
        if a.get("isDefault") is True:
            return str(a.get("accessControlGroupNo"))
    for a in acgs:
        if a.get("accessControlGroupStatus", {}).get("code") == "RUN":
            return str(a.get("accessControlGroupNo"))
    return None


def _flatten_dict_list(prefix: str, items: list) -> dict:
    """list[dict]를 NCP dot-notation 쿼리 키로 평탄화 (1-based 인덱스).

    각 dict의 list-valued 필드(예: accessControlGroupNoList)는
    `.M` 서브 인덱스(1부터)로 다시 풀어 보낸다. None / "" 값은 스킵.
    """
    flat: dict = {}
    for i, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        for key, val in item.items():
            if val is None or val == "":
                continue
            if isinstance(val, (list, tuple)):
                for j, sub in enumerate(val, start=1):
                    flat[f"{prefix}.{i}.{key}.{j}"] = sub
            else:
                flat[f"{prefix}.{i}.{key}"] = val
    return flat


def _flatten_nic_list(nic_list: list) -> dict:
    """networkInterfaceList 전용 래퍼 (하위 호환)."""
    return _flatten_dict_list("networkInterfaceList", nic_list)


@mcp.tool()
def create_login_key(keyName: str,
                     save_path: str = "",
                     regionCode: str = "KR") -> dict:
    """NCP 로그인 키(pem 파일)를 새로 생성하고 로컬에 저장합니다.

    참고: https://api.ncloud-docs.com/docs/compute-vserver-loginkey-createloginkey

    생성된 private key는 한 번만 발급되며 NCP 측에 저장되지 않으므로,
    호출 즉시 로컬 파일로 저장한다 (권한 0600).

    Args:
        keyName: 인증키 이름 (3-30자, 영문/숫자/하이픈). create_server의 loginKeyName으로 사용.
        save_path: pem 파일 저장 경로 (선택). 미지정 시 ~/Downloads/<keyName>.pem.
        regionCode: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vserver/v2/createLoginKey", {
        "regionCode": regionCode,
        "keyName":    keyName,
    })
    res = _get(path)
    private_key = (res.get("createLoginKeyResponse", {}) or {}).get("privateKey")
    if not private_key:
        return {"error": "privateKey가 응답에 없습니다.", "response": res}

    # 기본 저장 경로는 ~/Downloads/<keyName>.pem.
    # 사용자가 Finder/탐색기에서 쉽게 찾아 NCP 콘솔에 업로드(비밀번호 확인 등)할 수 있게 한다.
    # SSH 접속용으로 쓰려면 ~/.ssh/로 이동하거나 SSH config의 IdentityFile을 이 경로로 지정한다.
    target = save_path or os.path.expanduser(f"~/Downloads/{keyName}.pem")
    target = os.path.expanduser(target)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        f.write(private_key)
    os.chmod(target, 0o600)
    return {
        "result":   "ok",
        "keyName":  keyName,
        "savedTo":  target,
        "regionCode": regionCode,
    }


@mcp.tool()
def create_server(serverName: str,
                  serverImageProductCode: str,
                  vpcNo: str,
                  subnetNo: str,
                  loginKeyName: str = "",
                  serverProductCode: str = "",
                  serverDescription: str = "",
                  initScriptNo: str = "",
                  accessControlGroupNoList: Optional[list] = None,
                  networkInterfaceList: Optional[list] = None,
                  regionCode: str = "KR") -> dict:
    """NCP VPC 서버 인스턴스를 생성합니다.

    참고: https://api.ncloud-docs.com/docs/compute-vserver-server-createserverinstances

    Args:
        serverName: 서버 이름 (영소문자·숫자·하이픈, 3-30자)
        serverImageProductCode: 서버 이미지 코드 (풀 코드 또는 alias)
            ※ alias 입력 시 resolve_image_code로 자동 변환됨.
            기존 OS:
              - CentOS 7.3   : SW.VSVR.OS.LNX64.CNTOS.0703.B050
              - Ubuntu 20.04 : SW.VSVR.OS.LNX64.UBNTU.SVR2004.B050
              - Windows 2019 : SW.VSVR.OS.WND64.WND.SVR2019EN.B100
            Rocky Linux (ROCKY_LINUX_IMAGES dict 참조, NCP API 검증):
              - "rocky8.8"  → SW.VSVR.OS.LNX64.ROCKY.0808.B050
              - "rocky8.10" → SW.VSVR.OS.LNX64.ROCKY.0810.B050
            ※ Rocky Linux 9.x는 현재 NCP(KR/SGN/JPN/USWN) 미제공 — 9.x 코드 사용 금지.
        vpcNo: VPC 번호 (list_vpcs로 확인) — 필수
        subnetNo: 기본 NIC의 Subnet 번호 (list_subnets로 확인) — 필수
        loginKeyName: 인증키 이름 (선택, Linux SSH 접속용)
        serverProductCode: 서버 스펙 코드 (풀 코드 또는 alias, 생략 시 최소 사양)
            ※ alias 입력 시 resolve_spec_code로 자동 변환됨.
            Standard G2 (STANDARD_SPECS dict 참조, Rocky 8.x 호환 검증):
              - "s2-g2"   →  2 vCPU /   8 GB
              - "s4-g2"   →  4 vCPU /  16 GB
              - "s8-g2"   →  8 vCPU /  32 GB
              - "s16-g2"  → 16 vCPU /  64 GB
              - "s32-g2"  → 32 vCPU / 128 GB
        serverDescription: 서버 설명 (0~1000B)
        initScriptNo: 초기화 스크립트 번호
        accessControlGroupNoList: 기본 NIC에 적용할 ACG 번호 목록 (선택, list[str], 최대 3개).
            NCP는 createServerInstances에서 NIC당 ACG를 사실상 필수로 요구한다.
            미지정 시 vpcNo의 default ACG를 자동 조회(_get_default_acg_no)하여 채우므로,
            일반적인 경우 별도 지정 없이 호출해도 정상 동작한다.
            ACG 번호를 직접 확인하려면 list_access_control_groups(vpc_no=...)를 사용.
        networkInterfaceList: 고급 — 직접 NIC 리스트를 명시할 때만 사용 (선택).
            지정 시 accessControlGroupNoList·자동 fallback은 무시되고 이 값이 우선.
            list[dict] 형식. 각 dict 키:
              - networkInterfaceOrder (Required, 0~2, 0=기본 NIC)
              - subnetNo (신규 NIC 생성 또는 기존 NIC 부착 시 필수)
              - networkInterfaceNo (기존 NIC 부착 시 필수)
              - ip (선택, 미입력 시 자동 할당)
              - accessControlGroupNoList (신규 NIC 생성 시 필수, list[str], 최대 3개)
            예: [{"networkInterfaceOrder": 1, "subnetNo": "12345",
                  "accessControlGroupNoList": ["67890"]}]
        regionCode: 리전 코드 (KR · SGN · JPN · USWN)
    """
    params: dict = {
        "regionCode":             regionCode,
        "serverName":             serverName,
        "serverImageProductCode": resolve_image_code(serverImageProductCode),
        "vpcNo":                  vpcNo,
        "subnetNo":               subnetNo,
        "loginKeyName":           loginKeyName,
        "serverProductCode":      resolve_spec_code(serverProductCode),
        "serverDescription":      serverDescription,
        "initScriptNo":           initScriptNo,
    }
    # 기본 NIC 결정 우선순위:
    #   1) networkInterfaceList 직접 명시 → 그대로 사용
    #   2) accessControlGroupNoList 명시 → 기본 NIC(order 0)를 자동 구성
    #   3) 둘 다 미지정 → vpcNo의 default ACG를 조회해 기본 NIC를 자동 구성
    if not networkInterfaceList:
        acg_list = accessControlGroupNoList
        if not acg_list:
            default_acg = _get_default_acg_no(vpcNo, regionCode)
            if default_acg:
                acg_list = [default_acg]
        if acg_list:
            networkInterfaceList = [{
                "networkInterfaceOrder":    0,
                "subnetNo":                 subnetNo,
                "accessControlGroupNoList": list(acg_list),
            }]
    if networkInterfaceList:
        params.update(_flatten_nic_list(networkInterfaceList))
    path = _build_path("/vserver/v2/createServerInstances", params)
    return _get(path)


@mcp.tool()
def provision_server(server_name: str,
                     image: str = "rocky8.10",
                     spec: str = "s2-g2",
                     vpc_name: str = "",
                     vpc_cidr: str = "10.0.0.0/16",
                     subnet_name: str = "",
                     subnet_cidr: str = "10.0.1.0/24",
                     zone_code: str = "KR-2",
                     login_key_name: str = "",
                     region_code: str = "KR") -> dict:
    """VPC + Subnet + ACG SSH 규칙 + Login Key + Server를 한 번에 부트스트랩합니다.

    이름이 같은 VPC/Subnet/Login Key가 이미 있으면 재사용합니다(멱등). 공인 IP는
    포함하지 않음 — 서버가 RUN 상태가 되면 assign_public_ip를 별도로 호출하세요.

    Subnet 생성 시 NACL(Network ACL)은 별도로 지정하지 않으며, VPC의 default NACL이
    자동으로 적용됩니다.

    Args:
        server_name: 서버 이름 (3-30자) — 다른 자원 이름의 기본값으로도 사용
        image: 이미지 alias 또는 풀 코드 (rocky8.10 / rocky8.8 등)
        spec: 스펙 alias 또는 풀 코드 (s2-g2 등, 생략 시 최소 사양)
        vpc_name: VPC 이름 (기본: "{server_name}-vpc")
        vpc_cidr: 신규 VPC CIDR (재사용 시 무시)
        subnet_name: Subnet 이름 (기본: "{server_name}-subnet")
        subnet_cidr: 신규 Subnet CIDR (재사용 시 무시)
        zone_code: Subnet Zone (KR-1 · KR-2, 기본 KR-2)
        login_key_name: 로그인 키 이름 (기본: server_name).
            ~/Downloads/<name>.pem이 이미 있으면 재사용, 없으면 신규 발급해 저장
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    vpc_name       = vpc_name       or f"{server_name}-vpc"
    subnet_name    = subnet_name    or f"{server_name}-subnet"
    login_key_name = login_key_name or server_name
    out: dict = {}

    # 1) VPC
    existing = _find_vpc_by_name(vpc_name, region_code)
    if existing:
        vpc_no = str(existing.get("vpcNo"))
        out["vpc"] = {"reused": True, "no": vpc_no, "name": vpc_name}
    else:
        r = _get(_build_path("/vpc/v2/createVpc", {
            "regionCode":    region_code,
            "vpcName":       vpc_name,
            "ipv4CidrBlock": vpc_cidr,
        }))
        vlist = (r.get("createVpcResponse") or {}).get("vpcList") or []
        if not vlist:
            return {"error": "create_vpc 실패", "response": r, "completed": out}
        vpc_no = str(vlist[0].get("vpcNo"))
        if not _wait_for(lambda: _get_vpc_status(vpc_no, region_code), "RUN", timeout=90):
            return {"error": "VPC RUN 타임아웃", "vpcNo": vpc_no, "completed": out}
        out["vpc"] = {"reused": False, "no": vpc_no, "name": vpc_name, "cidr": vpc_cidr}

    # 2) Subnet
    existing = _find_subnet_by_name(vpc_no, subnet_name, region_code)
    if existing:
        subnet_no = str(existing.get("subnetNo"))
        out["subnet"] = {"reused": True, "no": subnet_no, "name": subnet_name}
    else:
        acl_no = _get_default_acl_no(vpc_no, region_code)
        if not acl_no:
            return {"error": "default Network ACL을 찾지 못했습니다", "vpcNo": vpc_no, "completed": out}
        r = _get(_build_path("/vpc/v2/createSubnet", {
            "regionCode":     region_code,
            "vpcNo":          vpc_no,
            "subnetName":     subnet_name,
            "subnet":         subnet_cidr,
            "zoneCode":       zone_code,
            "networkAclNo":   acl_no,
            "subnetTypeCode": "PUBLIC",
            "usageType":      "GEN",
        }))
        slist = (r.get("createSubnetResponse") or {}).get("subnetList") or []
        if not slist:
            return {"error": "create_subnet 실패", "response": r, "completed": out}
        subnet_no = str(slist[0].get("subnetNo"))
        if not _wait_for(lambda: _get_subnet_status(subnet_no, region_code), "RUN", timeout=90):
            return {"error": "Subnet RUN 타임아웃", "subnetNo": subnet_no, "completed": out}
        out["subnet"] = {"reused": False, "no": subnet_no, "name": subnet_name, "cidr": subnet_cidr}

    # 3) Default ACG 규칙 (중복 규칙은 NCP가 거부 — responseError 무시)
    #    inbound : myip → TCP 22(SSH) · TCP 3389(RDP), 0.0.0.0/0 → TCP 80(HTTP)
    #    outbound: 0.0.0.0/0 → TCP/UDP/ICMP 전체 (외부통신 제약 없음)
    acg_no = _get_default_acg_no(vpc_no, region_code)
    if acg_no:
        my_ip = _get_my_ip()
        my_cidr = f"{my_ip}/32" if my_ip else ""

        inbound_rules: list = []
        if my_cidr:
            inbound_rules.append({
                "protocolTypeCode": "TCP", "ipBlock": my_cidr, "portRange": "22",
                "accessControlGroupRuleDescription": "SSH from myip (provision_server)",
            })
            inbound_rules.append({
                "protocolTypeCode": "TCP", "ipBlock": my_cidr, "portRange": "3389",
                "accessControlGroupRuleDescription": "RDP from myip (provision_server)",
            })
        inbound_rules.append({
            "protocolTypeCode": "TCP", "ipBlock": "0.0.0.0/0", "portRange": "80",
            "accessControlGroupRuleDescription": "HTTP open (provision_server)",
        })
        in_res = _get(_build_acg_rule_path(
            "/vserver/v2/addAccessControlGroupInboundRule",
            acg_no, inbound_rules, region_code,
        ))

        outbound_rules = [
            {"protocolTypeCode": "TCP", "ipBlock": "0.0.0.0/0", "portRange": "1-65535",
             "accessControlGroupRuleDescription": "Allow all outbound TCP (provision_server)"},
            {"protocolTypeCode": "UDP", "ipBlock": "0.0.0.0/0", "portRange": "1-65535",
             "accessControlGroupRuleDescription": "Allow all outbound UDP (provision_server)"},
            {"protocolTypeCode": "ICMP", "ipBlock": "0.0.0.0/0",
             "accessControlGroupRuleDescription": "Allow all outbound ICMP (provision_server)"},
        ]
        out_res = _get(_build_acg_rule_path(
            "/vserver/v2/addAccessControlGroupOutboundRule",
            acg_no, outbound_rules, region_code,
        ))

        out["acgRules"] = {
            "acgNo":    acg_no,
            "myIp":     my_cidr or "unresolved",
            "inbound":  "added" if "responseError" not in in_res else "exists_or_failed",
            "outbound": "added" if "responseError" not in out_res else "exists_or_failed",
        }
    else:
        out["acgRules"] = {"acgNo": None, "skipped": True}

    # 4) Login Key — 로컬 pem 있으면 재사용, 없으면 신규 발급.
    # 저장 위치는 ~/Downloads/. Finder에서 즉시 보이도록 한 것이며 SSH 사용 시
    # ~/.ssh/로 이동하거나 SSH config의 IdentityFile을 이 경로로 맞춘다.
    pem_path = os.path.expanduser(f"~/Downloads/{login_key_name}.pem")
    if os.path.exists(pem_path):
        out["loginKey"] = {"reused": True, "name": login_key_name, "savedTo": pem_path}
    else:
        kres = _get(_build_path("/vserver/v2/createLoginKey", {
            "regionCode": region_code, "keyName": login_key_name,
        }))
        pk = (kres.get("createLoginKeyResponse") or {}).get("privateKey")
        if not pk:
            return {"error": "create_login_key 실패", "response": kres, "completed": out}
        os.makedirs(os.path.dirname(pem_path), exist_ok=True)
        with open(pem_path, "w") as f:
            f.write(pk)
        os.chmod(pem_path, 0o600)
        out["loginKey"] = {"reused": False, "name": login_key_name, "savedTo": pem_path}

    # 5) Server 생성 (RUN 대기 없이 즉시 반환)
    params: dict = {
        "regionCode":             region_code,
        "serverName":             server_name,
        "serverImageProductCode": resolve_image_code(image),
        "vpcNo":                  vpc_no,
        "subnetNo":               subnet_no,
        "loginKeyName":           login_key_name,
        "serverProductCode":      resolve_spec_code(spec),
    }
    if acg_no:
        params.update(_flatten_nic_list([{
            "networkInterfaceOrder":    0,
            "subnetNo":                 subnet_no,
            "accessControlGroupNoList": [acg_no],
        }]))
    sres = _get(_build_path("/vserver/v2/createServerInstances", params))
    sinst = (sres.get("createServerInstancesResponse") or {}).get("serverInstanceList") or []
    if not sinst:
        return {"error": "create_server 실패", "response": sres, "completed": out}
    server_no = str(sinst[0].get("serverInstanceNo"))
    out["server"] = {"no":     server_no,
                     "name":   server_name,
                     "status": _code(sinst[0].get("serverInstanceStatus"))}

    out["result"] = "ok"
    out["next"]   = "서버가 RUN 상태가 되면 assign_public_ip(server_no)로 공인 IP 할당"
    return out


@mcp.tool()
def assign_public_ip(serverInstanceNo: str,
                     publicIpDescription: str = "",
                     regionCode: str = "KR") -> dict:
    """서버 인스턴스에 공인 IP를 생성·할당합니다.

    참고: https://api.ncloud-docs.com/docs/networking-vpublicip-createpublicipinstance

    Args:
        serverInstanceNo: 공인 IP를 부여할 서버 인스턴스 번호 (RUN/NSTOP 상태, 미할당 상태여야 함)
        publicIpDescription: 공인 IP 설명 (0~1000B, 선택)
        regionCode: 리전 코드 (KR · SGN · JPN · USWN)
    """
    path = _build_path("/vserver/v2/createPublicIpInstance", {
        "regionCode":          regionCode,
        "serverInstanceNo":    serverInstanceNo,
        "publicIpDescription": publicIpDescription,
    })
    return _get(path)


# ─────────────────────────────────────────────────────────────────────────────
# Network 조회·규칙 관리 — ACG/NACL 규칙, 라우트 테이블, NAT Gateway, 서버 NIC.
# ─────────────────────────────────────────────────────────────────────────────

def _flat(v):
    """{code, codeName} enum은 code만 남기고, 빈 값은 버린 사본을 반환."""
    if isinstance(v, dict):
        if set(v) <= {"code", "codeName"} and "code" in v:
            return v["code"]
        return {k: _flat(x) for k, x in v.items() if x not in (None, "", [])}
    if isinstance(v, list):
        return [_flat(x) for x in v]
    return v


def _list_raw(res: dict, response_key: str, list_key: str) -> dict:
    """_slim_list와 같은 봉투 처리, 항목은 _flat만 적용."""
    return _slim_list(res, response_key, list_key, _flat)


@mcp.tool()
def get_server_network(server_instance_no: str,
                       region_code: str = "KR") -> dict:
    """서버의 NIC 목록(사설 IP, 서브넷, 적용된 ACG 번호)을 조회합니다."""
    res = _get(_build_path("/vserver/v2/getServerInstanceList", {
        "regionCode": region_code,
        "serverInstanceNoList.1": server_instance_no,
    }))
    if "error" in res:
        return res
    servers = (res.get("getServerInstanceListResponse") or {}).get("serverInstanceList") or []
    if not servers:
        return {"error": f"server {server_instance_no} not found"}
    nic_nos = servers[0].get("networkInterfaceNoList") or []
    params: dict = {"regionCode": region_code}
    for i, no in enumerate(nic_nos, start=1):
        params[f"networkInterfaceNoList.{i}"] = no
    res = _get(_build_path("/vserver/v2/getNetworkInterfaceList", params))
    return _list_raw(res, "getNetworkInterfaceListResponse", "networkInterfaceList")


@mcp.tool()
def list_acg_rules(access_control_group_no: str,
                   rule_type: str = "",
                   region_code: str = "KR") -> dict:
    """ACG 규칙 목록을 조회합니다.

    Args:
        access_control_group_no: ACG 번호 — 필수
        rule_type: "INBND" · "OTBND" (생략 시 전체)
        region_code: 리전 코드
    """
    res = _get(_build_path("/vserver/v2/getAccessControlGroupRuleList", {
        "regionCode":                     region_code,
        "accessControlGroupNo":           access_control_group_no,
        "accessControlGroupRuleTypeCode": rule_type,
    }))
    return _list_raw(res, "getAccessControlGroupRuleListResponse",
                     "accessControlGroupRuleList")


def _remove_acg_rule(endpoint: str, vpc_no: str, access_control_group_no: str,
                     rules: list, region_code: str) -> dict:
    params: dict = {
        "regionCode":           region_code,
        "vpcNo":                vpc_no,
        "accessControlGroupNo": access_control_group_no,
    }
    params.update(_flatten_dict_list("accessControlGroupRuleList", rules))
    return _get(_build_path(endpoint, params))


@mcp.tool()
def remove_acg_inbound_rule(vpc_no: str,
                            access_control_group_no: str,
                            rules: list,
                            region_code: str = "KR") -> dict:
    """ACG inbound 규칙을 삭제합니다.

    rules 각 항목은 list_acg_rules로 본 규칙과 정확히 일치해야 한다:
    protocolTypeCode, ipBlock 또는 accessControlGroupSequence, portRange(TCP/UDP).
    """
    return _remove_acg_rule("/vserver/v2/removeAccessControlGroupInboundRule",
                            vpc_no, access_control_group_no, rules, region_code)


@mcp.tool()
def remove_acg_outbound_rule(vpc_no: str,
                             access_control_group_no: str,
                             rules: list,
                             region_code: str = "KR") -> dict:
    """ACG outbound 규칙을 삭제합니다. (rules 형식은 remove_acg_inbound_rule과 동일)"""
    return _remove_acg_rule("/vserver/v2/removeAccessControlGroupOutboundRule",
                            vpc_no, access_control_group_no, rules, region_code)


@mcp.tool()
def list_network_acl_rules(network_acl_no: str,
                           rule_type: str = "",
                           region_code: str = "KR") -> dict:
    """Network ACL 규칙 목록을 조회합니다.

    Args:
        network_acl_no: NACL 번호 — 필수
        rule_type: "INBND" · "OTBND" (생략 시 전체)
        region_code: 리전 코드
    """
    params: dict = {"regionCode": region_code, "networkAclNo": network_acl_no}
    if rule_type:
        params["networkAclRuleTypeCodeList.1"] = rule_type
    res = _get(_build_path("/vpc/v2/getNetworkAclRuleList", params))
    return _list_raw(res, "getNetworkAclRuleListResponse", "networkAclRuleList")


def _nacl_rule(endpoint: str, network_acl_no: str, rules: list,
               region_code: str) -> dict:
    params: dict = {"regionCode": region_code, "networkAclNo": network_acl_no}
    params.update(_flatten_dict_list("networkAclRuleList", rules))
    return _get(_build_path(endpoint, params))


_NACL_RULE_DOC = """
    rules: list[dict]. 각 dict 키:
        - priority (필수): 0~199, 낮을수록 먼저 평가
        - protocolTypeCode (필수): "TCP" · "UDP" · "ICMP"
        - ipBlock (필수): IPv4 CIDR
        - ruleActionCode (필수): "ALLOW" · "DROP"
        - portRange (TCP/UDP 필수): "443", "1-65535"
        - networkAclRuleDescription (선택)
"""
_NACL_REMOVE_NOTE = "규칙은 list_network_acl_rules 결과와 정확히 일치해야 한다.\n"


@mcp.tool(description="NACL inbound 규칙을 추가합니다.\n" + _NACL_RULE_DOC)
def add_network_acl_inbound_rule(network_acl_no: str, rules: list,
                                 region_code: str = "KR") -> dict:
    return _nacl_rule("/vpc/v2/addNetworkAclInboundRule",
                      network_acl_no, rules, region_code)


@mcp.tool(description="NACL outbound 규칙을 추가합니다.\n" + _NACL_RULE_DOC)
def add_network_acl_outbound_rule(network_acl_no: str, rules: list,
                                  region_code: str = "KR") -> dict:
    return _nacl_rule("/vpc/v2/addNetworkAclOutboundRule",
                      network_acl_no, rules, region_code)


@mcp.tool(description="NACL inbound 규칙을 삭제합니다. " + _NACL_REMOVE_NOTE + _NACL_RULE_DOC)
def remove_network_acl_inbound_rule(network_acl_no: str, rules: list,
                                    region_code: str = "KR") -> dict:
    return _nacl_rule("/vpc/v2/removeNetworkAclInboundRule",
                      network_acl_no, rules, region_code)


@mcp.tool(description="NACL outbound 규칙을 삭제합니다. " + _NACL_REMOVE_NOTE + _NACL_RULE_DOC)
def remove_network_acl_outbound_rule(network_acl_no: str, rules: list,
                                     region_code: str = "KR") -> dict:
    return _nacl_rule("/vpc/v2/removeNetworkAclOutboundRule",
                      network_acl_no, rules, region_code)


@mcp.tool()
def list_route_tables(vpc_no: str = "", region_code: str = "KR") -> dict:
    """라우트 테이블 목록을 조회합니다."""
    res = _get(_build_path("/vpc/v2/getRouteTableList", {
        "regionCode": region_code, "vpcNo": vpc_no,
    }))
    return _list_raw(res, "getRouteTableListResponse", "routeTableList")


@mcp.tool()
def list_routes(vpc_no: str, route_table_no: str,
                region_code: str = "KR") -> dict:
    """라우트 테이블의 라우트(목적지 CIDR → 대상) 목록을 조회합니다."""
    res = _get(_build_path("/vpc/v2/getRouteList", {
        "regionCode": region_code, "vpcNo": vpc_no, "routeTableNo": route_table_no,
    }))
    return _list_raw(res, "getRouteListResponse", "routeList")


@mcp.tool()
def list_route_table_subnets(vpc_no: str, route_table_no: str,
                             region_code: str = "KR") -> dict:
    """라우트 테이블에 연결된 서브넷 목록을 조회합니다."""
    res = _get(_build_path("/vpc/v2/getRouteTableSubnetList", {
        "regionCode": region_code, "vpcNo": vpc_no, "routeTableNo": route_table_no,
    }))
    return _list_raw(res, "getRouteTableSubnetListResponse", "subnetList")


@mcp.tool()
def list_network_interfaces(subnet_no: str = "",
                            vpc_no: str = "",
                            region_code: str = "KR") -> dict:
    """NIC 목록을 조회합니다. 일반 서버 외에 관리형 서비스(Cloud DB 등)가 만든 NIC도 포함.

    subnet_no / vpc_no 필터는 전체 목록을 받아 클라이언트에서 적용한다.
    항목의 instanceType · instanceNo로 어떤 리소스의 NIC인지 구분한다.
    """
    items: list = []
    page = 1
    while True:
        res = _get(_build_path("/vserver/v2/getNetworkInterfaceList", {
            "regionCode": region_code, "pageNo": page, "pageSize": 1000,
        }))
        if "error" in res:
            return res
        inner = res.get("getNetworkInterfaceListResponse") or {}
        batch = inner.get("networkInterfaceList") or []
        items.extend(batch)
        if not batch or len(items) >= int(inner.get("totalRows") or 0):
            break
        page += 1
    if subnet_no:
        items = [x for x in items if str(x.get("subnetNo")) == str(subnet_no)]
    if vpc_no:
        subnets = _get(_build_path("/vpc/v2/getSubnetList", {
            "regionCode": region_code, "vpcNo": vpc_no,
        }))
        nos = {str(s.get("subnetNo")) for s in
               (subnets.get("getSubnetListResponse") or {}).get("subnetList") or []}
        items = [x for x in items if str(x.get("subnetNo")) in nos]
    return {"count": len(items), "items": [_flat(x) for x in items]}


# db_type → (API 경로 prefix, 응답 키 접두어)
_CLOUD_DB = {
    "mysql":      ("/vmysql/v2/getCloudMysqlInstanceList",           "Mysql"),
    "redis":      ("/vredis/v2/getCloudRedisInstanceList",           "Redis"),
    "mongodb":    ("/vmongodb/v2/getCloudMongoDbInstanceList",       "MongoDb"),
    "postgresql": ("/vpostgresql/v2/getCloudPostgresqlInstanceList", "Postgresql"),
    "mssql":      ("/vmssql/v2/getCloudMssqlInstanceList",           "Mssql"),
}


@mcp.tool()
def list_cloud_db_instances(db_type: str = "",
                            vpc_no: str = "",
                            region_code: str = "KR") -> dict:
    """Cloud DB 인스턴스 목록을 조회합니다 (노드별 서브넷·사설 IP 포함).

    Args:
        db_type: "mysql" · "redis" · "mongodb" · "postgresql" · "mssql" (생략 시 전부)
        vpc_no: 특정 VPC만 (선택)
        region_code: 리전 코드
    결과는 db_type별로 묶인다. 상품 미사용·권한 없음 등 실패한 타입은 error로 표시된다.
    """
    types = [db_type] if db_type else list(_CLOUD_DB)
    out: dict = {}
    for t in types:
        if t not in _CLOUD_DB:
            out[t] = {"error": f"unknown db_type: {t}"}
            continue
        endpoint, key = _CLOUD_DB[t]
        res = _get(_build_path(endpoint, {"regionCode": region_code, "vpcNo": vpc_no}))
        out[t] = _list_raw(res, f"getCloud{key}InstanceListResponse",
                           f"cloud{key}InstanceList")
    return out


@mcp.tool()
def list_nat_gateways(vpc_no: str = "", region_code: str = "KR") -> dict:
    """NAT Gateway 목록을 조회합니다."""
    res = _get(_build_path("/vpc/v2/getNatGatewayInstanceList", {
        "regionCode": region_code, "vpcNo": vpc_no,
    }))
    return _list_raw(res, "getNatGatewayInstanceListResponse", "natGatewayInstanceList")


# ─────────────────────────────────────────────────────────────────────────────
# Load Balancer 조회 — LB → 리스너 → 규칙 → 타깃 그룹 → 타깃 순으로 따라간다.
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_load_balancers(vpc_no: str = "",
                        load_balancer_type_code: str = "",
                        load_balancer_network_type_code: str = "",
                        load_balancer_instance_no_list: Optional[list] = None,
                        region_code: str = "KR") -> dict:
    """Load Balancer 인스턴스 목록을 조회합니다 (도메인, IP, 서브넷, 리스너 번호 포함).

    Args:
        vpc_no: 특정 VPC만 (선택)
        load_balancer_type_code: "APPLICATION" · "NETWORK" · "NETWORK_PROXY" (선택)
        load_balancer_network_type_code: "PUBLIC" · "PRIVATE" (선택)
        load_balancer_instance_no_list: 특정 LB 번호 필터 (선택, list[str])
        region_code: 리전 코드
    """
    params: dict = {
        "regionCode": region_code, "vpcNo": vpc_no,
        "loadBalancerTypeCode": load_balancer_type_code,
        "loadBalancerNetworkTypeCode": load_balancer_network_type_code,
    }
    for i, no in enumerate(load_balancer_instance_no_list or [], start=1):
        params[f"loadBalancerInstanceNoList.{i}"] = no
    res = _get(_build_path("/vloadbalancer/v2/getLoadBalancerInstanceList", params))
    return _list_raw(res, "getLoadBalancerInstanceListResponse", "loadBalancerInstanceList")


@mcp.tool()
def list_load_balancer_listeners(load_balancer_instance_no: str,
                                 region_code: str = "KR") -> dict:
    """LB의 리스너 목록(프로토콜, 포트, 인증서, 규칙 번호)을 조회합니다."""
    res = _get(_build_path("/vloadbalancer/v2/getLoadBalancerListenerList", {
        "regionCode": region_code, "loadBalancerInstanceNo": load_balancer_instance_no,
    }))
    return _list_raw(res, "getLoadBalancerListenerListResponse", "loadBalancerListenerList")


@mcp.tool()
def list_load_balancer_rules(load_balancer_listener_no: str,
                             region_code: str = "KR") -> dict:
    """리스너의 규칙 목록(조건 → 타깃 그룹)을 조회합니다. 타깃 그룹 번호는 여기서 얻는다."""
    res = _get(_build_path("/vloadbalancer/v2/getLoadBalancerRuleList", {
        "regionCode": region_code, "loadBalancerListenerNo": load_balancer_listener_no,
    }))
    return _list_raw(res, "getLoadBalancerRuleListResponse", "loadBalancerRuleList")


@mcp.tool()
def list_target_groups(vpc_no: str = "",
                       target_group_no_list: Optional[list] = None,
                       region_code: str = "KR") -> dict:
    """타깃 그룹 목록(프로토콜, 포트, 헬스체크, 연결된 LB, 타깃 번호)을 조회합니다.

    Args:
        vpc_no: 특정 VPC만 (선택)
        target_group_no_list: 특정 타깃 그룹 번호 필터 (선택, list[str])
        region_code: 리전 코드
    """
    params: dict = {"regionCode": region_code, "vpcNo": vpc_no}
    for i, no in enumerate(target_group_no_list or [], start=1):
        params[f"targetGroupNoList.{i}"] = no
    res = _get(_build_path("/vloadbalancer/v2/getTargetGroupList", params))
    return _list_raw(res, "getTargetGroupListResponse", "targetGroupList")


@mcp.tool()
def list_targets(target_group_no: str, region_code: str = "KR") -> dict:
    """타깃 그룹에 등록된 타깃(이름, IP, 헬스체크 상태)을 조회합니다."""
    res = _get(_build_path("/vloadbalancer/v2/getTargetList", {
        "regionCode": region_code, "targetGroupNo": target_group_no,
    }))
    return _list_raw(res, "getTargetListResponse", "targetList")


@mcp.tool()
def create_target_group(vpc_no: str,
                        target_group_protocol_type_code: str,
                        health_check_protocol_type_code: str,
                        target_group_name: str = "",
                        target_group_port: Optional[int] = None,
                        target_group_description: str = "",
                        health_check_port: Optional[int] = None,
                        health_check_url_path: str = "",
                        health_check_http_method_type_code: str = "",
                        target_no_list: Optional[list] = None,
                        region_code: str = "KR") -> dict:
    """타깃 그룹을 생성합니다 (타깃 유형 VSVR).

    Args:
        vpc_no: VPC 번호 — 필수
        target_group_protocol_type_code: "HTTP" · "HTTPS" (ALB) · "TCP" · "UDP" (NLB) · "PROXY_TCP" — 필수
        health_check_protocol_type_code: HTTP/HTTPS 그룹은 "HTTP" · "HTTPS", 그 외는 "TCP" — 필수
        target_group_name: 3-30자, 영문자로 시작 (생략 시 자동 부여)
        target_group_port: 타깃 포트 (기본 80)
        health_check_port: 헬스체크 포트 (기본 80). 타깃 포트와 달라도 된다.
        health_check_url_path: "/"로 시작 (HTTP/HTTPS 헬스체크만)
        health_check_http_method_type_code: "HEAD" · "GET" (HTTP/HTTPS 헬스체크면 필수)
        target_no_list: 생성과 동시에 등록할 서버 인스턴스 번호 (선택, list[str])
        region_code: 리전 코드
    """
    params: dict = {
        "regionCode": region_code, "vpcNo": vpc_no, "targetTypeCode": "VSVR",
        "targetGroupName": target_group_name,
        "targetGroupProtocolTypeCode": target_group_protocol_type_code,
        "targetGroupPort": target_group_port,
        "targetGroupDescription": target_group_description,
        "healthCheckProtocolTypeCode": health_check_protocol_type_code,
        "healthCheckPort": health_check_port,
        "healthCheckUrlPath": health_check_url_path,
        "healthCheckHttpMethodTypeCode": health_check_http_method_type_code,
    }
    for i, no in enumerate(target_no_list or [], start=1):
        params[f"targetNoList.{i}"] = no
    res = _get(_build_path("/vloadbalancer/v2/createTargetGroup", params))
    return _list_raw(res, "createTargetGroupResponse", "targetGroupList")


@mcp.tool()
def add_targets(target_group_no: str, target_no_list: list,
                region_code: str = "KR") -> dict:
    """타깃 그룹에 서버(타깃)를 등록합니다. target_no_list: 서버 인스턴스 번호 list[str]."""
    params: dict = {"regionCode": region_code, "targetGroupNo": target_group_no}
    for i, no in enumerate(target_no_list, start=1):
        params[f"targetNoList.{i}"] = no
    res = _get(_build_path("/vloadbalancer/v2/addTarget", params))
    return _list_raw(res, "addTargetResponse", "targetList")


@mcp.tool()
def create_load_balancer_listener(load_balancer_instance_no: str,
                                  protocol_type_code: str,
                                  port: int,
                                  target_group_no: str,
                                  ssl_certificate_no: str = "",
                                  tls_min_version_type_code: str = "",
                                  use_http2: Optional[bool] = None,
                                  region_code: str = "KR") -> dict:
    """LB에 리스너를 추가합니다. target_group_no가 리스너의 기본 규칙이 된다.

    Args:
        load_balancer_instance_no: LB 번호 — 필수
        protocol_type_code: ALB "HTTP" · "HTTPS", NLB "TCP" · "UDP", 프록시 LB "TCP" · "TLS" — 필수
        port: 리스너 포트 (기존 리스너와 중복 불가) — 필수
        target_group_no: 다른 LB에서 쓰지 않는 타깃 그룹 — 필수
        ssl_certificate_no: HTTPS · TLS면 필수 (기존 리스너의 sslCertificateNo 재사용 가능)
        tls_min_version_type_code: "TLSV10" (기본) · "TLSV11" · "TLSV12"
        use_http2: HTTPS 리스너만
        region_code: 리전 코드
    """
    res = _get(_build_path("/vloadbalancer/v2/createLoadBalancerListener", {
        "regionCode": region_code,
        "loadBalancerInstanceNo": load_balancer_instance_no,
        "protocolTypeCode": protocol_type_code,
        "port": port,
        "targetGroupNo": target_group_no,
        "sslCertificateNo": ssl_certificate_no,
        "tlsMinVersionTypeCode": tls_min_version_type_code,
        "useHttp2": None if use_http2 is None else str(use_http2).lower(),
    }))
    return _list_raw(res, "createLoadBalancerListenerResponse", "loadBalancerListenerList")


@mcp.tool()
def delete_load_balancer_listener(load_balancer_listener_no: str,
                                  region_code: str = "KR") -> dict:
    """LB 리스너를 삭제합니다 (되돌릴 수 없음)."""
    return _get(_build_path("/vloadbalancer/v2/deleteLoadBalancerListeners", {
        "regionCode": region_code,
        "loadBalancerListenerNoList.1": load_balancer_listener_no,
    }))


@mcp.tool()
def delete_target_group(target_group_no: str, region_code: str = "KR") -> dict:
    """타깃 그룹을 삭제합니다 (LB에서 쓰는 중이면 실패, 되돌릴 수 없음)."""
    return _get(_build_path("/vloadbalancer/v2/deleteTargetGroups", {
        "regionCode": region_code, "targetGroupNoList.1": target_group_no,
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Object Storage (S3 호환 API, boto3 사용)
# ─────────────────────────────────────────────────────────────────────────────
# NCP Object Storage는 region별 S3 호환 엔드포인트를 제공한다.
# 의존성: boto3 (미설치 시 `pip3 install boto3`).

OBJECT_STORAGE_ENDPOINTS = {
    "KR":   "https://kr.object.ncloudstorage.com",
    "SGN":  "https://sg.object.ncloudstorage.com",
    "JPN":  "https://jp.object.ncloudstorage.com",
    "USWN": "https://us.object.ncloudstorage.com",
}

def _s3_client(region_code: str = "KR"):
    """NCP Object Storage용 boto3 S3 클라이언트를 생성한다.

    boto3가 없으면 명확한 안내 메시지와 함께 RuntimeError를 던진다.
    """
    try:
        import boto3
    except ImportError as e:
        raise RuntimeError(
            "boto3가 설치되어 있지 않습니다. "
            "`pip3 install boto3` 실행 후 Claude Desktop을 재시작하세요."
        ) from e
    endpoint = OBJECT_STORAGE_ENDPOINTS.get(region_code, OBJECT_STORAGE_ENDPOINTS["KR"])
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        region_name=f"{region_code.lower()}-standard",
    )


@mcp.tool()
def list_buckets(region_code: str = "KR") -> dict:
    """Object Storage 버킷 목록을 조회합니다.

    Args:
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    try:
        r = _s3_client(region_code).list_buckets()
        return {
            "owner": r.get("Owner", {}).get("DisplayName", "-"),
            "count": len(r.get("Buckets", [])),
            "buckets": [{"name": b["Name"],
                         "created": b["CreationDate"].isoformat()}
                        for b in r.get("Buckets", [])],
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def list_objects(bucket_name: str,
                 prefix: str = "",
                 max_keys: int = 1000,
                 continuation_token: str = "",
                 region_code: str = "KR") -> dict:
    """특정 버킷의 객체 목록을 조회합니다.

    Args:
        bucket_name: 버킷 이름 (필수)
        prefix: 객체 키 접두사 필터 (예: "logs/2026/")
        max_keys: 최대 반환 개수 (1~1000, 기본 1000)
        continuation_token: 다음 페이지 토큰 (이전 응답의 next_token)
        region_code: 리전 코드
    """
    try:
        kwargs = {"Bucket": bucket_name, "Prefix": prefix, "MaxKeys": max_keys}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        r = _s3_client(region_code).list_objects_v2(**kwargs)
        return {
            "bucket":     bucket_name,
            "prefix":     prefix,
            "count":      r.get("KeyCount", 0),
            "truncated":  r.get("IsTruncated", False),
            "next_token": r.get("NextContinuationToken", ""),
            "objects": [{"key":      o["Key"],
                         "size":     o["Size"],
                         "modified": o["LastModified"].isoformat(),
                         "etag":     o.get("ETag", "").strip('"')}
                        for o in r.get("Contents", [])],
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def get_object_url(bucket_name: str,
                   object_key: str,
                   expires_in: int = 3600,
                   method: str = "GET",
                   region_code: str = "KR") -> dict:
    """객체에 대한 프리사인드 URL을 생성합니다 (다운로드 또는 업로드용).

    Args:
        bucket_name: 버킷 이름
        object_key: 객체 키
        expires_in: 만료 시간(초), 기본 3600 (최대 604800 = 7일)
        method: 'GET'(다운로드 URL) 또는 'PUT'(업로드 URL)
        region_code: 리전 코드
    """
    try:
        client_method = "get_object" if method.upper() == "GET" else "put_object"
        url = _s3_client(region_code).generate_presigned_url(
            ClientMethod=client_method,
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires_in,
        )
        return {"url": url, "method": method.upper(),
                "bucket": bucket_name, "key": object_key,
                "expires_in": expires_in}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def put_object(bucket_name: str,
               object_key: str,
               file_path: str,
               content_type: str = "",
               region_code: str = "KR") -> dict:
    """로컬 파일을 버킷에 객체로 업로드합니다.

    Args:
        bucket_name: 대상 버킷
        object_key: 저장될 객체 키 (예: "logs/2026/data.json")
        file_path: 업로드할 로컬 파일 절대 경로
        content_type: MIME 타입 (선택, 미지정 시 boto3가 확장자로 추정)
        region_code: 리전 코드
    """
    try:
        extra: dict = {}
        if content_type:
            extra["ContentType"] = content_type
        _s3_client(region_code).upload_file(
            file_path, bucket_name, object_key, ExtraArgs=extra,
        )
        return {"result": "ok", "bucket": bucket_name,
                "key": object_key, "file": file_path}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def get_object(bucket_name: str,
               object_key: str,
               file_path: str,
               region_code: str = "KR") -> dict:
    """버킷의 객체를 로컬 파일로 다운로드합니다.

    Args:
        bucket_name: 버킷 이름
        object_key: 객체 키
        file_path: 저장할 로컬 절대 경로
        region_code: 리전 코드
    """
    try:
        _s3_client(region_code).download_file(bucket_name, object_key, file_path)
        return {"result": "ok", "bucket": bucket_name,
                "key": object_key, "file": file_path}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def delete_object(bucket_name: str,
                  object_key: str,
                  region_code: str = "KR") -> dict:
    """버킷의 객체를 삭제합니다.

    ⚠️ 되돌릴 수 없는 작업입니다.

    Args:
        bucket_name: 버킷 이름
        object_key: 삭제할 객체 키
        region_code: 리전 코드
    """
    try:
        _s3_client(region_code).delete_object(Bucket=bucket_name, Key=object_key)
        return {"result": "ok", "bucket": bucket_name, "key": object_key}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def create_bucket(bucket_name: str,
                  region_code: str = "KR") -> dict:
    """새 Object Storage 버킷을 생성합니다.

    Args:
        bucket_name: 버킷 이름 (DNS 호환, 3~63자, 영소문자/숫자/'-'/'.', 전역 유일)
        region_code: 리전 코드 (KR · SGN · JPN · USWN)
    """
    try:
        _s3_client(region_code).create_bucket(Bucket=bucket_name)
        return {"result": "ok", "bucket": bucket_name, "region": region_code}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def delete_bucket(bucket_name: str,
                  region_code: str = "KR") -> dict:
    """버킷을 삭제합니다.

    ⚠️ 되돌릴 수 없는 작업이며, 버킷에 객체가 남아 있으면 실패합니다.
    먼저 list_objects + delete_object로 비운 뒤 호출하세요.

    Args:
        bucket_name: 삭제할 버킷 이름
        region_code: 리전 코드
    """
    try:
        _s3_client(region_code).delete_bucket(Bucket=bucket_name)
        return {"result": "ok", "bucket": bucket_name}
    except Exception as e:
        return {"error": str(e)}


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

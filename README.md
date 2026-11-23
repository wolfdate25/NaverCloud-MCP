# ncp-mcp

[NAVER Cloud Platform(NCP)](https://www.ncloud.com) 리소스를 Claude 같은 MCP 클라이언트에서 다룰 수 있게 해 주는 [MCP](https://modelcontextprotocol.io) 서버입니다. stdio 방식으로 동작하며, NCP Open API(VPC 서버·네트워크·로드밸런서)와 Object Storage(S3 호환)를 **52개 도구**로 제공합니다.

> ⚠️ `create_*`, `delete_*`, `provision_server` 같은 도구는 **실제 리소스를 만들고 지우며 비용이 발생**할 수 있습니다. 일부 삭제는 되돌릴 수 없습니다. 운영 계정에 연결하기 전에 권한을 최소화한 인증키를 쓰세요.

## 제공 도구

| 영역 | 도구 |
|---|---|
| 서버 | `list_servers`, `get_server_detail`, `create_server`, `provision_server`, `assign_public_ip`, `get_server_network` |
| VPC / Subnet | `list_vpcs`, `create_vpc`, `delete_vpc`, `list_subnets`, `create_subnet`, `delete_subnet` |
| ACG (방화벽) | `list_access_control_groups`, `create_access_control_group`, `list_acg_rules`, `add_acg_inbound_rule`, `add_acg_outbound_rule`, `remove_acg_inbound_rule`, `remove_acg_outbound_rule` |
| Network ACL | `list_network_acls`, `create_network_acl`, `delete_network_acl`, `list_network_acl_rules`, `add_network_acl_{inbound,outbound}_rule`, `remove_network_acl_{inbound,outbound}_rule` |
| 라우팅 / 네트워크 | `list_route_tables`, `list_routes`, `list_route_table_subnets`, `list_network_interfaces`, `list_nat_gateways` |
| 로그인 키 | `create_login_key` |
| Load Balancer | `list_load_balancers`, `list_load_balancer_listeners`, `list_load_balancer_rules`, `create_load_balancer_listener`, `delete_load_balancer_listener`, `list_target_groups`, `create_target_group`, `delete_target_group`, `list_targets`, `add_targets` |
| Cloud DB | `list_cloud_db_instances` |
| Object Storage | `list_buckets`, `create_bucket`, `delete_bucket`, `list_objects`, `put_object`, `get_object`, `delete_object`, `get_object_url` |

대부분의 도구는 `region_code`(기본 `KR`, 그 외 `SGN` · `JPN` · `USWN`)를 받습니다. 각 도구의 인자와 설명은 MCP 클라이언트에서 도구 목록을 보거나 `ncp_server.py`의 docstring을 참고하세요.

### `provision_server`

VPC + Subnet + ACG SSH 규칙 + 로그인 키 + 서버를 한 번에 만듭니다. 같은 이름의 VPC·Subnet·로그인 키가 이미 있으면 재사용합니다. 공인 IP는 포함되지 않으므로 서버가 `RUN` 상태가 된 뒤 `assign_public_ip`를 따로 호출하세요.

- 이미지 alias: `rocky8.10`(기본), `rocky8.8` (alias 대신 풀 상품 코드도 가능)
- 스펙 alias: `s2-g2`(기본, 2 vCPU/8 GB) · `s4-g2` · `s8-g2` · `s16-g2` · `s32-g2`
- 로그인 키(pem)는 `~/Downloads/<이름>.pem`에 저장됩니다. SSH에 쓰려면 `~/.ssh/`로 옮기고 `chmod 600` 하세요.

## 요구 사항

- Python 3.10 이상
- [uv](https://docs.astral.sh/uv/) (권장)
- NCP 계정과 API 인증키(Access Key / Secret Key)

## 설치

```bash
git clone https://github.com/wolfdate25/NaverCloud-MCP.git
cd NaverCloud-MCP
uv sync
```

uv 없이 쓰려면 `python -m venv .venv && .venv/bin/pip install -r requirements.txt` 로 설치해도 됩니다.

## 인증키 설정

1. NCP 콘솔 → 마이페이지 → 계정 관리 → [인증키 관리](https://www.ncloud.com/mypage/manage/authkey)에서 키를 발급합니다.
2. 서버는 아래 **환경변수**에서 키를 읽습니다. 두 값이 없으면 시작 시 `KeyError`로 종료됩니다.

| 환경변수 | 필수 | 설명 |
|---|---|---|
| `NCP_ACCESS_KEY` | ✅ | NCP Access Key |
| `NCP_SECRET_KEY` | ✅ | NCP Secret Key |
| `NCP_CA_BUNDLE` | | TLS 검증에 쓸 CA 번들 경로 (기본 `/etc/ssl/certs/ca-certificates.crt`). 사내 TLS 검사 환경에서 필요할 수 있습니다. |

> `.env` 파일은 **자동으로 읽지 않습니다**. `.env.example`은 어떤 값이 필요한지 보여 주는 견본이며, 아래 MCP 클라이언트 설정의 `env`나 셸 환경변수로 전달하세요.
> 인증키는 코드·`.env`·MCP 설정 파일을 **git에 커밋하지 마세요**. `.gitignore`에 `.env`, `*.pem`, `*.key`가 포함되어 있습니다.

## MCP 클라이언트에 등록

### Claude Code

```bash
claude mcp add ncp \
  -e NCP_ACCESS_KEY=<your_access_key> \
  -e NCP_SECRET_KEY=<your_secret_key> \
  -- uv run --directory /path/to/NaverCloud-MCP ncp-mcp
```

### JSON 설정 (Claude Desktop 등)

```json
{
  "mcpServers": {
    "ncp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/NaverCloud-MCP", "ncp-mcp"],
      "env": {
        "NCP_ACCESS_KEY": "<your_access_key>",
        "NCP_SECRET_KEY": "<your_secret_key>"
      }
    }
  }
}
```

`/path/to/NaverCloud-MCP`는 클론한 절대 경로로 바꾸세요. 직접 실행해 보려면 키를 환경변수로 넣고 `uv run ncp-mcp`(또는 `uv run python ncp_server.py`)를 실행합니다. stdio 서버라 입력을 기다리며 멈춰 있는 것이 정상입니다.

## 개발

```bash
uv sync
NCP_ACCESS_KEY=dummy NCP_SECRET_KEY=dummy uv run python -c "import ncp_server; print('ok')"
```

- 모든 도구는 `ncp_server.py` 한 파일에 `@mcp.tool()`로 정의되어 있습니다.
- 요청은 `x-ncp-apigw-signature-v2`(HMAC-SHA256) 헤더로 서명해 `https://ncloud.apigw.ntruss.com`에 보냅니다. Object Storage는 boto3(S3 호환)를 사용합니다.

## 라이선스

[MIT](LICENSE)

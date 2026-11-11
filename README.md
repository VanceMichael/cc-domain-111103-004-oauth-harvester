# 多组织授权接口的令牌轮换采集

只读采集项目，面向多个合作组织的授权接口。核心目标：把**多组织授权维护**与
**数据拉取**拆清楚——采集 worker 不持有任何刷新逻辑，所有令牌轮换由统一协调器
按组织单飞处理，避免并发刷新互相覆盖、一个组织的授权问题拖停全部任务。

## 架构与模块

| 模块 | 职责 |
| --- | --- |
| `app/secrets.py` | `Secret` 包装敏感值；`str/repr` 只显示不可逆指纹；`RedactingFilter` 对日志做秘密脱敏 |
| `app/oauth.py` | 读取本地虚构授权材料；`GrantRecord` 中的令牌以 `Secret` 承载 |
| `app/auth.py` | 授权状态机（`active` / `refresh_pending` / `reauth_required` / `revoked`）与不含秘密的异常类型 |
| `app/storage.py` | `AuthStore`：按组织隔离的授权状态，临时文件 + 原子替换、权限 0600；`HarvestStore`：逐组织 SQLite 页面台账与记录去重 |
| `app/token_service.py` | 本地令牌服务/数据接口替身：轮换使旧 refresh token 失效、attempt 幂等重放、故障注入、逐组织撤权 |
| `app/coordinator.py` | `RefreshCoordinator`：单飞刷新、fence 代次租约、崩溃恢复、暂停/恢复/撤权/重新授权、操作者状态视图 |
| `app/harvester.py` | `HarvestWorker` 与 `Supervisor`：取租约 → 请求 → 401 交协调器 → fence 校验 → 幂等落库；逐组织线程隔离 |
| `app/demo.py` | 四个端到端故障场景的可运行演示 |

## 关键机制如何对应问题

- **并发刷新覆盖新令牌** → 每组织一把锁 + Condition 的单飞：两个 worker 同时遇
  401 时只有一个真正调用刷新端点，另一个等待同一结果；后完成的旧刷新不可能覆盖
  新令牌（`tests/test_coordinator.py::SingleFlightTests`）。
- **刷新未确认期间旧 worker 发请求** → 刷新先把 `refresh_pending`（含 attempt id
  与待确认代次）落盘再出网；期间 `request_lease` 阻塞，旧 fence 租约立即失效，
  返回结果还要过一次 fence 校验，过期代次的响应直接丢弃重取。
- **换发成功但写本地存储前进程退出** → 磁盘保留 attempt id，重启后
  `recover_all()` 用同一 attempt 做幂等确认，**绝不重用已失效的旧 refresh
  token**；服务端无法重放时转入 `reauth_required` 并给出下一步授权动作。
- **服务端已轮换而客户端超时** → 超时不触发第二次刷新，挂起状态保留到恢复确认。
- **分页续传与去重** → 页面台账（`page_journal`）记录下一页游标，换令牌/重启后
  从断点继续；记录主键唯一约束（`INSERT OR IGNORE`）保证重复页面不重复落库。
- **逐组织隔离** → 授权文件、台账、锁、线程全部按组织隔离；单组织撤权或 refresh
  失效只暂停自己，其他组织继续采集。
- **秘密保护** → 令牌只存在于 `Secret` 与 0600 文件中；日志过滤器、异常消息、
  任务报告与操作者视图均只含组织标识、状态码和令牌指纹，测试与演示均含明文泄漏扫描。

## 操作者动作与状态视图

`RefreshCoordinator` 提供 `set_paused(org, True/False)`、`revoke(org)`、
`reauthorize(org)`；`status()` 返回每个组织的脱敏快照，其中 `next_action` 明确
下一步需要的授权动作，例如：

- `active`：无需动作；
- 暂停：调用恢复接口继续采集；
- `refresh_pending`：启动时自动确认挂起 attempt，无法重放则重新授权；
- `reauth_required`：引导重新完成授权以换取新的 refresh token；
- `revoked`：重新登记该组织授权（本地凭据已清除）。

## 本地运行

项目使用 Python 3.12+，仅依赖标准库。从项目根目录执行：

```sh
python3 -m app.demo                                   # 四个故障场景端到端演示
python3 -m unittest discover -s tests -v              # 全部单元/集成测试（26 个）
python3 -m compileall -q app tests                    # 语法检查
python3 -m app.inspect                                # 原始来源读取入口（保持可用）
```

演示覆盖：① 服务端已轮换而客户端超时；② 两个 worker 同时遇 401 的单飞刷新；
③ 换发成功、写本地存储前进程退出的重启恢复（含无法重放的反向验证）；
④ 仅一个组织撤权 / refresh 失效、暂停恢复与重新授权。

## 边界与数据说明

`fixtures/` 中组织与短效凭据均为虚构内容，不含真实授权信息；所有服务替身只在
进程内模拟，不发起任何真实网络请求。系统只读取合作方明确授权的数据，不提交或
更改其业务记录。处理结果放在 `runtime/`（已在 `.gitignore` 中忽略），源文件保持
只读；授权状态与台账文件权限固定为 0600。

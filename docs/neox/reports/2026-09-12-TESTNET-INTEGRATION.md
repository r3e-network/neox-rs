# 2026-09-12 Testnet 集成验证

## 连接结果

只读连接端点：`https://testnet-1.rpc.banelabs.org`

- client：`Geth/./node/v0.6.2-stable-8a687a93/linux-amd64/go1.24.13`
- chain ID：`0xba9304` / decimal `12227332`
- 当前高度：约 `10,030,414`（探针执行时）
- `eth_syncing=false`
- `net_peerCount=0x1f`（31）
- 最新区块有非空 dBFT extraData，miner 为 Neo X 系统地址
- `eth_gasPrice`、`eth_maxPriorityFeePerGas`、`eth_feeHistory`、`eth_getBlockTransactionCountByNumber`、`eth_getTransactionCount`、`eth_getCode` 均返回有效结果

## Neo X 系统合约只读检查

- Governance proxy `0x1212000000000000000000000000000000000001`：有代码
- KeyManagement proxy `0x1212000000000000000000000000000000000008`：有代码
- Governance `epochDuration()` 返回 `0xec40` = **60,480**
- Governance `sharePeriodDuration()` 返回 `0x0b40` = **2,880**
- KeyManagement `ZK_VERSION()` 返回 `1`
- KeyManagement `roundNumber()` 返回 `0x67` = **103**
- 创世区块 hash：`0x221f7d0a47dd80fe10f476625d62303947c9cd336113e119c64d919f0e9beb71`
- 最新区块具备连续 parent hash，未发现 RPC 层异常

## 结论

- testnet RPC 网络连通性：**PASS**
- testnet 节点同步状态：**PASS**
- testnet 基础费用/RPC 只读接口：**PASS**
- Neo X 系统合约代码与关键 DKG 配置读取：**PASS**
- testnet 共识/签名完整性：**部分验证**：可观察到有效 dBFT extraData 与持续出块，但未发送交易、未执行签名注入或节点级共识故障注入。
- 本地 Rust 与 testnet Geth 的 live differential：**未执行**，因为当前没有同时运行的本地 Rust HTTP endpoint；不能把公共 testnet 自检等同于跨客户端差分。

机器可读原始证据：`outputs/testnet-integration-20260912.json`。

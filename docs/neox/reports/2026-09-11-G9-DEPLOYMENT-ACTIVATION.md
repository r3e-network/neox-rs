# G9 双侧部署与共同激活门禁

## 已落地配置

- 共同激活高度：**10,000,000**
- 激活前：两侧均使用 legacy PKCS#7 语义
- 激活高度及之后：两侧均使用 strict PKCS#7 语义
- 禁止 strict/legacy 混跑
- 禁止激活后的 ad-hoc rollback

## 部署版本指纹

| 客户端 | 版本/来源 | 指纹 |
|---|---|---|
| Rust | `neox-v2.5.2` | `c1cc93a0202322c2d426114e5b44107bdfcd72cc` |
| Geth | height-gated patch on baseline | base `f0e236838bb334c7c0d29eeca33533ed0cfda254`; `outputs/geth-pkcs7-strict-height-gate.patch`; SHA-256 `26f19d844fa2ba7b55f10ad10421c0afd72f54841f4e8669049eb6e98d29c98f` |

## 双侧门控实现

Rust：

- 配置字段：`neoXPkcs7StrictBlock`
- 门控函数：`is_pkcs7_strict_active_at_block`
- 语义：`block >= activation_height` 时 strict

Geth：

- 配置字段：`neoXPkcs7StrictBlock`
- 门控函数：`IsNeoXPkcs7Strict`
- 语义：`head >= activation_height` 时 strict

## 边界验收向量

| 区块高度 | Rust | Geth |
|---:|---|---|
| 9,999,999 | legacy | legacy |
| 10,000,000 | strict | strict |
| 10,000,001 | strict | strict |

## 强制部署规则

1. 必须先部署双方带高度门控的版本，再设置共同激活高度。
2. 两侧 genesis/config 必须写入完全相同的 `neoXPkcs7StrictBlock=10000000`。
3. 激活前必须核对双方 build hash、配置 hash 和边界向量结果。
4. 激活高度之后，禁止运行任一 legacy 二进制或缺失激活字段的配置。
5. 激活后禁止删除、下调激活高度或回滚到旧二进制。
6. 任一节点配置高度不一致时，发布门禁必须失败，不得继续部署。

机器可读清单：`outputs/g9-deployment-activation.json`。

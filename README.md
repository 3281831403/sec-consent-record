用户明明撤回了授权，下游系统还在照常拿到他的数据：未记录授权时默认放行，等于默认同意；撤回只写状态不写时间，下游无法判断先后；撤回不传播，下游仍按旧状态取数；传播不校验目标确认，失败被静默忽略；版本校验只比较前缀，低版本被判为满足；版本升级后旧记录仍有效，未重新征得同意；有效期缺失，授权永久有效；有效期用创建时间而不是最后确认时间；策略校验不检查是否默认拒绝；批量处理复用授权状态，后一个用户命中前一个用户的授权。本仓库以 engine/privacy/consent.py 为核心，tests/privacy/test_consent.py 含 15 个当前全红的测试。要修的是：按上面的顺序把 10 个缺陷逐个修掉，且不得修改测试。engine/privacy/consent.py 是核心，tests/privacy/test_consent.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式

在仓库根目录执行以下命令。实现只使用标准库，离线运行，不使用随机数，全部时间由调用方显式传入。

    pytest tests -q

当前预期输出为 15 failed，且没有 error。逐个修复缺陷后，预期变为 15 passed。

字段表

场景: 安全

 3, pytest
依赖: 无外部依赖
 / 漏洞检测与攻防 / Bugfix / Python 3, pytest / 无外部依赖

测试约束

tests 目录不可修改。测试只调用 engine.privacy.consent 的 8 个桩，不联网，不读取系统时钟，不生成随机数据。

布局说明

本仓库使用 engine 嵌套布局，核心实现位于 engine/privacy 包内，测试位于 tests/privacy 包内。仓库根目录的 conftest.py 只负责把仓库根加入导入路径，不改变测试语义。

    sec-consent-record/
        README.md
        conftest.py
        engine/__init__.py
        engine/privacy/__init__.py
        engine/privacy/consent.py
        tests/privacy/test_consent.py

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

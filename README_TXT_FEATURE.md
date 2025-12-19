# --txt 参数功能完整说明

## 快速开始

```bash
# 1. 查看帮助
python mix-github.py help

# 2. 使用示例需求文件进行分析
python mix-github.py analyze your_target.exe --txt example_requirements.txt --model llama3

# 3. 交互式模式
python mix-github.py interactive --txt example_requirements.txt
```

## 功能说明

### 什么是 --txt 参数？

`--txt` 参数允许你指定一个需求文件，告诉 AI 工具你想要分析什么。AI 将：
- 🎯 **聚焦目标** - 只分析与你的目标相关的代码
- 🔍 **优先关注** - 优先分析你关心的功能点
- 🔑 **识别关键** - 重点追踪你指定的 API
- 🚫 **过滤噪音** - 忽略你不关心的代码

### 为什么要使用它？

**没有需求文件时：**
```
AI: "这个程序有 500 个函数，我逐一分析..."
你: "我只想知道注册码验证在哪里！"
```

**有需求文件时：**
```
你: "目标是绕过注册码验证，关注 RegQueryValueEx"
AI: "找到 3 个相关函数，主要验证逻辑在 0x401234..."
```

## 需求文件格式

创建一个 `.txt` 文件：

```txt
# 调试需求示例

目标: 绕过软件的授权验证

重点关注:
- 注册码验证函数
- 试用期检查  
- 网络验证相关调用

关键API:
- GetSystemTime
- RegQueryValueEx
- InternetOpen
- CreateFile

忽略:
- UI相关代码
- 日志功能
- 资源加载
```

### 字段说明

| 字段 | 必需 | 说明 | 示例 |
|------|------|------|------|
| 目标 | 是 | 本次调试的主要目标 | 绕过授权验证 |
| 重点关注 | 否 | 需要重点分析的功能 | 注册码验证函数 |
| 关键API | 否 | 与目标相关的重要API | GetSystemTime |
| 忽略 | 否 | 可以忽略的代码类型 | UI相关代码 |

### 格式规则

✅ **正确格式**:
```txt
目标: 绕过授权验证
重点关注:
- 第一项
- 第二项
```

❌ **错误格式**:
```txt
目标:绕过授权验证          # 缺少空格
重点关注
- 第一项                    # 缺少冒号
 - 第二项                   # 前面有空格
```

## 使用场景

### 场景 1: 破解软件试用限制

```txt
目标: 移除软件试用期限制

重点关注:
- 试用天数检查
- 时间比较逻辑
- 注册表日期存储

关键API:
- GetLocalTime
- GetSystemTime
- RegOpenKeyEx
- RegQueryValueEx

忽略:
- 错误处理
- 日志输出
```

### 场景 2: 绕过网络验证

```txt
目标: 绕过在线激活验证

重点关注:
- 网络请求构造
- 服务器响应处理
- 验证结果判断

关键API:
- InternetOpen
- HttpSendRequest
- InternetReadFile

忽略:
- UI更新
- 进度显示
```

### 场景 3: 分析加密算法

```txt
目标: 理解数据加密方式

重点关注:
- 加密函数实现
- 密钥生成逻辑
- 初始化向量

关键API:
- CryptEncrypt
- CryptCreateHash
- BCryptEncrypt

忽略:
- 文件I/O
- 内存分配
```

## 命令示例

### 基础使用

```bash
# 分析 PE 文件
python mix-github.py analyze crack_me.exe --txt my_req.txt

# 交互模式
python mix-github.py interactive --txt my_req.txt

# 生成补丁
python mix-github.py patch target.exe --txt my_req.txt --format python
```

### 高级选项

```bash
# 使用特定 LLM 模型
python mix-github.py analyze app.exe --txt req.txt --model codellama

# 指定输出目录
python mix-github.py analyze app.exe --txt req.txt --output ./analysis_results

# 使用远程 Ollama 服务
python mix-github.py analyze app.exe --txt req.txt --ollama-url http://server:11434

# 组合多个参数
python mix-github.py analyze app.exe \
    --txt requirements.txt \
    --model llama3 \
    --output ./results \
    --ollama-url http://localhost:11434
```

## 交互模式命令

进入交互模式后，可以使用新增的需求管理命令：

```bash
# 查看当前需求
disasm> requirements

# 加载新需求
disasm> loadreq new_requirements.txt

# 使用需求上下文询问 LLM
disasm> llm 如何绕过这个验证？
```

## 工作原理

1. **加载需求** 📥
   - 解析 .txt 文件
   - 提取目标、关注点、API列表

2. **传递上下文** 🔄
   - 需求传递给所有 AI 分析师
   - 注入到 LLM 的 system prompt

3. **针对性分析** 🎯
   - 优先分析相关函数
   - 过滤无关代码
   - 聚焦于目标

4. **生成报告** 📊
   - 报告围绕需求组织
   - 突出关键发现
   - 提供针对性建议

## 常见问题

### Q: 不使用 --txt 会怎样？
A: 工具正常工作，但 AI 会分析所有代码，可能不够聚焦。

### Q: 可以中途更改需求吗？
A: 可以！在交互模式中使用 `loadreq` 命令。

### Q: 需求文件必须包含所有字段吗？
A: 不需要，只有"目标"是必需的，其他字段可选。

### Q: 可以使用英文吗？
A: 当前只支持中文字段名，但内容可以是任何语言。

### Q: LLM 不可用时需求还有用吗？
A: 有一定作用，会影响函数分析优先级，但效果不如有 LLM。

## 文件位置

- **主程序**: `mix-github.py`
- **示例需求**: `example_requirements.txt`
- **使用指南**: `USAGE_DEMO.md`
- **实现细节**: `IMPLEMENTATION_SUMMARY.md`

## 下一步

1. 查看 `example_requirements.txt` 了解格式
2. 创建自己的需求文件
3. 使用 `--txt` 参数运行分析
4. 在交互模式中体验新功能

## 技术支持

- 遇到问题？查看 `IMPLEMENTATION_SUMMARY.md`
- 需要示例？参考 `USAGE_DEMO.md`
- 功能建议？提交 Issue

---

**享受更智能、更高效的逆向分析体验！** 🚀

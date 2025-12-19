# --txt 参数使用演示

## 功能概述

新增的 `--txt` 参数允许用户指定一个调试需求文件，AI分析将根据需求内容进行针对性分析。

## 使用方法

### 1. 基本用法

```bash
# 使用需求文件分析PE文件
python mix-github.py analyze target.exe --txt requirements.txt

# 交互式模式加载需求
python mix-github.py interactive --txt requirements.txt
```

### 2. 需求文件格式

创建一个 `.txt` 文件，格式如下：

```txt
# 调试需求文件
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

### 3. 使用示例

#### 示例1: 分析并生成报告

```bash
python mix-github.py analyze crackme.exe --txt example_requirements.txt --model llama3
```

AI将会：
- 优先分析需求文件中指定的关键API
- 重点关注与目标相关的代码段
- 忽略不相关的代码（如UI、日志）
- 生成针对性的补丁建议

#### 示例2: 交互式调试

```bash
python mix-github.py interactive --txt example_requirements.txt
```

在交互模式中可以：

```
# 查看当前需求
disasm> requirements

# 动态加载新需求
disasm> loadreq new_requirements.txt

# 基于需求询问LLM
disasm> llm 如何绕过授权验证？
```

### 4. 功能优势

1. **针对性分析**：AI不会漫无目的地分析，而是聚焦于需求目标
2. **过滤噪音**：忽略不相关的代码，提高分析效率
3. **优先级排序**：关键API和函数会被优先分析
4. **上下文理解**：LLM理解你的目标，给出更准确的建议

### 5. 与其他参数组合

```bash
# 使用特定模型 + 需求文件
python mix-github.py analyze target.exe --txt req.txt --model codellama

# 指定输出目录
python mix-github.py analyze target.exe --txt req.txt --output ./results

# 禁用LLM，仅基础分析 + 需求过滤
python mix-github.py analyze target.exe --txt req.txt --no-llm
```

## 技术细节

### 需求如何影响分析

1. **OllamaClient.analyze_code**：将需求注入到system prompt
2. **AICodeAnalyst**：所有分析师都能访问需求上下文
3. **函数优先级**：包含关键API的函数优先分析
4. **LLM响应**：AI回答会围绕需求目标，不偏离主题

### 需求文件字段说明

| 字段 | 说明 | 示例 |
|------|------|------|
| 目标 | 本次调试的主要目标 | 绕过授权验证 |
| 重点关注 | 需要重点分析的功能点 | 注册码验证函数 |
| 关键API | 与目标相关的重要API | GetSystemTime |
| 忽略 | 可以忽略的代码类型 | UI相关代码 |

## 完整示例

```bash
# 1. 准备需求文件
cat > my_requirements.txt << 'ENDREQ'
目标: 移除软件试用期限制

重点关注:
- 时间检查逻辑
- 注册表验证
- 试用天数计算

关键API:
- GetLocalTime
- RegOpenKeyEx
- RegQueryValueEx

忽略:
- 错误处理
- 日志记录
ENDREQ

# 2. 执行分析
python mix-github.py analyze trial_software.exe --txt my_requirements.txt --model llama3

# 3. 查看结果
# AI会生成包含以下内容的报告：
# - 与时间检查相关的函数列表
# - 注册表访问的具体位置
# - 试用期计算的逻辑分析
# - 针对性的补丁建议
```

## 注意事项

1. 需求文件必须使用UTF-8编码
2. 每个字段后必须跟冒号（中文冒号）
3. 列表项必须以 `-` 开头
4. 需求文件路径可以是相对或绝对路径

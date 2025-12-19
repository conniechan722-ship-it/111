# --txt 参数功能实现总结

## 概述

成功为 `mix-github.py` 添加了 `--txt` 命令行参数，允许用户导入调试需求文件。AI 分析现在可以根据需求文件的内容进行针对性分析。

## 实现的功能

### 1. 需求文件加载 (load_requirements)

**位置**: 文件开头，紧跟 imports 之后

**功能**:
- 解析 UTF-8 编码的 .txt 需求文件
- 支持中文字段（目标、重点关注、关键API、忽略）
- 提取结构化数据供后续使用
- 自动打印加载的需求摘要

**示例**:
```python
requirements = load_requirements('example_requirements.txt')
# 返回: {'goal': '...', 'focus': [...], 'key_apis': [...], 'ignore': [...]}
```

### 2. OllamaClient 增强

**修改内容**:
- `analyze_code` 方法新增 `requirements` 参数
- 根据需求动态构建 system prompt
- 将目标、关注点、关键API注入到提示词中
- 指导 LLM 围绕需求进行针对性分析

**代码变更**:
```python
def analyze_code(self, code_context: str, question: str, 
                 analyst_role: str = "reverse engineer",
                 requirements: Dict[str, Any] = None) -> Optional[str]:
```

### 3. AI 分析师体系更新

**修改的类**:
- `AICodeAnalyst` (基类)
- `LogicAnalyst`
- `SecurityAnalyst`
- `PatchExpert`
- `ReverseEngineer`
- `BehaviorAnalyst`

**变更内容**:
- 所有类的 `__init__` 方法添加 `requirements` 参数
- `_get_llm_insight` 方法传递需求到 LLM
- 分析师能访问需求上下文进行针对性分析

### 4. AITeamManager 更新

**功能增强**:
- 构造函数接收 `requirements` 参数
- 将需求传递给所有团队成员
- 协调各分析师基于需求进行分析

**代码**:
```python
def __init__(self, ollama_url: str = None, model: str = None, 
             use_llm: bool = True, requirements: Dict[str, Any] = None):
```

### 5. AIDisassemblyAnalyzer 更新

**新增功能**:
- 接收 `requirements_file` 路径参数
- 自动加载需求文件
- 将需求传递给 AI 团队
- 在分析过程中使用需求过滤和优先级排序

**使用**:
```python
analyzer = AIDisassemblyAnalyzer(
    file_path, 
    requirements_file='requirements.txt'
)
```

### 6. InteractiveAnalyzer 交互式增强

**新增命令**:
1. `requirements` - 查看当前加载的需求
2. `loadreq <file>` - 动态加载新的需求文件

**更新的方法**:
- `__init__`: 接收并加载需求文件
- `_show_help`: 添加需求管理命令说明
- `_llm_query`: LLM查询时包含需求上下文
- `_show_requirements`: 显示当前需求详情
- `_load_requirements`: 动态加载需求

**示例使用**:
```
disasm> requirements
📋 当前调试需求
目标: 绕过软件的授权验证
重点关注:
  - 注册码验证函数
  - 试用期检查

disasm> loadreq new_req.txt
需求文件已加载: new_req.txt
```

### 7. 命令行参数解析

**parse_args 更新**:
```python
parsed = {
    ...
    'requirements_file': None,  # 新增字段
}

elif arg == '--txt' and i + 1 < len(args):
    parsed['requirements_file'] = args[i + 1]
    i += 1
```

### 8. 命令函数更新

**修改的函数**:
- `cmd_analyze`: 传递 requirements_file 给分析器
- `cmd_interactive`: 传递 requirements_file 给交互式分析器  
- `cmd_patch`: 传递 requirements_file 给补丁生成器

### 9. 帮助文档更新

**print_usage 增强**:
- 添加 `--txt <文件>` 参数说明
- 提供需求文件格式示例
- 添加使用示例

## 需求文件格式

支持的结构：

```txt
# 注释行
目标: 主要调试目标

重点关注:
- 关注点1
- 关注点2

关键API:
- API1
- API2

忽略:
- 忽略项1
- 忽略项2
```

## 工作流程

1. **加载阶段**:
   - 用户通过 `--txt` 指定需求文件
   - `load_requirements` 解析文件内容
   - 需求数据结构化存储

2. **初始化阶段**:
   - AIDisassemblyAnalyzer 接收需求
   - AITeamManager 将需求分发给各分析师
   - 每个分析师保存需求引用

3. **分析阶段**:
   - LLM 调用时包含需求上下文
   - System prompt 注入目标和关注点
   - 分析结果聚焦于需求目标

4. **交互阶段**:
   - 用户可查看当前需求
   - 可动态加载新需求
   - LLM 查询基于需求回答

## 使用示例

### 基本使用

```bash
# 分析模式
python mix-github.py analyze target.exe --txt requirements.txt

# 交互模式
python mix-github.py interactive --txt requirements.txt

# 补丁模式
python mix-github.py patch target.exe --txt requirements.txt --format python
```

### 高级组合

```bash
# 使用特定模型
python mix-github.py analyze app.exe --txt req.txt --model codellama

# 指定输出目录
python mix-github.py analyze app.exe --txt req.txt --output ./results

# 远程 Ollama 服务
python mix-github.py analyze app.exe --txt req.txt --ollama-url http://192.168.1.100:11434
```

## 测试验证

### 功能测试
- ✅ 需求文件解析正确
- ✅ 命令行参数识别
- ✅ 各类初始化正确传递需求
- ✅ LLM 接收需求上下文
- ✅ 交互命令工作正常

### 代码质量
- ✅ 无语法错误
- ✅ 类型提示完整
- ✅ 文档字符串齐全
- ✅ 错误处理健壮

## 文件变更统计

- **修改文件**: mix-github.py
- **新增函数**: 3 个
  - load_requirements
  - _show_requirements
  - _load_requirements
- **修改函数**: 10+ 个
- **修改类**: 8 个
- **新增参数**: 多处
- **代码增量**: 约 200 行

## 向后兼容性

- ✅ --txt 参数完全可选
- ✅ 不指定时功能正常工作
- ✅ 现有脚本无需修改
- ✅ 所有原有功能保持不变

## 文档

- ✅ 命令行帮助完整
- ✅ 使用演示文档 (USAGE_DEMO.md)
- ✅ 实现总结文档 (本文件)
- ✅ 示例需求文件 (example_requirements.txt)

## 总结

成功实现了完整的 `--txt` 参数功能，包括：
- 需求文件的加载和解析
- 全链路的需求上下文传递
- AI 分析的针对性优化
- 交互式的需求管理
- 完善的文档和示例

该功能使得逆向分析工作更加高效和专注，AI 不再盲目分析，而是围绕用户指定的目标进行针对性分析。

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI团队反汇编分析工具 v2.0 (集成 Ollama LLM)

目标：
1. 深度反汇编分析，理解代码逻辑
2. 识别可修改的功能点
3. 生成补丁建议
4. AI多角色协作分析 (支持 Ollama LLM)

功能：
- 反汇编引擎（支持x86/x64）
- 控制流分析
- 数据流分析
- 函数语义识别
- 补丁点识别
- AI团队多角色代码审查
- Ollama LLM 智能分析
"""

import os
import sys

# 确保 Windows 控制台支持 UTF-8
if sys.platform == 'win32': 
    import io
    sys.stdout = io. TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr. buffer, encoding='utf-8')

import json
import struct
import re
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum, auto
from abc import ABC, abstractmethod
import hashlib

# ============================================================================
# 可选依赖检查
# ============================================================================

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    print("提示:  pip install pefile 以启用PE分析")

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError: 
    HAS_CAPSTONE = False
    print("提示: pip install capstone 以启用专业反汇编")

try:
    from keystone import *
    HAS_KEYSTONE = True
except ImportError:
    HAS_KEYSTONE = False
    print("提示:  pip install keystone-engine 以启用汇编功能")

try:
    import requests
    HAS_REQUESTS = True
except ImportError: 
    HAS_REQUESTS = False
    print("提示:  pip install requests 以启用Ollama LLM支持")


# ============================================================================
# Ollama LLM 客户端
# ============================================================================

class OllamaClient: 
    """Ollama 本地大语言模型客户端"""
    
    DEFAULT_URL = "http://localhost:11434"
    DEFAULT_MODEL = "llama3"
    
    def __init__(self, base_url:  str = None, model: str = None, timeout: int = 120):
        """
        初始化 Ollama 客户端
        
        Args:
            base_url:  Ollama 服务地址
            model:  模型名称
            timeout: 请求超时时间（秒）
        """
        self.base_url = (base_url or self.DEFAULT_URL).rstrip('/')
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout
        self. available = False
        self.available_models = []
        
        # 检查服务可用性
        if HAS_REQUESTS: 
            self._check_availability()
    
    def _check_availability(self) -> bool:
        """检查 Ollama 服务是否可用"""
        try:
            response = requests.get(
                f"{self. base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                self.available_models = [m['name'] for m in data. get('models', [])]
                self. available = len(self.available_models) > 0
                
                # 如果指定的模型不存在，尝试使用第一个可用模型
                if self.available and self.model not in self.available_models:
                    # 检查是否有部分匹配
                    for m in self.available_models:
                        if self.model in m or m in self.model:
                            self.model = m
                            break
                    else:
                        # 使用第一个可用模型
                        print(f"[Ollama] 模型 '{self. model}' 不可用，使用 '{self.available_models[0]}'")
                        self.model = self.available_models[0]
                
                print(f"[Ollama] 服务可用，模型: {self. model}")
                return True
            else: 
                print(f"[Ollama] 服务响应异常: {response. status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"[Ollama] 无法连接到 {self.base_url}")
            return False
        except requests.exceptions.Timeout:
            print(f"[Ollama] 连接超时")
            return False
        except Exception as e:
            print(f"[Ollama] 检查可用性失败: {e}")
            return False
    
    def generate(self, prompt: str, system: str = None, 
                 temperature: float = 0.7, max_tokens: int = 2048) -> Optional[str]:
        """
        生成文本响应
        
        Args:
            prompt: 用户提示词
            system: 系统提示词
            temperature: 温度参数
            max_tokens: 最大生成token数
            
        Returns:
            生成的文本，失败返回 None
        """
        if not HAS_REQUESTS or not self.available:
            return None
        
        try: 
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }
            
            if system:
                payload["system"] = system
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response. status_code == 200:
                data = response.json()
                return data. get('response', '')
            else: 
                print(f"[Ollama] 生成失败: {response.status_code}")
                return None
                
        except requests.exceptions. Timeout:
            print(f"[Ollama] 请求超时")
            return None
        except Exception as e: 
            print(f"[Ollama] 生成错误: {e}")
            return None
    
    def chat(self, messages:  List[Dict], temperature: float = 0.7) -> Optional[str]:
        """
        聊天模式
        
        Args:
            messages: 消息列表 [{"role": "user/assistant/system", "content":  "..."}]
            temperature: 温度参数
            
        Returns: 
            助手回复，失败返回 None
        """
        if not HAS_REQUESTS or not self.available:
            return None
        
        try:
            payload = {
                "model": self.model,
                "messages":  messages,
                "stream": False,
                "options": {
                    "temperature": temperature
                }
            }
            
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('message', {}).get('content', '')
            else:
                print(f"[Ollama] 聊天失败: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            print(f"[Ollama] 请求超时")
            return None
        except Exception as e: 
            print(f"[Ollama] 聊天错误: {e}")
            return None
    
    def analyze_code(self, code_context: str, question: str, 
                     analyst_role: str = "reverse engineer") -> Optional[str]:
        """
        分析代码的便捷方法
        
        Args: 
            code_context: 代码上下文（反汇编、函数信息等）
            question: 分析问题
            analyst_role: 分析师角色
            
        Returns:
            分析结果
        """
        system_prompt = f"""你是一位专业的{analyst_role}，精通x86/x64汇编语言和逆向工程。
你的任务是分析提供的反汇编代码，并给出专业、准确的分析。

分析时请注意：
1. 识别代码的功能和目的
2. 找出关键的逻辑点和可修改位置
3. 评估潜在的安全风险
4. 提供具体可行的建议

请用中文回答，保持专业简洁。"""
        
        prompt = f"""## 代码上下文

{code_context}

## 分析问题

{question}

请提供你的专业分析："""
        
        return self.generate(prompt, system=system_prompt)
    
    def is_available(self) -> bool:
        """检查服务是否可用"""
        return self.available and HAS_REQUESTS
    
    def get_status(self) -> Dict[str, Any]: 
        """获取服务状态"""
        return {
            'available': self.available,
            'base_url': self. base_url,
            'model': self.model,
            'available_models': self.available_models,
            'has_requests': HAS_REQUESTS
        }

# ============================================================================
# 基础数据结构
# ============================================================================

class InstructionType(Enum):
    """指令类型分类"""
    UNKNOWN = auto()
    DATA_TRANSFER = auto()      # mov, push, pop, lea
    ARITHMETIC = auto()         # add, sub, mul, div, inc, dec
    LOGIC = auto()              # and, or, xor, not, shl, shr
    CONTROL_FLOW = auto()       # jmp, call, ret, jcc
    COMPARISON = auto()         # cmp, test
    STRING = auto()             # movs, stos, lods, cmps
    STACK = auto()              # push, pop, enter, leave
    SYSTEM = auto()             # int, syscall, sysenter
    FLOATING_POINT = auto()     # fld, fst, fadd, etc. 
    SIMD = auto()               # SSE, AVX instructions
    NOP = auto()                # nop, padding
    PRIVILEGED = auto()         # ring0 instructions


class BranchType(Enum):
    """分支类型"""
    NONE = auto()
    UNCONDITIONAL = auto()      # jmp
    CONDITIONAL = auto()        # jcc
    CALL = auto()               # call
    RET = auto()                # ret
    INDIRECT = auto()           # jmp [eax], call [ebx]
    LOOP = auto()               # loop, loope, loopne


@dataclass
class Instruction:
    """反汇编指令"""
    address:  int
    size: int
    mnemonic: str
    op_str: str
    bytes:  bytes
    instruction_type: InstructionType = InstructionType. UNKNOWN
    branch_type: BranchType = BranchType.NONE
    branch_target: Optional[int] = None
    is_call: bool = False
    is_ret:  bool = False
    is_jump: bool = False
    is_conditional: bool = False
    reads:  List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    comment: str = ""
    
    def __str__(self):
        return f"0x{self.address:08x}:  {self.mnemonic} {self. op_str}"
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'address': hex(self.address),
            'size':  self.size,
            'mnemonic': self.mnemonic,
            'op_str': self.op_str,
            'bytes':  self.bytes.hex(),
            'type': self.instruction_type.name,
            'branch_type': self.branch_type.name,
            'branch_target': hex(self.branch_target) if self.branch_target else None
        }


@dataclass
class BasicBlock:
    """基本块"""
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit:  bool = False
    loop_header: bool = False
    
    @property
    def size(self) -> int:
        return self.end_address - self.start_address
    
    def __str__(self):
        return f"BasicBlock(0x{self.start_address:08x} - 0x{self.end_address:08x}, {len(self. instructions)} instrs)"
    
    def get_disassembly(self) -> str:
        """获取反汇编文本"""
        lines = []
        for instr in self.instructions:
            lines. append(f"  0x{instr. address:08x}:  {instr. mnemonic} {instr.op_str}")
        return '\n'.join(lines)


@dataclass
class Function:
    """函数"""
    address: int
    name: str
    size: int = 0
    end_address: int = 0
    basic_blocks: List[BasicBlock] = field(default_factory=list)
    calls: List[int] = field(default_factory=list)
    called_by: List[int] = field(default_factory=list)
    local_vars: List[Dict] = field(default_factory=list)
    arguments: List[Dict] = field(default_factory=list)
    return_type: str = "unknown"
    is_thunk: bool = False
    is_import: bool = False
    is_export: bool = False
    complexity: int = 0
    description: str = ""
    ai_analysis:  Dict[str, Any] = field(default_factory=dict)
    llm_analysis: str = ""  # LLM 生成的分析
    
    def get_disassembly(self) -> str:
        """获取完整反汇编"""
        lines = [f"; Function: {self.name}", f"; Address: 0x{self.address:08x}", ""]
        for bb in self.basic_blocks:
            lines.append(f"; Basic Block 0x{bb. start_address:08x}")
            lines.append(bb.get_disassembly())
            lines.append("")
        return '\n'. join(lines)


@dataclass 
class PatchPoint:
    """可修改点"""
    address:  int
    size:  int
    original_bytes: bytes
    original_instruction:  str
    patch_type: str
    description: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    suggested_patches: List[Dict] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    reversible: bool = True
    llm_suggestion: str = ""  # LLM 生成的建议
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'address':  hex(self.address),
            'size': self.size,
            'original_bytes': self.original_bytes.hex(),
            'original_instruction': self.original_instruction,
            'patch_type':  self.patch_type,
            'description': self.description,
            'risk_level': self.risk_level,
            'suggested_patches':  self.suggested_patches,
            'side_effects': self.side_effects
        }
# ============================================================================
# 反汇编引擎
# ============================================================================

class DisassemblyEngine: 
    """反汇编引擎"""
    
    # x86指令信息表
    INSTRUCTION_INFO = {
        # 数据传输
        'mov': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'movzx': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'movsx': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'lea': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'xchg': (InstructionType.DATA_TRANSFER, BranchType.NONE),
        'push': (InstructionType.STACK, BranchType. NONE),
        'pop': (InstructionType. STACK, BranchType.NONE),
        'pushad': (InstructionType.STACK, BranchType. NONE),
        'popad': (InstructionType. STACK, BranchType.NONE),
        'pushfd': (InstructionType.STACK, BranchType.NONE),
        'popfd':  (InstructionType.STACK, BranchType. NONE),
        
        # 算术运算
        'add': (InstructionType. ARITHMETIC, BranchType.NONE),
        'sub':  (InstructionType.ARITHMETIC, BranchType. NONE),
        'mul': (InstructionType.ARITHMETIC, BranchType.NONE),
        'imul':  (InstructionType.ARITHMETIC, BranchType. NONE),
        'div': (InstructionType.ARITHMETIC, BranchType. NONE),
        'idiv': (InstructionType. ARITHMETIC, BranchType.NONE),
        'inc': (InstructionType.ARITHMETIC, BranchType. NONE),
        'dec': (InstructionType. ARITHMETIC, BranchType.NONE),
        'neg':  (InstructionType.ARITHMETIC, BranchType. NONE),
        
        # 逻辑运算
        'and':  (InstructionType.LOGIC, BranchType.NONE),
        'or': (InstructionType. LOGIC, BranchType.NONE),
        'xor': (InstructionType.LOGIC, BranchType.NONE),
        'not': (InstructionType.LOGIC, BranchType. NONE),
        'shl': (InstructionType. LOGIC, BranchType.NONE),
        'shr': (InstructionType.LOGIC, BranchType. NONE),
        'sar': (InstructionType. LOGIC, BranchType.NONE),
        'rol': (InstructionType.LOGIC, BranchType. NONE),
        'ror': (InstructionType. LOGIC, BranchType.NONE),
        
        # 比较
        'cmp':  (InstructionType.COMPARISON, BranchType. NONE),
        'test': (InstructionType.COMPARISON, BranchType. NONE),
        
        # 控制流
        'jmp': (InstructionType. CONTROL_FLOW, BranchType.UNCONDITIONAL),
        'je': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jz': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jne': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jnz': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'ja': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jae': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jb': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jbe': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jg': (InstructionType. CONTROL_FLOW, BranchType. CONDITIONAL),
        'jge': (InstructionType. CONTROL_FLOW, BranchType.CONDITIONAL),
        'jl':  (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jle': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'js': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jns': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'jo': (InstructionType.CONTROL_FLOW, BranchType.CONDITIONAL),
        'jno': (InstructionType.CONTROL_FLOW, BranchType. CONDITIONAL),
        'call': (InstructionType.CONTROL_FLOW, BranchType.CALL),
        'ret': (InstructionType.CONTROL_FLOW, BranchType.RET),
        'retn': (InstructionType.CONTROL_FLOW, BranchType.RET),
        'loop': (InstructionType.CONTROL_FLOW, BranchType.LOOP),
        'loope': (InstructionType.CONTROL_FLOW, BranchType.LOOP),
        'loopne': (InstructionType.CONTROL_FLOW, BranchType.LOOP),
        
        # 字符串操作
        'movs': (InstructionType.STRING, BranchType. NONE),
        'movsb': (InstructionType.STRING, BranchType. NONE),
        'movsw': (InstructionType.STRING, BranchType. NONE),
        'movsd': (InstructionType.STRING, BranchType. NONE),
        'stos': (InstructionType.STRING, BranchType. NONE),
        'stosb': (InstructionType.STRING, BranchType. NONE),
        'stosw': (InstructionType.STRING, BranchType. NONE),
        'stosd': (InstructionType. STRING, BranchType.NONE),
        'lods': (InstructionType.STRING, BranchType. NONE),
        'cmps': (InstructionType.STRING, BranchType. NONE),
        'scas': (InstructionType.STRING, BranchType. NONE),
        'rep': (InstructionType.STRING, BranchType. NONE),
        
        # 系统
        'int': (InstructionType.SYSTEM, BranchType. NONE),
        'syscall': (InstructionType.SYSTEM, BranchType.NONE),
        'sysenter': (InstructionType. SYSTEM, BranchType.NONE),
        'cpuid': (InstructionType.SYSTEM, BranchType.NONE),
        'rdtsc': (InstructionType. SYSTEM, BranchType.NONE),
        
        # NOP
        'nop':  (InstructionType.NOP, BranchType. NONE),
        
        # 特权指令
        'cli': (InstructionType.PRIVILEGED, BranchType.NONE),
        'sti': (InstructionType.PRIVILEGED, BranchType.NONE),
        'hlt': (InstructionType.PRIVILEGED, BranchType.NONE),
        'in': (InstructionType.PRIVILEGED, BranchType.NONE),
        'out': (InstructionType. PRIVILEGED, BranchType. NONE),
    }
    
    def __init__(self, arch:  str = 'x86', mode: str = '32'):
        self.arch = arch
        self.mode = mode
        self.cs = None
        self. ks = None
        
        # 初始化Capstone
        if HAS_CAPSTONE:
            if arch == 'x86':
                if mode == '64':
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
                else:
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
                self.cs.detail = True
        
        # 初始化Keystone
        if HAS_KEYSTONE:
            if arch == 'x86':
                if mode == '64': 
                    self. ks = Ks(KS_ARCH_X86, KS_MODE_64)
                else:
                    self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
    
    def disassemble(self, code: bytes, base_address: int = 0) -> List[Instruction]:
        """反汇编代码"""
        if HAS_CAPSTONE and self.cs:
            return self._disassemble_capstone(code, base_address)
        else:
            return self._disassemble_simple(code, base_address)
    
    def _disassemble_capstone(self, code: bytes, base_address: int) -> List[Instruction]:
        """使用Capstone反汇编"""
        instructions = []
        
        for insn in self.cs.disasm(code, base_address):
            mnemonic = insn.mnemonic. lower()
            
            # 获取指令类型和分支类型
            inst_type, branch_type = self.INSTRUCTION_INFO. get(
                mnemonic, (InstructionType.UNKNOWN, BranchType. NONE)
            )
            
            # 解析分支目标
            branch_target = None
            if branch_type in [BranchType.UNCONDITIONAL, BranchType.CONDITIONAL,
                              BranchType.CALL, BranchType. LOOP]:
                branch_target = self._parse_branch_target(insn)
            
            # 解析读写操作数
            reads, writes = self._parse_operands(insn)
            
            instr = Instruction(
                address=insn.address,
                size=insn.size,
                mnemonic=mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
                instruction_type=inst_type,
                branch_type=branch_type,
                branch_target=branch_target,
                is_call=(branch_type == BranchType. CALL),
                is_ret=(branch_type == BranchType. RET),
                is_jump=(branch_type in [BranchType.UNCONDITIONAL, BranchType.CONDITIONAL]),
                is_conditional=(branch_type == BranchType. CONDITIONAL),
                reads=reads,
                writes=writes
            )
            
            instructions.append(instr)
        
        return instructions
    
    def _disassemble_simple(self, code:  bytes, base_address: int) -> List[Instruction]: 
        """简单反汇编（无Capstone时使用）"""
        instructions = []
        offset = 0
        
        # 简单的x86指令解码
        simple_opcodes = {
            0x90: ('nop', 1),
            0xC3: ('ret', 1),
            0xCC: ('int3', 1),
            0x55: ('push ebp', 1),
            0x5D: ('pop ebp', 1),
            0x50: ('push eax', 1),
            0x51: ('push ecx', 1),
            0x52: ('push edx', 1),
            0x53: ('push ebx', 1),
            0x58: ('pop eax', 1),
            0x59: ('pop ecx', 1),
            0x5A: ('pop edx', 1),
            0x5B: ('pop ebx', 1),
            0xC9: ('leave', 1),
        }
        
        while offset < len(code):
            addr = base_address + offset
            opcode = code[offset]
            
            if opcode in simple_opcodes: 
                mnemonic, size = simple_opcodes[opcode]
                op_str = ""
                if ' ' in mnemonic:
                    parts = mnemonic. split(' ', 1)
                    mnemonic = parts[0]
                    op_str = parts[1]
            elif opcode == 0xE8:  # CALL rel32
                if offset + 5 <= len(code):
                    rel = struct.unpack('<i', code[offset+1:offset+5])[0]
                    target = addr + 5 + rel
                    mnemonic = 'call'
                    op_str = f'0x{target:x}'
                    size = 5
                else: 
                    mnemonic = 'db'
                    op_str = f'0x{opcode:02x}'
                    size = 1
            elif opcode == 0xE9:  # JMP rel32
                if offset + 5 <= len(code):
                    rel = struct.unpack('<i', code[offset+1:offset+5])[0]
                    target = addr + 5 + rel
                    mnemonic = 'jmp'
                    op_str = f'0x{target: x}'
                    size = 5
                else:
                    mnemonic = 'db'
                    op_str = f'0x{opcode:02x}'
                    size = 1
            elif opcode == 0xEB:  # JMP rel8
                if offset + 2 <= len(code):
                    rel = struct.unpack('<b', code[offset+1:offset+2])[0]
                    target = addr + 2 + rel
                    mnemonic = 'jmp'
                    op_str = f'short 0x{target:x}'
                    size = 2
                else: 
                    mnemonic = 'db'
                    op_str = f'0x{opcode: 02x}'
                    size = 1
            elif 0x70 <= opcode <= 0x7F:  # Jcc rel8
                jcc_names = ['jo', 'jno', 'jb', 'jnb', 'jz', 'jnz', 'jbe', 'ja',
                            'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']
                if offset + 2 <= len(code):
                    rel = struct.unpack('<b', code[offset+1:offset+2])[0]
                    target = addr + 2 + rel
                    mnemonic = jcc_names[opcode - 0x70]
                    op_str = f'short 0x{target:x}'
                    size = 2
                else: 
                    mnemonic = 'db'
                    op_str = f'0x{opcode: 02x}'
                    size = 1
            else:
                # 未知指令，作为数据处理
                mnemonic = 'db'
                op_str = f'0x{opcode: 02x}'
                size = 1
            
            # 获取指令类型
            inst_type, branch_type = self.INSTRUCTION_INFO.get(
                mnemonic, (InstructionType.UNKNOWN, BranchType. NONE)
            )
            
            instr = Instruction(
                address=addr,
                size=size,
                mnemonic=mnemonic,
                op_str=op_str,
                bytes=code[offset:offset+size],
                instruction_type=inst_type,
                branch_type=branch_type,
                is_call=(mnemonic == 'call'),
                is_ret=(mnemonic in ['ret', 'retn']),
                is_jump=(mnemonic == 'jmp' or mnemonic. startswith('j')),
                is_conditional=(0x70 <= opcode <= 0x7F)
            )
            
            instructions.append(instr)
            offset += size
        
        return instructions
    
    def _parse_branch_target(self, insn) -> Optional[int]: 
        """解析分支目标地址"""
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == CS_OP_IMM:
                return op.imm
        return None
    
    def _parse_operands(self, insn) -> Tuple[List[str], List[str]]:
        """解析操作数的读写"""
        reads = []
        writes = []
        
        try:
            regs_read, regs_write = insn.regs_access()
            reads = [insn.reg_name(r) for r in regs_read]
            writes = [insn.reg_name(r) for r in regs_write]
        except Exception:
            pass
        
        return reads, writes
    
    def assemble(self, assembly:  str, address:  int = 0) -> Optional[bytes]:
        """汇编代码"""
        if not HAS_KEYSTONE or not self. ks:
            print("错误:  需要Keystone引擎进行汇编")
            return None
        
        try: 
            encoding, count = self.ks. asm(assembly, address)
            return bytes(encoding)
        except Exception as e:
            print(f"汇编错误:  {e}")
            return None

# ============================================================================
# 控制流分析器
# ============================================================================

class ControlFlowAnalyzer:
    """控制流分析器"""
    
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        self.addr_to_instr = {i.address: i for i in instructions}
        self.basic_blocks:  Dict[int, BasicBlock] = {}
        self.functions: Dict[int, Function] = {}
    
    def build_basic_blocks(self) -> Dict[int, BasicBlock]:
        """构建基本块"""
        if not self.instructions:
            return {}
        
        # 找出所有基本块的起始地址
        leaders = {self.instructions[0].address}
        
        for i, instr in enumerate(self.instructions):
            # 分支目标是leader
            if instr. branch_target and instr.branch_target in self.addr_to_instr:
                leaders. add(instr. branch_target)
            
            # 分支指令后面的指令是leader
            if instr.is_jump or instr.is_call or instr.is_ret:
                if i + 1 < len(self.instructions):
                    leaders.add(self. instructions[i + 1].address)
        
        # 构建基本块
        sorted_leaders = sorted(leaders)
        
        for i, leader_addr in enumerate(sorted_leaders):
            # 找到块的结束
            end_addr = leader_addr
            block_instrs = []
            
            for instr in self.instructions:
                if instr.address < leader_addr:
                    continue
                if i + 1 < len(sorted_leaders) and instr.address >= sorted_leaders[i + 1]: 
                    break
                
                block_instrs.append(instr)
                end_addr = instr. address + instr. size
                
                # 如果是分支指令，结束当前块
                if instr. is_jump or instr.is_ret:
                    break
            
            if block_instrs: 
                bb = BasicBlock(
                    start_address=leader_addr,
                    end_address=end_addr,
                    instructions=block_instrs
                )
                self.basic_blocks[leader_addr] = bb
        
        # 建立块之间的关系
        self._build_block_edges()
        
        return self.basic_blocks
    
    def _build_block_edges(self):
        """建立基本块之间的边"""
        for addr, block in self.basic_blocks.items():
            if not block.instructions:
                continue
            
            last_instr = block.instructions[-1]
            
            # 无条件跳转
            if last_instr.branch_type == BranchType.UNCONDITIONAL:
                if last_instr. branch_target in self.basic_blocks:
                    block.successors.append(last_instr.branch_target)
                    self.basic_blocks[last_instr.branch_target]. predecessors.append(addr)
            
            # 条件跳转
            elif last_instr. branch_type == BranchType. CONDITIONAL:
                # 跳转目标
                if last_instr.branch_target in self.basic_blocks:
                    block.successors. append(last_instr.branch_target)
                    self.basic_blocks[last_instr. branch_target].predecessors.append(addr)
                
                # fall-through
                next_addr = last_instr.address + last_instr.size
                if next_addr in self.basic_blocks:
                    block. successors.append(next_addr)
                    self.basic_blocks[next_addr].predecessors. append(addr)
            
            # 返回指令
            elif last_instr. branch_type == BranchType.RET:
                block.is_exit = True
            
            # 普通指令 - fall-through
            else:
                next_addr = last_instr.address + last_instr.size
                if next_addr in self.basic_blocks:
                    block.successors.append(next_addr)
                    self.basic_blocks[next_addr]. predecessors.append(addr)
    
    def detect_loops(self) -> List[Dict]:
        """检测循环"""
        loops = []
        
        for addr, block in self.basic_blocks.items():
            # 回边检测：后继指向自己或祖先
            for succ in block.successors:
                if succ <= addr:  # 简单的回边检测
                    loop = {
                        'header': succ,
                        'back_edge_from': addr,
                        'type': 'natural_loop'
                    }
                    loops.append(loop)
                    
                    if succ in self. basic_blocks: 
                        self.basic_blocks[succ].loop_header = True
        
        return loops
    
    def calculate_complexity(self) -> int:
        """计算圈复杂度"""
        # V(G) = E - N + 2P
        edges = sum(len(bb.successors) for bb in self.basic_blocks.values())
        nodes = len(self.basic_blocks)
        components = 1
        
        return edges - nodes + 2 * components
    
    def identify_functions(self) -> Dict[int, Function]:
        """识别函数"""
        function_starts = set()
        
        for instr in self.instructions:
            # 常见的函数序言
            if (instr.mnemonic == 'push' and 'ebp' in instr.op_str. lower()) or \
               (instr.mnemonic == 'push' and 'rbp' in instr.op_str. lower()):
                idx = self.instructions.index(instr)
                if idx + 1 < len(self.instructions):
                    next_instr = self. instructions[idx + 1]
                    if next_instr.mnemonic == 'mov' and \
                       ('ebp' in next_instr.op_str.lower() or 'rbp' in next_instr.op_str. lower()):
                        function_starts. add(instr.address)
            
            # sub rsp 模式（x64）
            elif instr.mnemonic == 'sub' and 'rsp' in instr.op_str.lower():
                function_starts.add(instr.address)
        
        # 通过CALL目标识别
        for instr in self.instructions:
            if instr.is_call and instr.branch_target:
                if instr.branch_target in self.addr_to_instr:
                    function_starts.add(instr.branch_target)
        
        # 创建函数对象
        sorted_starts = sorted(function_starts)
        
        for i, start_addr in enumerate(sorted_starts):
            end_addr = start_addr
            for instr in self.instructions:
                if instr.address < start_addr:
                    continue
                if i + 1 < len(sorted_starts) and instr.address >= sorted_starts[i + 1]:
                    break
                end_addr = instr.address + instr.size
                if instr.is_ret:
                    break
            
            func = Function(
                address=start_addr,
                name=f"sub_{start_addr: x}",
                size=end_addr - start_addr,
                end_address=end_addr
            )
            
            # 收集函数内的基本块
            for bb_addr, bb in self.basic_blocks.items():
                if start_addr <= bb_addr < end_addr:
                    func.basic_blocks. append(bb)
            
            # 收集调用目标
            for instr in self.instructions:
                if start_addr <= instr.address < end_addr:
                    if instr.is_call and instr.branch_target:
                        func. calls.append(instr.branch_target)
            
            self.functions[start_addr] = func
        
        return self.functions


# ============================================================================
# 数据流分析器
# ============================================================================

class DataFlowAnalyzer: 
    """数据流分析器"""
    
    def __init__(self, basic_blocks: Dict[int, BasicBlock]):
        self.basic_blocks = basic_blocks
        self. definitions: Dict[int, Set[str]] = {}
        self.uses: Dict[int, Set[str]] = {}
        self.live_in: Dict[int, Set[str]] = {}
        self. live_out: Dict[int, Set[str]] = {}
    
    def analyze_definitions_and_uses(self):
        """分析定义和使用"""
        for addr, block in self. basic_blocks.items():
            defs = set()
            uses = set()
            
            for instr in block. instructions:
                for r in instr.reads:
                    if r not in defs:
                        uses.add(r)
                
                for w in instr.writes:
                    defs.add(w)
            
            self.definitions[addr] = defs
            self.uses[addr] = uses
    
    def compute_liveness(self):
        """计算活跃性分析"""
        self.analyze_definitions_and_uses()
        
        for addr in self.basic_blocks:
            self.live_in[addr] = set()
            self.live_out[addr] = set()
        
        changed = True
        while changed:
            changed = False
            
            for addr in reversed(list(self. basic_blocks.keys())):
                block = self.basic_blocks[addr]
                
                new_out = set()
                for succ in block.successors:
                    if succ in self.live_in: 
                        new_out |= self.live_in[succ]
                
                new_in = self.uses[addr] | (new_out - self. definitions[addr])
                
                if new_in != self.live_in[addr] or new_out != self.live_out[addr]:
                    changed = True
                    self.live_in[addr] = new_in
                    self.live_out[addr] = new_out
    
    def find_dead_code(self) -> List[Instruction]:
        """查找死代码"""
        dead_instructions = []
        
        for addr, block in self.basic_blocks.items():
            live = self.live_out. get(addr, set()).copy()
            
            for instr in reversed(block.instructions):
                if instr.writes and not any(w in live for w in instr.writes):
                    if not self._has_side_effects(instr):
                        dead_instructions.append(instr)
                
                for w in instr.writes:
                    live.discard(w)
                for r in instr. reads:
                    live.add(r)
        
        return dead_instructions
    
    def _has_side_effects(self, instr: Instruction) -> bool:
        """检查指令是否有副作用"""
        side_effect_mnemonics = [
            'call', 'int', 'syscall', 'sysenter',
            'push', 'pop', 'ret', 'jmp',
            'in', 'out', 'cli', 'sti',
            'stosb', 'stosw', 'stosd', 'movsb', 'movsw', 'movsd'
        ]
        return instr.mnemonic. lower() in side_effect_mnemonics


# ============================================================================
# 语义分析器
# ============================================================================

class SemanticAnalyzer:
    """语义分析器 - 理解代码意图"""
    
    FUNCTION_PATTERNS = {
        'string_copy': [['mov', 'cmp', 'je', 'mov', 'inc', 'jmp'], ['rep', 'movsb']],
        'string_length': [['xor', 'mov', 'cmp', 'je', 'inc', 'jmp'], ['repne', 'scasb']],
        'loop_counter': [['mov', 'cmp', 'jge', 'inc', 'jmp'], ['mov', 'dec', 'jnz']],
        'memory_clear': [['xor', 'rep', 'stosb'], ['mov', 'rep', 'stosd']],
        'comparison': [['cmp', 'je'], ['cmp', 'jne'], ['test', 'jz'], ['test', 'jnz']],
        'switch_table': [['cmp', 'ja', 'jmp']],
    }
    
    API_CATEGORIES = {
        'file_io': ['CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle', 
                    'DeleteFile', 'MoveFile', 'CopyFile', 'fopen', 'fread', 'fwrite'],
        'network': ['socket', 'connect', 'send', 'recv', 'WSAStartup',
                   'InternetOpen', 'HttpOpenRequest', 'HttpSendRequest'],
        'process': ['CreateProcess', 'OpenProcess', 'TerminateProcess',
                   'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory'],
        'registry': ['RegOpenKey', 'RegSetValue', 'RegQueryValue', 'RegCreateKey'],
        'crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 
                  'CryptCreateHash', 'BCryptEncrypt'],
        'memory': ['malloc', 'free', 'HeapAlloc', 'HeapFree', 'VirtualAlloc'],
        'string': ['strcpy', 'strcmp', 'strlen', 'strcat', 'sprintf', 'memcpy', 'memset'],
        'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                      'NtQueryInformationProcess', 'GetTickCount'],
    }
    
    def __init__(self, functions: Dict[int, Function], imports: List[Dict] = None):
        self.functions = functions
        self.imports = imports or []
        self.api_map = self._build_api_map()
    
    def _build_api_map(self) -> Dict[str, str]:
        api_map = {}
        for category, apis in self.API_CATEGORIES.items():
            for api in apis: 
                api_map[api. lower()] = category
        return api_map
    
    def analyze_function_purpose(self, func: Function) -> Dict[str, Any]: 
        """分析函数目的"""
        analysis = {
            'purpose': 'unknown',
            'patterns_matched': [],
            'api_calls': [],
            'api_categories': set(),
            'is_suspicious': False,
            'suspicion_reasons': [],
            'description': '',
        }
        
        mnemonics = []
        for bb in func.basic_blocks:
            for instr in bb. instructions:
                mnemonics.append(instr.mnemonic)
        
        for pattern_name, patterns in self.FUNCTION_PATTERNS.items():
            for pattern in patterns: 
                if self._match_pattern(mnemonics, pattern):
                    analysis['patterns_matched'].append(pattern_name)
        
        for call_target in func.calls:
            api_name = self._resolve_api_name(call_target)
            if api_name:
                analysis['api_calls'].append(api_name)
                category = self.api_map.get(api_name.lower())
                if category: 
                    analysis['api_categories'].add(category)
        
        suspicious_categories = {'anti_debug', 'process', 'crypto'}
        if analysis['api_categories'] & suspicious_categories:
            analysis['is_suspicious'] = True
            analysis['suspicion_reasons']. append(
                f"使用了敏感API类别: {analysis['api_categories'] & suspicious_categories}"
            )
        
        analysis['description'] = self._generate_description(analysis)
        
        return analysis
    
    def _match_pattern(self, mnemonics: List[str], pattern:  List[str]) -> bool:
        if len(pattern) > len(mnemonics):
            return False
        pattern_str = ' '.join(pattern)
        mnemonic_str = ' '.join(mnemonics)
        return pattern_str in mnemonic_str
    
    def _resolve_api_name(self, address: int) -> Optional[str]:
        for imp in self.imports:
            if imp. get('address') == hex(address) or imp.get('address') == address:
                return imp.get('function', '')
        return None
    
    def _generate_description(self, analysis: Dict) -> str:
        parts = []
        if 'string_copy' in analysis['patterns_matched']: 
            parts.append("字符串复制操作")
        if 'string_length' in analysis['patterns_matched']:
            parts.append("字符串长度计算")
        if 'loop_counter' in analysis['patterns_matched']:
            parts.append("循环计数操作")
        if 'memory_clear' in analysis['patterns_matched']:
            parts.append("内存清零操作")
        if 'file_io' in analysis['api_categories']:
            parts.append("文件I/O操作")
        if 'network' in analysis['api_categories']:
            parts. append("网络通信")
        if 'crypto' in analysis['api_categories']:
            parts.append("加密/解密操作")
        if 'registry' in analysis['api_categories']:
            parts.append("注册表操作")
        return "; ".join(parts) if parts else "未识别的功能"

# ============================================================================
# 补丁分析器
# ============================================================================

class PatchAnalyzer:
    """补丁分析器 - 识别可修改点"""
    
    NOP_X86 = b'\x90'
    NOP_X64 = b'\x90'
    JMP_SHORT = b'\xEB'
    
    def __init__(self, instructions: List[Instruction], engine:  DisassemblyEngine):
        self.instructions = instructions
        self.engine = engine
        self. patch_points:  List[PatchPoint] = []
    
    def find_patch_points(self) -> List[PatchPoint]:
        """查找所有可能的补丁点"""
        self.patch_points = []
        
        self._find_conditional_jumps()
        self._find_calls()
        self._find_comparisons()
        self._find_returns()
        self._find_string_refs()
        self._find_constants()
        
        return self.patch_points
    
    def _find_conditional_jumps(self):
        """查找条件跳转"""
        for instr in self.instructions:
            if instr.is_conditional: 
                if instr.branch_target:
                    distance = instr.branch_target - (instr.address + instr.size)
                else:
                    distance = 0
                
                patches = []
                
                patches.append({
                    'name': 'NOP跳转',
                    'bytes': self.NOP_X86 * instr.size,
                    'description': '移除条件跳转，总是执行后续代码'
                })
                
                if -128 <= distance <= 127:
                    patches.append({
                        'name':  '强制跳转',
                        'bytes': self.JMP_SHORT + bytes([distance & 0xFF]),
                        'description':  '改为无条件跳转，总是执行跳转'
                    })
                
                inverted = self._invert_condition(instr.mnemonic)
                if inverted and self. engine: 
                    assembled = self.engine. assemble(
                        f"{inverted} 0x{instr. branch_target:x}", instr.address
                    )
                    if assembled:
                        patches.append({
                            'name':  '反转条件',
                            'bytes': assembled,
                            'description': f'反转条件:  {instr.mnemonic} -> {inverted}'
                        })
                
                patch = PatchPoint(
                    address=instr.address,
                    size=instr.size,
                    original_bytes=instr. bytes,
                    original_instruction=str(instr),
                    patch_type='conditional_jump',
                    description=f'条件跳转:  {instr.mnemonic}',
                    risk_level='MEDIUM',
                    suggested_patches=patches,
                    side_effects=['可能改变程序逻辑流程', '可能绕过检查']
                )
                self.patch_points.append(patch)
    
    def _invert_condition(self, mnemonic:  str) -> Optional[str]:
        """反转条件"""
        inversions = {
            'je': 'jne', 'jne': 'je',
            'jz': 'jnz', 'jnz': 'jz',
            'ja': 'jbe', 'jbe': 'ja',
            'jb': 'jae', 'jae': 'jb',
            'jg': 'jle', 'jle': 'jg',
            'jl': 'jge', 'jge': 'jl',
            'js': 'jns', 'jns': 'js',
            'jo': 'jno', 'jno': 'jo',
        }
        return inversions.get(mnemonic. lower())
    
    def _find_calls(self):
        """查找函数调用"""
        for instr in self. instructions:
            if instr.is_call:
                patches = []
                
                patches.append({
                    'name': 'NOP调用',
                    'bytes':  self.NOP_X86 * instr.size,
                    'description':  '移除函数调用'
                })
                
                ret_true = b'\xB8\x01\x00\x00\x00\xC3'
                ret_false = b'\x31\xC0\xC3'
                
                if instr.size >= 6:
                    patches.append({
                        'name': '返回TRUE',
                        'bytes': ret_true + self.NOP_X86 * (instr.size - 6),
                        'description': '替换调用，直接返回1(TRUE)'
                    })
                
                if instr. size >= 3:
                    patches.append({
                        'name': '返回FALSE',
                        'bytes':  ret_false + self.NOP_X86 * (instr.size - 3),
                        'description': '替换调用，直接返回0(FALSE)'
                    })
                
                patch = PatchPoint(
                    address=instr.address,
                    size=instr.size,
                    original_bytes=instr.bytes,
                    original_instruction=str(instr),
                    patch_type='call',
                    description=f'函数调用: {instr.op_str}',
                    risk_level='HIGH',
                    suggested_patches=patches,
                    side_effects=['移除功能', '可能导致程序不稳定', '可能绕过安全检查']
                )
                self.patch_points. append(patch)
    
    def _find_comparisons(self):
        """查找比较指令"""
        for i, instr in enumerate(self.instructions):
            if instr.mnemonic in ['cmp', 'test']: 
                patches = []
                
                match = re.search(r'0x([0-9a-fA-F]+)|(\d+)', instr.op_str)
                if match:
                    patches.append({
                        'name': '修改比较值为0',
                        'bytes': None,
                        'description': '将比较的常量改为0'
                    })
                    patches.append({
                        'name': '修改比较值为1',
                        'bytes': None,
                        'description': '将比较的常量改为1'
                    })
                
                if i + 1 < len(self.instructions):
                    next_instr = self.instructions[i + 1]
                    if next_instr.is_conditional:
                        total_size = instr.size + next_instr.size
                        patches.append({
                            'name': 'NOP比较和跳转',
                            'bytes':  self.NOP_X86 * total_size,
                            'description': '移除整个条件检查'
                        })
                
                if patches:
                    patch = PatchPoint(
                        address=instr.address,
                        size=instr.size,
                        original_bytes=instr. bytes,
                        original_instruction=str(instr),
                        patch_type='comparison',
                        description='比较指令',
                        risk_level='MEDIUM',
                        suggested_patches=patches,
                        side_effects=['改变条件判断结果']
                    )
                    self.patch_points.append(patch)
    
    def _find_returns(self):
        """查找返回指令"""
        for i, instr in enumerate(self.instructions):
            if instr.is_ret:
                if i > 0:
                    prev = self.instructions[i - 1]
                    if prev. mnemonic == 'mov' and 'eax' in prev.op_str. lower():
                        patches = []
                        
                        patches.append({
                            'name': '返回0',
                            'bytes': b'\x31\xC0',
                            'description': '将返回值改为0'
                        })
                        patches.append({
                            'name': '返回1',
                            'bytes':  b'\xB8\x01\x00\x00\x00',
                            'description':  '将返回值改为1'
                        })
                        patches.append({
                            'name': '返回-1',
                            'bytes': b'\x83\xC8\xFF',
                            'description': '将返回值改为-1'
                        })
                        
                        patch = PatchPoint(
                            address=prev.address,
                            size=prev.size,
                            original_bytes=prev.bytes,
                            original_instruction=str(prev),
                            patch_type='return_value',
                            description='返回值设置',
                            risk_level='MEDIUM',
                            suggested_patches=patches,
                            side_effects=['改变函数返回值', '影响调用者行为']
                        )
                        self.patch_points. append(patch)
    
    def _find_string_refs(self):
        """查找字符串引用"""
        for instr in self.instructions:
            if instr.mnemonic in ['push', 'mov', 'lea']:
                match = re.search(r'0x([4-7][0-9a-fA-F]{5,7})', instr.op_str)
                if match:
                    addr = int(match. group(1), 16)
                    
                    patch = PatchPoint(
                        address=instr.address,
                        size=instr.size,
                        original_bytes=instr.bytes,
                        original_instruction=str(instr),
                        patch_type='string_ref',
                        description=f'可能的字符串引用: 0x{addr:x}',
                        risk_level='LOW',
                        suggested_patches=[{
                            'name':  '修改字符串地址',
                            'bytes': None,
                            'description': '将字符串引用指向其他位置'
                        }],
                        side_effects=['改变显示的文本', '可能导致崩溃']
                    )
                    self.patch_points.append(patch)
    
    def _find_constants(self):
        """查找常量值"""
        for instr in self.instructions:
            if instr.mnemonic in ['mov', 'cmp', 'add', 'sub', 'and', 'or', 'xor']: 
                match = re.search(r'0x([0-9a-fA-F]+)', instr.op_str)
                if match:
                    value = int(match. group(1), 16)
                    
                    if value > 0xFF and value < 0x7FFFFFFF:
                        patch = PatchPoint(
                            address=instr.address,
                            size=instr.size,
                            original_bytes=instr. bytes,
                            original_instruction=str(instr),
                            patch_type='constant',
                            description=f'常量值: 0x{value: x} ({value})',
                            risk_level='LOW',
                            suggested_patches=[{
                                'name':  '修改常量值',
                                'bytes': None,
                                'description': '修改此常量为其他值'
                            }],
                            side_effects=['改变计算结果', '可能影响程序逻辑']
                        )
                        self.patch_points.append(patch)
    
    def generate_patch_script(self, patch:  PatchPoint, patch_index: int = 0) -> str:
        """生成补丁脚本"""
        if patch_index >= len(patch. suggested_patches):
            return ""
        
        suggested = patch.suggested_patches[patch_index]
        patch_bytes = suggested. get('bytes')
        
        if not patch_bytes: 
            return f"# 需要手动实现:  {suggested['description']}"
        
        script = f"""# 补丁脚本
# 位置: 0x{patch. address:08x}
# 原始:  {patch.original_instruction}
# 补丁: {suggested['name']}
# 描述:  {suggested['description']}

def apply_patch(file_path, file_offset):
    original = {patch.original_bytes!r}
    patched = {patch_bytes!r}
    
    with open(file_path, 'r+b') as f:
        f.seek(file_offset)
        current = f.read(len(original))
        
        if current == original:
            f.seek(file_offset)
            f.write(patched)
            print(f"补丁应用成功: 0x{{file_offset:x}}")
            return True
        else:
            print(f"原始字节不匹配，跳过")
            return False

# 使用方法: 
# apply_patch("target.exe", 0x{patch. address:x})
"""
        return script

# ============================================================================
# AI团队 - 代码分析专家（带LLM支持）
# ============================================================================

class AICodeAnalyst(ABC):
    """AI代码分析师基类"""
    
    def __init__(self, name: str, role: str, ollama:  OllamaClient = None):
        self.name = name
        self.role = role
        self. ollama = ollama
        self.findings:  List[Dict] = []
        self. system_prompt = ""
    
    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """执行分析"""
        pass
    
    def _add_finding(self, category: str, severity: str, title: str,
                     details: str, recommendation: str = ""):
        """添加发现"""
        self.findings. append({
            'analyst': self.name,
            'category':  category,
            'severity': severity,
            'title': title,
            'details': details,
            'recommendation': recommendation
        })
    
    def _get_llm_insight(self, context: str, question: str) -> Optional[str]:
        """获取LLM洞察"""
        if not self.ollama or not self.ollama.is_available():
            return None
        
        try:
            return self.ollama. analyze_code(context, question, self.role)
        except Exception as e:
            print(f"[{self.name}] LLM分析失败: {e}")
            return None
    
    def _format_instructions_for_llm(self, instructions: List[Instruction], 
                                      limit: int = 50) -> str:
        """格式化指令供LLM分析"""
        lines = []
        for instr in instructions[: limit]:
            lines.append(f"0x{instr. address:08x}:  {instr.mnemonic} {instr.op_str}")
        if len(instructions) > limit:
            lines.append(f"... (还有 {len(instructions) - limit} 条指令)")
        return '\n'.join(lines)


class LogicAnalyst(AICodeAnalyst):
    """逻辑分析师 - 理解代码逻辑流程"""
    
    def __init__(self, ollama: OllamaClient = None):
        super().__init__("逻辑分析师", "代码逻辑和控制流专家", ollama)
        self.system_prompt = """你是一位专业的代码逻辑分析师，擅长分析程序的控制流和数据流。
你的任务是：
1. 理解代码的执行流程
2. 识别关键的条件判断和循环结构
3. 解释代码的功能和目的
4. 找出逻辑漏洞或可优化点

请用中文回答，保持专业简洁。"""
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        result = {
            'analyst': self.name,
            'analysis_type': 'logic_flow',
            'findings': [],
            'code_structure': {},
            'logic_patterns': [],
            'logic_summary': '',
            'llm_insight': None
        }
        
        functions = data.get('functions', {})
        basic_blocks = data. get('basic_blocks', {})
        instructions = data.get('instructions', [])
        
        # 分析每个函数的逻辑
        for addr, func in functions. items():
            func_analysis = self._analyze_function_logic(func)
            result['findings']. append(func_analysis)
        
        # 生成整体结构
        result['code_structure'] = {
            'total_functions': len(functions),
            'total_blocks': len(basic_blocks),
            'entry_points': [addr for addr, bb in basic_blocks. items() if bb. is_entry],
            'exit_points':  [addr for addr, bb in basic_blocks.items() if bb.is_exit],
        }
        
        # 检测逻辑模式
        result['logic_patterns'] = self._detect_logic_patterns(data)
        
        # 生成逻辑摘要
        result['logic_summary'] = self._generate_logic_summary(result)
        
        # LLM深度分析
        if self.ollama and self.ollama. is_available() and instructions:
            context = self._format_instructions_for_llm(instructions, 30)
            question = "请分析这段代码的主要逻辑流程，识别关键的条件判断和循环结构，并解释其可能的功能。"
            
            llm_response = self._get_llm_insight(context, question)
            if llm_response:
                result['llm_insight'] = llm_response
        
        return result
    
    def _analyze_function_logic(self, func: Function) -> Dict:
        """分析单个函数的逻辑"""
        analysis = {
            'address': hex(func.address),
            'name':  func.name,
            'block_count': len(func.basic_blocks),
            'call_count': len(func.calls),
            'logic_type': 'unknown',
            'description': ''
        }
        
        if len(func.basic_blocks) == 1:
            analysis['logic_type'] = 'linear'
            analysis['description'] = '简单线性函数，无分支'
        elif any(bb.loop_header for bb in func. basic_blocks):
            analysis['logic_type'] = 'loop'
            analysis['description'] = '包含循环结构'
        elif len(func.basic_blocks) > 5:
            analysis['logic_type'] = 'complex'
            analysis['description'] = f'复杂函数，包含{len(func.basic_blocks)}个基本块'
        else:
            analysis['logic_type'] = 'branching'
            analysis['description'] = '包含条件分支'
        
        return analysis
    
    def _detect_logic_patterns(self, data: Dict) -> List[Dict]:
        """检测逻辑模式"""
        patterns = []
        instructions = data.get('instructions', [])
        
        for i, instr in enumerate(instructions):
            if instr.mnemonic == 'cmp' and i + 1 < len(instructions):
                next_instr = instructions[i + 1]
                if next_instr.is_conditional:
                    patterns.append({
                        'type': 'condition_check',
                        'address': hex(instr.address),
                        'pattern': f'{instr.mnemonic} {instr.op_str} -> {next_instr.mnemonic}',
                        'description': '条件检查后跳转'
                    })
        
        for instr in instructions: 
            if instr. mnemonic in ['loop', 'loope', 'loopne']:
                patterns. append({
                    'type': 'loop',
                    'address': hex(instr.address),
                    'pattern': f'{instr.mnemonic} {instr.op_str}',
                    'description': '计数循环'
                })
            elif instr.is_conditional and instr.branch_target:
                if instr.branch_target < instr.address:
                    patterns.append({
                        'type': 'backward_branch',
                        'address': hex(instr.address),
                        'target': hex(instr.branch_target),
                        'description': '向后跳转（可能是循环）'
                    })
        
        call_sequence = []
        for instr in instructions: 
            if instr. is_call: 
                call_sequence. append({
                    'address': hex(instr.address),
                    'target': instr.op_str
                })
        
        if len(call_sequence) > 3:
            patterns. append({
                'type': 'call_chain',
                'calls': call_sequence[: 10],
                'description': f'函数调用链（{len(call_sequence)}个调用）'
            })
        
        return patterns
    
    def _generate_logic_summary(self, result: Dict) -> str:
        """生成逻辑摘要"""
        structure = result. get('code_structure', {})
        patterns = result.get('logic_patterns', [])
        
        summary_parts = []
        summary_parts.append(f"代码包含 {structure. get('total_functions', 0)} 个函数，"
                           f"{structure.get('total_blocks', 0)} 个基本块。")
        
        pattern_types = defaultdict(int)
        for p in patterns:
            pattern_types[p['type']] += 1
        
        if pattern_types: 
            summary_parts. append("检测到的逻辑模式：")
            for ptype, count in pattern_types.items():
                summary_parts.append(f"  - {ptype}: {count} 处")
        
        return "\n".join(summary_parts)


class SecurityAnalyst(AICodeAnalyst):
    """安全分析师 - 识别安全问题和可利用点"""
    
    def __init__(self, ollama: OllamaClient = None):
        super().__init__("安全分析师", "安全漏洞和逆向工程专家", ollama)
        self.system_prompt = """你是一位专业的安全分析师，精通软件安全和逆向工程。
你的任务是：
1. 识别代码中的安全检查和保护机制
2. 找出可能被绕过的安全点
3. 评估安全风险等级
4. 提供具体的绕过建议

请用中文回答，保持专业简洁。"""
        
        self.dangerous_functions = {
            'strcpy': '缓冲区溢出风险',
            'strcat': '缓冲区溢出风险',
            'sprintf': '格式化字符串漏洞',
            'gets': '严重缓冲区溢出',
            'scanf': '输入验证问题',
            'memcpy': '需检查长度参数',
            'memmove': '需检查长度参数',
        }
        
        self.security_functions = {
            'IsDebuggerPresent': '调试器检测',
            'CheckRemoteDebuggerPresent': '远程调试器检测',
            'NtQueryInformationProcess':  '进程信息查询（可能是反调试）',
            'GetTickCount': '时间检测（可能是反调试）',
            'QueryPerformanceCounter': '性能计数器（可能是反调试）',
            'OutputDebugString': '调试输出检测',
        }
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            'analyst': self.name,
            'analysis_type': 'security',
            'vulnerabilities': [],
            'security_checks': [],
            'bypass_opportunities': [],
            'dangerous_imports': [],
            'risk_assessment': {},
            'llm_insight': None
        }
        
        instructions = data.get('instructions', [])
        imports = data.get('imports', [])
        patch_points = data. get('patch_points', [])
        
        result['dangerous_imports'] = self._analyze_imports(imports)
        result['security_checks'] = self._find_security_checks(instructions, imports)
        result['bypass_opportunities'] = self._find_bypass_opportunities(
            instructions, patch_points, result['security_checks']
        )
        result['risk_assessment'] = self._assess_risk(result)
        
        # LLM深度分析
        if self.ollama and self.ollama.is_available():
            security_context = self._build_security_context(result, instructions)
            question = "请分析这些安全检查点，评估它们的强度，并提供具体的绕过建议。"
            
            llm_response = self._get_llm_insight(security_context, question)
            if llm_response: 
                result['llm_insight'] = llm_response
        
        return result
    
    def _build_security_context(self, result: Dict, instructions: List[Instruction]) -> str:
        """构建安全分析上下文"""
        lines = ["## 安全检查点"]
        
        for check in result. get('security_checks', [])[:5]:
            lines.append(f"- {check. get('function', check.get('type', 'unknown'))} @ {check.get('address', 'N/A')}")
        
        lines.append("\n## 危险导入")
        for imp in result.get('dangerous_imports', [])[:5]:
            lines. append(f"- {imp.get('function', '')} ({imp.get('risk', '')})")
        
        lines.append("\n## 相关代码")
        lines.append(self._format_instructions_for_llm(instructions, 20))
        
        return '\n'.join(lines)
    
    def _analyze_imports(self, imports:  List[Dict]) -> List[Dict]: 
        """分析危险导入"""
        dangerous = []
        
        for imp in imports:
            func_name = imp. get('function', '')
            
            for dangerous_func, risk in self.dangerous_functions.items():
                if dangerous_func. lower() in func_name.lower():
                    dangerous.append({
                        'function': func_name,
                        'dll': imp.get('dll', ''),
                        'risk':  risk,
                        'severity': 'HIGH'
                    })
            
            for sec_func, purpose in self.security_functions.items():
                if sec_func.lower() in func_name.lower():
                    dangerous. append({
                        'function': func_name,
                        'dll': imp. get('dll', ''),
                        'purpose': purpose,
                        'severity':  'INFO',
                        'is_security_check': True
                    })
        
        return dangerous
    
    def _find_security_checks(self, instructions: List[Instruction],
                              imports: List[Dict]) -> List[Dict]:
        """查找安全检查点"""
        checks = []
        
        for i, instr in enumerate(instructions):
            if instr.is_call:
                for sec_func in self.security_functions: 
                    if sec_func. lower() in instr.op_str. lower():
                        check = {
                            'address': hex(instr.address),
                            'function': sec_func,
                            'purpose': self.security_functions[sec_func],
                            'subsequent_check': None
                        }
                        
                        for j in range(i + 1, min(i + 10, len(instructions))):
                            next_instr = instructions[j]
                            if next_instr.mnemonic in ['test', 'cmp']: 
                                check['comparison'] = str(next_instr)
                            if next_instr. is_conditional: 
                                check['subsequent_check'] = {
                                    'address': hex(next_instr.address),
                                    'instruction': str(next_instr)
                                }
                                break
                        
                        checks.append(check)
        
        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['test', 'cmp']:
                if 'eax' in instr.op_str. lower() and i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    if next_instr. is_conditional: 
                        checks.append({
                            'address': hex(instr.address),
                            'type': 'return_value_check',
                            'comparison': str(instr),
                            'jump':  str(next_instr),
                            'purpose': '返回值检查'
                        })
        
        return checks
    
    def _find_bypass_opportunities(self, instructions: List[Instruction],
                                   patch_points: List[PatchPoint],
                                   security_checks: List[Dict]) -> List[Dict]:
        """查找绕过机会"""
        opportunities = []
        
        for check in security_checks:
            if check.get('subsequent_check'):
                addr_str = check['subsequent_check']. get('address', '0x0')
                
                opportunity = {
                    'target': check. get('function', check.get('type', 'unknown')),
                    'check_address': check['address'],
                    'bypass_address': addr_str,
                    'method': 'NOP条件跳转或反转条件',
                    'difficulty': 'EASY',
                    'description': f"可以通过修改 {addr_str} 处的跳转来绕过检查"
                }
                opportunities.append(opportunity)
        
        for patch in patch_points:
            if patch.patch_type == 'conditional_jump':
                opportunities.append({
                    'target': '条件检查',
                    'check_address':  hex(patch.address),
                    'bypass_address': hex(patch.address),
                    'method': patch.suggested_patches[0]['name'] if patch.suggested_patches else 'NOP',
                    'difficulty': 'EASY',
                    'description': patch.description
                })
            elif patch.patch_type == 'call': 
                opportunities.append({
                    'target': '函数调用',
                    'check_address': hex(patch. address),
                    'bypass_address':  hex(patch.address),
                    'method': 'NOP调用或修改返回值',
                    'difficulty': 'MEDIUM',
                    'description': patch.description
                })
        
        return opportunities
    
    def _assess_risk(self, result: Dict) -> Dict:
        """风险评估"""
        dangerous_count = len(result. get('dangerous_imports', []))
        security_count = len(result. get('security_checks', []))
        bypass_count = len(result.get('bypass_opportunities', []))
        
        risk_score = dangerous_count * 2 + bypass_count
        
        if risk_score >= 10:
            risk_level = 'CRITICAL'
        elif risk_score >= 5:
            risk_level = 'HIGH'
        elif risk_score >= 2:
            risk_level = 'MEDIUM'
        else: 
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'dangerous_function_count': dangerous_count,
            'security_check_count': security_count,
            'bypass_opportunity_count': bypass_count,
            'recommendation': self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        recommendations = {
            'CRITICAL': "发现多个高危点，建议深入分析每个安全检查的绕过可能性",
            'HIGH':  "存在明显的安全检查，可以尝试补丁绕过",
            'MEDIUM': "存在一些检查点，需要进一步分析",
            'LOW': "安全检查较少，可能不是主要保护逻辑"
        }
        return recommendations.get(risk_level, "未知风险级别")

class PatchExpert(AICodeAnalyst):
    """补丁专家 - 提供修改建议"""
    
    def __init__(self, ollama:  OllamaClient = None):
        super().__init__("补丁专家", "二进制补丁和代码修改专家", ollama)
        self.system_prompt = """你是一位专业的二进制补丁专家，精通PE文件修改和代码补丁。
你的任务是：
1. 分析可修改的代码点
2. 提供具体的补丁方案（包括字节序列）
3. 评估补丁风险和副作用
4. 生成补丁脚本

请用中文回答，保持专业简洁。"""
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            'analyst':  self. name,
            'analysis_type': 'patching',
            'patch_recommendations': [],
            'modification_plan': [],
            'categorized_patches': {},
            'risk_analysis': {},
            'llm_insight': None
        }
        
        patch_points = data.get('patch_points', [])
        security_analysis = data.get('security_analysis', {})
        
        result['categorized_patches'] = self._categorize_patches(patch_points)
        result['patch_recommendations'] = self._generate_recommendations(
            patch_points, security_analysis
        )
        result['modification_plan'] = self._create_modification_plan(
            result['patch_recommendations']
        )
        result['risk_analysis'] = self._analyze_patch_risks(patch_points)
        
        # LLM深度分析
        if self.ollama and self.ollama. is_available() and patch_points:
            patch_context = self._build_patch_context(patch_points[: 10])
            question = "请分析这些可修改点，推荐最佳的补丁策略，并说明每个补丁的风险。"
            
            llm_response = self._get_llm_insight(patch_context, question)
            if llm_response: 
                result['llm_insight'] = llm_response
        
        return result
    
    def _build_patch_context(self, patch_points: List[PatchPoint]) -> str:
        """构建补丁分析上下文"""
        lines = ["## 可修改点列表\n"]
        
        for i, pp in enumerate(patch_points, 1):
            lines.append(f"### 补丁点 {i}")
            lines.append(f"- 地址:  {hex(pp.address)}")
            lines.append(f"- 类型: {pp. patch_type}")
            lines.append(f"- 原始指令: {pp. original_instruction}")
            lines.append(f"- 风险级别: {pp.risk_level}")
            lines.append(f"- 描述: {pp. description}")
            if pp.suggested_patches:
                lines. append(f"- 建议补丁: {pp.suggested_patches[0]['name']}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def _categorize_patches(self, patch_points:  List[PatchPoint]) -> Dict[str, List]: 
        """分类补丁点"""
        categories = defaultdict(list)
        
        for patch in patch_points: 
            categories[patch.patch_type]. append({
                'address':  hex(patch.address),
                'description': patch.description,
                'risk_level': patch.risk_level,
                'patch_count': len(patch. suggested_patches)
            })
        
        return dict(categories)
    
    def _generate_recommendations(self, patch_points: List[PatchPoint],
                                  security_analysis: Dict) -> List[Dict]:
        """生成补丁建议"""
        recommendations = []
        
        bypass_opportunities = security_analysis.get('bypass_opportunities', [])
        bypass_addresses = {opp. get('bypass_address') for opp in bypass_opportunities}
        
        for patch in patch_points: 
            addr_hex = hex(patch. address)
            
            priority = 'LOW'
            if addr_hex in bypass_addresses:
                priority = 'HIGH'
            elif patch.patch_type in ['conditional_jump', 'call']: 
                priority = 'MEDIUM'
            
            rec = {
                'address': addr_hex,
                'type': patch.patch_type,
                'priority': priority,
                'original':  patch.original_instruction,
                'suggestions': [],
                'side_effects': patch.side_effects
            }
            
            for suggested in patch.suggested_patches:
                if suggested. get('bytes'):
                    rec['suggestions'].append({
                        'name': suggested['name'],
                        'description': suggested['description'],
                        'bytes': suggested['bytes']. hex(),
                        'reversible': True
                    })
            
            if rec['suggestions']: 
                recommendations.append(rec)
        
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return recommendations
    
    def _create_modification_plan(self, recommendations: List[Dict]) -> List[Dict]:
        """创建修改计划"""
        plan = []
        
        high_priority = [r for r in recommendations if r['priority'] == 'HIGH']
        
        for i, rec in enumerate(high_priority[: 5], 1):
            step = {
                'step': i,
                'action': f"修改 {rec['address']} 处的 {rec['type']}",
                'target': rec['address'],
                'original': rec['original'],
                'suggested_patch': rec['suggestions'][0] if rec['suggestions'] else None,
                'expected_effect': rec['suggestions'][0]['description'] if rec['suggestions'] else '未知',
                'verification':  '运行程序验证修改效果'
            }
            plan.append(step)
        
        return plan
    
    def _analyze_patch_risks(self, patch_points: List[PatchPoint]) -> Dict: 
        """分析补丁风险"""
        risk_counts = defaultdict(int)
        for patch in patch_points:
            risk_counts[patch.risk_level] += 1
        
        total = len(patch_points)
        
        high_risk_pct = 0
        if total > 0:
            high_risk_pct = (risk_counts. get('HIGH', 0) + risk_counts.get('CRITICAL', 0)) / total * 100
        
        return {
            'total_patches': total,
            'by_risk_level':  dict(risk_counts),
            'high_risk_percentage': high_risk_pct,
            'recommendation': self._get_risk_recommendation(risk_counts)
        }
    
    def _get_risk_recommendation(self, risk_counts: Dict) -> str:
        high_risk = risk_counts.get('HIGH', 0) + risk_counts. get('CRITICAL', 0)
        if high_risk > 5:
            return "存在多个高风险修改点，建议在虚拟机中测试"
        elif high_risk > 0:
            return "建议先备份原文件再进行修改"
        else: 
            return "风险较低，可以尝试修改"


class ReverseEngineer(AICodeAnalyst):
    """逆向工程师 - 深度代码理解"""
    
    def __init__(self, ollama: OllamaClient = None):
        super().__init__("逆向工程师", "深度逆向分析和算法识别专家", ollama)
        self.system_prompt = """你是一位资深的逆向工程师，精通汇编语言和底层代码分析。
你的任务是：
1. 深度理解代码结构和算法
2. 识别加密、压缩、混淆等技术
3. 生成伪代码帮助理解
4. 识别关键数据结构

请用中文回答，保持专业简洁。"""
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        result = {
            'analyst':  self.name,
            'analysis_type': 'reverse_engineering',
            'code_understanding': {},
            'algorithms_detected': [],
            'data_structures':  [],
            'decompilation_hints': [],
            'llm_insight': None
        }
        
        instructions = data.get('instructions', [])
        functions = data.get('functions', {})
        basic_blocks = data. get('basic_blocks', {})
        
        result['code_understanding'] = self._understand_code_structure(
            instructions, functions, basic_blocks
        )
        result['algorithms_detected'] = self._detect_algorithms(instructions)
        result['data_structures'] = self._identify_data_structures(instructions)
        result['decompilation_hints'] = self._generate_decompilation_hints(functions)
        
        # LLM深度分析
        if self.ollama and self.ollama.is_available() and instructions:
            code_context = self._format_instructions_for_llm(instructions, 40)
            question = "请深度分析这段代码，识别其中的算法模式，并尝试生成伪代码来解释其功能。"
            
            llm_response = self._get_llm_insight(code_context, question)
            if llm_response:
                result['llm_insight'] = llm_response
        
        return result
    
    def _understand_code_structure(self, instructions: List[Instruction],
                                   functions: Dict[int, Function],
                                   basic_blocks: Dict[int, BasicBlock]) -> Dict:
        """理解代码结构"""
        structure = {
            'instruction_count': len(instructions),
            'function_count': len(functions),
            'block_count': len(basic_blocks),
            'instruction_distribution': {},
            'control_flow_complexity': 'unknown'
        }
        
        type_counts = defaultdict(int)
        for instr in instructions:
            type_counts[instr. instruction_type. name] += 1
        
        structure['instruction_distribution'] = dict(type_counts)
        
        branch_count = sum(1 for i in instructions if i. is_conditional)
        call_count = sum(1 for i in instructions if i.is_call)
        
        complexity_score = branch_count + call_count * 0.5
        if complexity_score > 50:
            structure['control_flow_complexity'] = 'HIGH'
        elif complexity_score > 20:
            structure['control_flow_complexity'] = 'MEDIUM'
        else:
            structure['control_flow_complexity'] = 'LOW'
        
        structure['metrics'] = {
            'branch_count': branch_count,
            'call_count': call_count,
            'complexity_score': complexity_score
        }
        
        return structure
    
    def _detect_algorithms(self, instructions: List[Instruction]) -> List[Dict]:
        """检测算法模式"""
        algorithms = []
        
        # 检测XOR循环（可能是加密）
        xor_count = 0
        loop_detected = False
        for instr in instructions: 
            if instr.mnemonic == 'xor' and 'eax' not in instr.op_str. lower():
                xor_count += 1
            if instr.mnemonic in ['loop', 'loope', 'loopne']:
                loop_detected = True
            if instr.is_conditional and instr.branch_target and instr.branch_target < instr.address:
                loop_detected = True
        
        if xor_count > 5 and loop_detected:
            algorithms.append({
                'name': 'XOR加密/解密',
                'confidence': 'HIGH' if xor_count > 10 else 'MEDIUM',
                'indicators': f'{xor_count}个XOR操作，存在循环',
                'description':  '可能是简单的XOR加密算法'
            })
        
        # 检测移位操作
        shift_ops = sum(1 for i in instructions if i. mnemonic in ['shl', 'shr', 'rol', 'ror', 'sar'])
        if shift_ops > 10:
            algorithms.append({
                'name': '位操作密集算法',
                'confidence': 'MEDIUM',
                'indicators': f'{shift_ops}个移位操作',
                'description': '可能是哈希函数或复杂加密'
            })
        
        # 检测字符串操作
        string_ops = sum(1 for i in instructions if i.instruction_type == InstructionType.STRING)
        if string_ops > 5:
            algorithms.append({
                'name': '字符串处理',
                'confidence':  'HIGH',
                'indicators':  f'{string_ops}个字符串操作',
                'description': '字符串复制/比较/搜索'
            })
        
        # 检测数学运算
        math_ops = sum(1 for i in instructions 
                      if i.mnemonic in ['add', 'adc', 'mul', 'imul', 'div', 'idiv'])
        if math_ops > 20:
            algorithms. append({
                'name': '数学计算',
                'confidence': 'MEDIUM',
                'indicators': f'{math_ops}个数学运算',
                'description': '可能是校验和或数值计算'
            })
        
        return algorithms
    
    def _identify_data_structures(self, instructions: List[Instruction]) -> List[Dict]:
        """识别数据结构"""
        structures = []
        
        # 检测数组访问模式
        array_patterns = 0
        for instr in instructions:
            if re.search(r'\[.*\+.*\*[1248]\]', instr. op_str):
                array_patterns += 1
            elif re.search(r'\[.*\+\s*0x[0-9a-f]+\]', instr.op_str):
                array_patterns += 1
        
        if array_patterns > 5:
            structures. append({
                'type': 'array',
                'confidence': 'HIGH' if array_patterns > 15 else 'MEDIUM',
                'indicators': f'{array_patterns}个数组访问模式',
                'description': '检测到数组或结构体数组访问'
            })
        
        # 检测链表操作
        deref_chain = 0
        for i, instr in enumerate(instructions):
            if instr.mnemonic == 'mov' and '[' in instr. op_str: 
                if i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    if next_instr.mnemonic == 'mov' and '[' in next_instr. op_str: 
                        deref_chain += 1
        
        if deref_chain > 3:
            structures. append({
                'type': 'linked_structure',
                'confidence': 'MEDIUM',
                'indicators': f'{deref_chain}个连续指针解引用',
                'description': '可能是链表或树结构遍历'
            })
        
        # 检测栈帧结构
        stack_access = 0
        for instr in instructions:
            if re.search(r'\[e? [sb]p[+-]', instr.op_str):
                stack_access += 1
        
        if stack_access > 10:
            structures. append({
                'type': 'local_variables',
                'confidence': 'HIGH',
                'indicators':  f'{stack_access}个栈访问',
                'description': '函数使用多个局部变量'
            })
        
        return structures
    
    def _generate_decompilation_hints(self, functions: Dict[int, Function]) -> List[Dict]:
        """生成反编译提示"""
        hints = []
        
        for addr, func in list(functions.items())[:10]: 
            hint = {
                'function': func.name,
                'address':  hex(func.address),
                'estimated_complexity': 'unknown',
                'pseudocode_structure': [],
                'variable_hints': []
            }
            
            if func.basic_blocks:
                has_loop = any(bb.loop_header for bb in func.basic_blocks)
                has_branch = len(func.basic_blocks) > 1
                
                if has_loop: 
                    hint['pseudocode_structure']. append('包含循环结构 (while/for)')
                if has_branch: 
                    hint['pseudocode_structure']. append('包含条件分支 (if/else)')
                if len(func.calls) > 0:
                    hint['pseudocode_structure'].append(f'调用 {len(func. calls)} 个其他函数')
                
                bb_count = len(func.basic_blocks)
                if bb_count > 10:
                    hint['estimated_complexity'] = 'HIGH'
                elif bb_count > 3:
                    hint['estimated_complexity'] = 'MEDIUM'
                else: 
                    hint['estimated_complexity'] = 'LOW'
            
            hints. append(hint)
        
        return hints


class BehaviorAnalyst(AICodeAnalyst):
    """行为分析师 - 分析程序运行时行为"""
    
    def __init__(self, ollama: OllamaClient = None):
        super().__init__("行为分析师", "程序行为预测和恶意代码分析专家", ollama)
        self.system_prompt = """你是一位专业的程序行为分析师，擅长预测程序的运行时行为。
你的任务是：
1. 分析程序的API调用模式
2. 预测程序的行为和目的
3. 识别可疑或恶意行为
4. 评估程序的安全风险

请用中文回答，保持专业简洁。"""
    
    def analyze(self, data:  Dict[str, Any]) -> Dict[str, Any]:
        result = {
            'analyst': self. name,
            'analysis_type': 'behavior',
            'predicted_behaviors': [],
            'api_usage_analysis': {},
            'suspicious_behaviors': [],
            'behavior_timeline': [],
            'llm_insight': None
        }
        
        instructions = data.get('instructions', [])
        imports = data.get('imports', [])
        functions = data.get('functions', {})
        
        result['api_usage_analysis'] = self._analyze_api_usage(imports)
        result['predicted_behaviors'] = self._predict_behaviors(imports, instructions)
        result['suspicious_behaviors'] = self._identify_suspicious(imports, instructions)
        result['behavior_timeline'] = self._create_behavior_timeline(
            instructions, imports, functions
        )
        
        # LLM深度分析
        if self.ollama and self.ollama.is_available() and imports:
            behavior_context = self._build_behavior_context(imports, result)
            question = "请分析这些API调用模式，预测程序的主要行为，并识别任何可疑活动。"
            
            llm_response = self._get_llm_insight(behavior_context, question)
            if llm_response: 
                result['llm_insight'] = llm_response
        
        return result
    
    def _build_behavior_context(self, imports: List[Dict], result:  Dict) -> str:
        """构建行为分析上下文"""
        lines = ["## 导入的API函数\n"]
        
        by_dll = defaultdict(list)
        for imp in imports:
            by_dll[imp. get('dll', 'unknown')].append(imp. get('function', ''))
        
        for dll, funcs in list(by_dll. items())[:5]:
            lines.append(f"### {dll}")
            for func in funcs[: 10]:
                lines. append(f"- {func}")
            lines.append("")
        
        if result.get('suspicious_behaviors'):
            lines.append("## 检测到的可疑行为\n")
            for sb in result['suspicious_behaviors'][:5]: 
                lines.append(f"- {sb. get('type', '')}: {sb.get('description', '')}")
        
        return '\n'.join(lines)
    
    def _analyze_api_usage(self, imports: List[Dict]) -> Dict: 
        """分析API使用模式"""
        categories = defaultdict(list)
        
        api_categories = {
            'file':  ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'FindFirstFile'],
            'network':  ['socket', 'connect', 'send', 'recv', 'WSA', 'Internet', 'Http'],
            'process': ['CreateProcess', 'OpenProcess', 'VirtualAlloc', 'WriteProcessMemory'],
            'registry':  ['RegOpen', 'RegCreate', 'RegSet', 'RegQuery', 'RegDelete'],
            'crypto': ['Crypt', 'BCrypt', 'Hash'],
            'ui': ['MessageBox', 'CreateWindow', 'ShowWindow', 'GetDlgItem'],
            'memory': ['malloc', 'free', 'HeapAlloc', 'VirtualAlloc', 'GlobalAlloc'],
            'thread': ['CreateThread', 'ExitThread', 'WaitForSingleObject', 'SetEvent'],
        }
        
        for imp in imports: 
            func = imp.get('function', '')
            for category, keywords in api_categories. items():
                if any(kw. lower() in func.lower() for kw in keywords):
                    categories[category]. append(func)
                    break
        
        primary = 'unknown'
        if categories: 
            primary = max(categories.keys(), key=lambda k: len(categories[k]))
        
        return {
            'categories': dict(categories),
            'primary_functionality': primary,
            'api_diversity': len(categories),
            'total_apis': len(imports)
        }
    
    def _predict_behaviors(self, imports: List[Dict],
                          instructions: List[Instruction]) -> List[Dict]:
        """预测程序行为"""
        behaviors = []
        import_names = [imp.get('function', '').lower() for imp in imports]
        import_text = ' '.join(import_names)
        
        behavior_patterns = [
            (['createfile', 'writefile', 'deletefile'], '文件操作', '程序会创建、修改或删除文件'),
            (['socket', 'connect', 'wsastartup', 'internetopen'], '网络通信', '程序会进行网络连接'),
            (['createprocess', 'openprocess', 'writeprocessmemory'], '进程操作', '程序会创建或操作其他进程'),
            (['regopen', 'regset', 'regcreate'], '注册表修改', '程序会修改Windows注册表'),
            (['crypt', 'bcrypt', 'hash'], '加密/解密', '程序使用加密功能'),
            (['messagebox', 'createwindow', 'getdc', 'bitblt'], 'UI交互', '程序有用户界面'),
        ]
        
        for keywords, btype, desc in behavior_patterns:
            if any(kw in import_text for kw in keywords):
                behaviors.append({
                    'type': btype,
                    'confidence': 'HIGH',
                    'description': desc,
                    'indicators': [kw for kw in keywords if kw in import_text]
                })
        
        return behaviors
    
    def _identify_suspicious(self, imports: List[Dict],
                            instructions: List[Instruction]) -> List[Dict]:
        """识别可疑行为"""
        suspicious = []
        import_names = [imp.get('function', '').lower() for imp in imports]
        import_text = ' '.join(import_names)
        
        suspicious_patterns = [
            (['isdebuggerpresent', 'checkremotedebuggerpresent', 
              'ntqueryinformationprocess', 'outputdebugstring'],
             '反调试', 'MEDIUM', '程序包含反调试检测', '修改检测函数返回值或NOP掉检测代码'),
            (['virtualallocex', 'writeprocessmemory', 'createremotethread',
              'ntunmapviewofsection'],
             '代码注入', 'HIGH', '程序可能进行代码注入', 'NOP掉注入相关调用'),
            (['setwindowshookex', 'getasynckeystate', 'getkeystate', 'getkeyboardstate'],
             '键盘监控', 'HIGH', '程序可能记录键盘输入', 'NOP掉钩子安装代码'),
            (['createservice', 'openservice', 'startservice', 'controlservice'],
             '服务操作', 'MEDIUM', '程序操作Windows服务', '检查服务创建/启动逻辑'),
        ]
        
        for apis, stype, severity, desc, bypass in suspicious_patterns: 
            found = [api for api in apis if api in import_text]
            if len(found) >= (2 if stype == '代码注入' else 1):
                suspicious. append({
                    'type': stype,
                    'severity': severity,
                    'apis': found,
                    'description': desc,
                    'bypass_suggestion': bypass
                })
        
        return suspicious
    
    def _create_behavior_timeline(self, instructions: List[Instruction],
                                  imports: List[Dict],
                                  functions: Dict[int, Function]) -> List[Dict]:
        """创建行为时间线"""
        timeline = []
        
        call_sequence = []
        for instr in instructions: 
            if instr. is_call:
                call_sequence.append({
                    'address': hex(instr.address),
                    'target': instr.op_str
                })
        
        for i, call in enumerate(call_sequence[: 20]):
            timeline.append({
                'order': i + 1,
                'address': call['address'],
                'action': f"调用 {call['target']}",
                'significance': 'NORMAL'
            })
        
        return timeline

# ============================================================================
# AI团队管理器
# ============================================================================

class AITeamManager:
    """AI团队管理器"""
    
    def __init__(self, ollama_url: str = None, model:  str = None, use_llm: bool = True):
        """
        初始化AI团队管理器
        
        Args:
            ollama_url: Ollama服务地址
            model:  模型名称
            use_llm: 是否使用LLM
        """
        self.use_llm = use_llm
        self.ollama = None
        
        if use_llm: 
            self.ollama = OllamaClient(ollama_url, model)
            if not self.ollama.is_available():
                print("[AITeam] Ollama不可用，将使用基础分析模式")
                self. ollama = None
        
        # 创建分析师团队
        self. analysts = {
            'logic': LogicAnalyst(self. ollama),
            'security': SecurityAnalyst(self.ollama),
            'patch': PatchExpert(self.ollama),
            'reverse': ReverseEngineer(self. ollama),
            'behavior': BehaviorAnalyst(self.ollama)
        }
        self.analysis_results = {}
    
    def run_full_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]: 
        """运行完整的AI团队分析"""
        print("\n" + "="*70)
        print("🤖 AI团队分析开始")
        if self.ollama and self.ollama.is_available():
            print(f"   LLM模式:  {self.ollama.model}")
        else:
            print("   基础分析模式 (无LLM)")
        print("="*70)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'llm_enabled': self.ollama is not None and self.ollama. is_available(),
            'llm_model': self.ollama.model if self.ollama else None,
            'team_analysis': {},
            'consensus': {},
            'recommendations': []
        }
        
        # 逐个运行分析师
        for name, analyst in self. analysts.items():
            print(f"\n[*] {analyst.name} 正在分析...")
            try:
                analysis = analyst.analyze(data)
                results['team_analysis'][name] = analysis
                
                # 显示LLM洞察状态
                if analysis.get('llm_insight'):
                    print(f"    ✓ {analyst.name} 完成 (含LLM洞察)")
                else:
                    print(f"    ✓ {analyst.name} 完成")
                    
            except Exception as e: 
                print(f"    ✗ {analyst.name} 失败:  {e}")
                results['team_analysis'][name] = {'error': str(e)}
        
        # 将安全分析结果传递给补丁专家
        if 'security' in results['team_analysis']:
            data['security_analysis'] = results['team_analysis']['security']
            results['team_analysis']['patch'] = self. analysts['patch'].analyze(data)
        
        # 生成共识
        results['consensus'] = self._build_consensus(results['team_analysis'])
        
        # 生成最终建议
        results['recommendations'] = self._generate_recommendations(results)
        
        # 如果有LLM，生成综合洞察
        if self.ollama and self.ollama. is_available():
            results['llm_summary'] = self._generate_llm_summary(results)
        
        self.analysis_results = results
        return results
    
    def _build_consensus(self, team_analysis: Dict) -> Dict: 
        """建立团队共识"""
        consensus = {
            'overall_assessment': '',
            'key_findings': [],
            'priority_targets': [],
            'risk_level': 'UNKNOWN'
        }
        
        all_findings = []
        
        # 从安全分析收集
        security = team_analysis.get('security', {})
        if security. get('bypass_opportunities'):
            for opp in security['bypass_opportunities'][:5]:
                all_findings.append({
                    'source': '安全分析师',
                    'finding': f"绕过机会: {opp. get('target', 'unknown')} @ {opp.get('bypass_address', 'N/A')}",
                    'priority': 'HIGH'
                })
        
        if security.get('dangerous_imports'):
            for imp in security['dangerous_imports'][:3]:
                if imp.get('is_security_check'):
                    all_findings.append({
                        'source': '安全分析师',
                        'finding': f"安全检查: {imp.get('function', '')} - {imp.get('purpose', '')}",
                        'priority':  'MEDIUM'
                    })
        
        # 从逆向分析收集
        reverse = team_analysis.get('reverse', {})
        if reverse.get('algorithms_detected'):
            for algo in reverse['algorithms_detected']: 
                all_findings.append({
                    'source': '逆向工程师',
                    'finding': f"检测到算法: {algo. get('name', 'unknown')}",
                    'priority': 'MEDIUM'
                })
        
        # 从行为分析收集
        behavior = team_analysis.get('behavior', {})
        if behavior.get('suspicious_behaviors'):
            for sus in behavior['suspicious_behaviors']: 
                all_findings.append({
                    'source': '行为分析师',
                    'finding': f"可疑行为:  {sus.get('type', 'unknown')}",
                    'priority': sus.get('severity', 'MEDIUM')
                })
        
        consensus['key_findings'] = all_findings[: 15]
        
        # 确定优先级目标
        patch = team_analysis.get('patch', {})
        if patch. get('modification_plan'):
            for step in patch['modification_plan'][:5]:
                consensus['priority_targets'].append({
                    'address': step. get('target', 'N/A'),
                    'action': step.get('action', ''),
                    'expected_effect': step.get('expected_effect', '')
                })
        
        # 计算整体风险级别
        risk = security.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        consensus['risk_level'] = risk
        
        # 生成整体评估
        high_findings = sum(1 for f in all_findings if f['priority'] == 'HIGH')
        consensus['overall_assessment'] = self._generate_assessment(
            high_findings, len(consensus['priority_targets']), risk
        )
        
        return consensus
    
    def _generate_assessment(self, high_findings: int, targets: int, risk:  str) -> str:
        """生成整体评估"""
        if risk == 'CRITICAL' or high_findings > 5:
            return "程序包含多个高优先级修改点，建议按计划逐步修改并测试"
        elif risk == 'HIGH' or high_findings > 2:
            return "发现若干可修改点，可以尝试绕过主要保护机制"
        elif targets > 0:
            return "存在一些可修改点，风险较低"
        else: 
            return "未发现明显的修改机会，可能需要更深入的分析"
    
    def _generate_recommendations(self, results:  Dict) -> List[Dict]:
        """生成最终建议"""
        recommendations = []
        
        consensus = results.get('consensus', {})
        team_analysis = results. get('team_analysis', {})
        
        # 基于优先级目标生成建议
        for target in consensus. get('priority_targets', [])[:3]:
            recommendations.append({
                'priority': 1,
                'type': 'patch',
                'action': target.get('action', ''),
                'target': target.get('address', ''),
                'expected_result': target.get('expected_effect', ''),
                'risk':  'MEDIUM'
            })
        
        # 基于可疑行为生成建议
        behavior = team_analysis. get('behavior', {})
        for sus in behavior.get('suspicious_behaviors', [])[:2]:
            recommendations. append({
                'priority': 2,
                'type':  'investigate',
                'action': f"调查 {sus.get('type', '')} 相关代码",
                'target': ', '.join(sus. get('apis', [])[:3]),
                'expected_result': sus. get('bypass_suggestion', ''),
                'risk':  sus.get('severity', 'MEDIUM')
            })
        
        recommendations.sort(key=lambda x: x['priority'])
        
        return recommendations
    
    def _generate_llm_summary(self, results: Dict) -> Optional[str]:
        """使用LLM生成综合摘要"""
        if not self.ollama or not self. ollama.is_available():
            return None
        
        # 收集所有LLM洞察
        insights = []
        for name, analysis in results. get('team_analysis', {}).items():
            if analysis. get('llm_insight'):
                insights.append(f"## {analysis. get('analyst', name)}的分析\n{analysis['llm_insight']}")
        
        if not insights:
            return None
        
        context = '\n\n'.join(insights)
        
        system_prompt = """你是一位资深的逆向工程团队负责人。
请综合团队成员的分析结果，生成一份简洁的执行摘要。
重点关注：
1. 最关键的发现
2. 最佳的修改策略
3. 风险评估和建议

请用中文回答，保持简洁专业。"""
        
        try: 
            summary = self.ollama.generate(
                f"请综合以下分析结果，生成执行摘要：\n\n{context}",
                system=system_prompt,
                max_tokens=1024
            )
            return summary
        except Exception as e:
            print(f"[AITeam] 生成LLM摘要失败: {e}")
            return None
    
    def generate_report(self, output_path: str = None, analyzer_data: Dict = None) -> str:
        """生成分析报告"""
        if not self.analysis_results:
            return "没有分析结果"
        
        results = self.analysis_results
        
        if analyzer_data is None:
            analyzer_data = {}
        
        report = f"""# 🤖 AI团队反汇编分析报告

**生成时间**:  {results. get('timestamp', 'N/A')}
**LLM模式**: {'启用 (' + results.get('llm_model', '') + ')' if results.get('llm_enabled') else '禁用'}

---

## 📊 团队共识

**整体评估**: {results['consensus']. get('overall_assessment', 'N/A')}

**风险级别**: {results['consensus'].get('risk_level', 'UNKNOWN')}

### 关键发现

| 来源 | 发现 | 优先级 |
|------|------|--------|
"""
        
        for finding in results['consensus']. get('key_findings', [])[:10]:
            report += f"| {finding['source']} | {finding['finding']} | {finding['priority']} |\n"
        
        report += f"""
### 优先修改目标

| 地址 | 操作 | 预期效果 |
|------|------|----------|
"""
        
        for target in results['consensus'].get('priority_targets', []):
            report += f"| {target['address']} | {target['action']} | {target['expected_effect']} |\n"
        
        # LLM综合摘要
        if results.get('llm_summary'):
            report += f"""
---

## 🧠 AI综合分析

{results['llm_summary']}
"""
        
        report += f"""
---

## 🔧 修改建议

"""
        
        for i, rec in enumerate(results. get('recommendations', []), 1):
            report += f"""### 建议 {i}:  {rec['action']}

- **目标**: {rec['target']}
- **预期结果**: {rec['expected_result']}
- **风险**: {rec['risk']}

"""
        
        # 各分析师详细报告
        report += """
---

## 📋 详细分析报告

"""
        
        # 添加各分析师的LLM洞察
        for name, analysis in results.get('team_analysis', {}).items():
            if analysis.get('llm_insight'):
                analyst_name = analysis.get('analyst', name)
                report += f"""### 💡 {analyst_name}的AI洞察

{analysis['llm_insight']}

"""
        
        # 安全分析
        security = results['team_analysis'].get('security', {})
        if security and not security.get('error'):
            report += f"""### 🔒 安全分析

**危险导入**: {len(security.get('dangerous_imports', []))} 个
**安全检查点**: {len(security.get('security_checks', []))} 个
**绕过机会**: {len(security.get('bypass_opportunities', []))} 个

"""
            for opp in security.get('bypass_opportunities', [])[:5]:
                report += f"- **{opp. get('target', '')}** @ {opp.get('bypass_address', '')} - {opp.get('method', '')}\n"
        
        # 行为分析
        behavior = results['team_analysis']. get('behavior', {})
        if behavior and not behavior.get('error'):
            report += f"""
### 🎯 行为分析

**预测行为**:
"""
            for b in behavior.get('predicted_behaviors', []):
                report += f"- {b. get('type', '')}: {b.get('description', '')}\n"
            
            if behavior.get('suspicious_behaviors'):
                report += f"""
**可疑行为**: 
"""
                for s in behavior['suspicious_behaviors']: 
                    report += f"- ⚠️ **{s.get('type', '')}** ({s.get('severity', '')}): {s.get('description', '')}\n"
        
        # 逆向分析
        reverse = results['team_analysis'].get('reverse', {})
        if reverse and not reverse.get('error'):
            report += f"""
### 🔍 逆向分析

**代码复杂度**: {reverse.get('code_understanding', {}).get('control_flow_complexity', 'N/A')}

**检测到的算法**:
"""
            for algo in reverse. get('algorithms_detected', []):
                report += f"- {algo.get('name', '')}: {algo.get('description', '')}\n"
        
        # 生成时间戳用于文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_path: 
            os.makedirs(output_path, exist_ok=True)
            report_path = os.path.join(output_path, f"report_{timestamp}.md")
            json_path = os.path.join(output_path, f"analysis_{timestamp}.json")
        else:
            report_path = f"report_{timestamp}.md"
            json_path = f"analysis_{timestamp}.json"
        
        # 保存Markdown报告
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n[*] 报告已保存:  {report_path}")
        
        # 保存JSON数据
        if analyzer_data:
            json_data = {
                'timestamp': timestamp,
                'file_path': analyzer_data.get('file_path', 'N/A'),
                'file_hash': analyzer_data. get('file_hash', 'N/A'),
                'llm_enabled': results.get('llm_enabled', False),
                'llm_model':  results.get('llm_model'),
                'statistics': {
                    'instructions':  len(analyzer_data. get('instructions', [])),
                    'basic_blocks': len(analyzer_data.get('basic_blocks', {})),
                    'functions': len(analyzer_data.get('functions', {})),
                    'imports': len(analyzer_data.get('imports', [])),
                    'exports': len(analyzer_data.get('exports', [])),
                    'patch_points': len(analyzer_data.get('patch_points', []))
                },
                'ai_consensus': self. analysis_results.get('consensus', {}),
                'llm_summary': results.get('llm_summary')
            }
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json. dump(json_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"[*] JSON结果已保存:  {json_path}")
        
        return report_path

# ============================================================================
# AI反汇编分析器主类
# ============================================================================

class AIDisassemblyAnalyzer:
    """AI反汇编分析器 - 整合所有分析组件的主类"""
    
    def __init__(self, file_path:  str, ollama_url: str = None, 
                 model:  str = None, use_llm: bool = True):
        """
        初始化分析器
        
        Args:
            file_path: PE文件路径
            ollama_url: Ollama服务地址
            model: 模型名称
            use_llm: 是否使用LLM
        """
        self.file_path = file_path
        self.file_data = None  # 修复：添加file_data属性
        self.pe = None
        self.instructions = []
        self.functions = {}
        self.imports = []
        self.exports = []
        self. patch_points = []
        
        # Ollama配置
        self. ollama_url = ollama_url
        self.model = model
        self. use_llm = use_llm
        
        # 分析引擎
        self.disasm_engine = DisassemblyEngine()
        self.ai_team = None  # 延迟初始化
        
        # 这些分析器会在有数据后才初始化
        self.control_flow = None
        self.data_flow = None
        self.semantic = None
        self.patch_analyzer = None
        
        self.analysis_results = {}
    
    def load(self) -> bool:
        """加载PE文件"""
        if not os.path. exists(self.file_path):
            print(f"文件不存在: {self.file_path}")
            return False
        
        # 读取原始文件数据（修复：添加file_data读取）
        try: 
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            print(f"[*] 已读取文件: {len(self.file_data):,} 字节")
        except Exception as e:
            print(f"读取文件失败: {e}")
            return False
        
        # 解析PE结构
        if not HAS_PEFILE:
            print("警告: pefile未安装，无法解析PE结构")
            return True  # 仍然可以进行基础分析
        
        try:
            self.pe = pefile.PE(self.file_path)
            
            # 确定架构
            if self.pe.FILE_HEADER.Machine == 0x8664:
                self.disasm_engine = DisassemblyEngine('x86', '64')
                print("[*] 检测到64位PE文件")
            else:
                self. disasm_engine = DisassemblyEngine('x86', '32')
                print("[*] 检测到32位PE文件")
            
            # 解析导入表
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe. DIRECTORY_ENTRY_IMPORT: 
                    dll_name = entry. dll.decode('utf-8') if isinstance(entry. dll, bytes) else entry.dll
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp. name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                        else:
                            func_name = f"Ordinal_{imp.ordinal}"
                        self.imports.append({
                            'dll': dll_name,
                            'function': func_name,
                            'address': hex(imp.address) if imp.address else None
                        })
                print(f"[*] 解析到 {len(self. imports)} 个导入函数")
            
            # 解析导出表
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe. DIRECTORY_ENTRY_EXPORT. symbols:
                    if exp.name:
                        func_name = exp.name. decode('utf-8') if isinstance(exp.name, bytes) else exp.name
                    else: 
                        func_name = f"Ordinal_{exp.ordinal}"
                    self.exports.append({
                        'name': func_name,
                        'address': hex(self.pe. OPTIONAL_HEADER. ImageBase + exp. address) if exp.address else None,
                        'ordinal': exp.ordinal
                    })
                print(f"[*] 解析到 {len(self.exports)} 个导出函数")
            
            return True
            
        except Exception as e: 
            print(f"解析PE文件失败: {e}")
            return False
    
    def disassemble(self):
        """执行反汇编"""
        if not self.pe and not self.file_data:
            print("请先加载文件")
            return
        
        code_data = None
        base_addr = 0
        
        if self.pe:
            # 获取代码段
            for section in self.pe.sections:
                if section. Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    code_data = section.get_data()
                    base_addr = self.pe. OPTIONAL_HEADER. ImageBase + section.VirtualAddress
                    section_name = section.Name. decode('utf-8').strip('\x00')
                    print(f"[*] 反汇编代码段: {section_name} @ 0x{base_addr:x}")
                    break
            
            if not code_data: 
                # 如果没有找到可执行段，使用入口点所在的段
                entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                for section in self.pe.sections:
                    if section.VirtualAddress <= entry_rva < section. VirtualAddress + section. Misc_VirtualSize:
                        code_data = section.get_data()
                        base_addr = self. pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                        break
        else:
            # 没有PE解析，尝试直接反汇编
            code_data = self. file_data
            base_addr = 0
        
        if code_data:
            self.instructions = self.disasm_engine.disassemble(code_data, base_addr)
            print(f"[*] 反汇编完成: {len(self.instructions)} 条指令")
        else:
            print("未找到可执行代码")
    
    def analyze_control_flow(self):
        """分析控制流"""
        if not self.instructions:
            print("请先执行反汇编")
            return
        
        self.control_flow = ControlFlowAnalyzer(self.instructions)
        self.control_flow.build_basic_blocks()
        self.functions = self.control_flow.identify_functions()
        
        print(f"[*] 识别到 {len(self.control_flow.basic_blocks)} 个基本块")
        print(f"[*] 识别到 {len(self.functions)} 个函数")
    
    def analyze_data_flow(self):
        """分析数据流"""
        if not self.control_flow or not self.control_flow.basic_blocks:
            print("请先分析控制流")
            return
        
        self.data_flow = DataFlowAnalyzer(self.control_flow.basic_blocks)
        self.data_flow.analyze_definitions_and_uses()
        self.data_flow. compute_liveness()
        
        dead_code = self. data_flow.find_dead_code()
        if dead_code:
            print(f"[*] 发现 {len(dead_code)} 条潜在死代码")
    
    def analyze_semantics(self):
        """语义分析"""
        if not self. functions:
            print("请先分析控制流")
            return
        
        self.semantic = SemanticAnalyzer(self.functions, self.imports)
        
        suspicious_count = 0
        for func in self.functions.values():
            func. ai_analysis = self.semantic. analyze_function_purpose(func)
            if func.ai_analysis.get('is_suspicious'):
                suspicious_count += 1
        
        print(f"[*] 语义分析完成，发现 {suspicious_count} 个可疑函数")
    
    def find_patch_points(self):
        """查找可修改点"""
        if not self.instructions:
            print("请先执行反汇编")
            return
        
        self.patch_analyzer = PatchAnalyzer(self. instructions, self.disasm_engine)
        self.patch_points = self.patch_analyzer.find_patch_points()
        
        # 按类型统计
        type_counts = defaultdict(int)
        for pp in self.patch_points:
            type_counts[pp. patch_type] += 1
        
        print(f"[*] 找到 {len(self.patch_points)} 个可修改点:")
        for ptype, count in type_counts.items():
            print(f"    - {ptype}: {count}")
    
    def run_ai_analysis(self) -> Dict:
        """运行AI团队分析（修复：添加此方法）"""
        if not self.instructions:
            print("请先执行基础分析")
            return {}
        
        # 初始化AI团队（如果还没有）
        if not self.ai_team:
            self.ai_team = AITeamManager(
                ollama_url=self.ollama_url,
                model=self.model,
                use_llm=self.use_llm
            )
        
        # 准备分析数据
        analysis_data = {
            'instructions': self.instructions,
            'basic_blocks': self.control_flow.basic_blocks if self.control_flow else {},
            'functions':  self.functions,
            'imports': self.imports,
            'exports': self. exports,
            'patch_points': self.patch_points
        }
        
        # 运行分析
        self.analysis_results = self.ai_team.run_full_analysis(analysis_data)
        
        return self.analysis_results
    
    def full_analysis(self) -> Dict:
        """执行完整分析"""
        print("\n" + "="*70)
        print("🔬 开始完整分析")
        print("="*70)
        
        if not self.load():
            return {}
        
        print("\n[*] 开始反汇编...")
        self.disassemble()
        
        if not self.instructions:
            print("反汇编失败，无法继续")
            return {}
        
        print("\n[*] 分析控制流...")
        self.analyze_control_flow()
        
        print("\n[*] 分析数据流...")
        self.analyze_data_flow()
        
        print("\n[*] 语义分析...")
        self.analyze_semantics()
        
        print("\n[*] 查找可修改点...")
        self.find_patch_points()
        
        print("\n[*] 启动AI团队分析...")
        self.analysis_results = self. run_ai_analysis()
        
        return self.analysis_results
    
    def generate_report(self, output_path: str = None) -> str:
        """生成分析报告"""
        if not self. ai_team:
            print("请先运行分析")
            return ""
        
        # 计算文件哈希
        file_hash = 'N/A'
        if self.file_data:
            file_hash = hashlib.sha256(self.file_data).hexdigest()
        
        # 准备分析器数据
        analyzer_data = {
            'file_path': self.file_path,
            'file_hash': file_hash,
            'instructions': self.instructions,
            'basic_blocks': self.control_flow.basic_blocks if self.control_flow else {},
            'functions': self.functions,
            'imports': self. imports,
            'exports': self.exports,
            'patch_points': self. patch_points
        }
        
        return self.ai_team.generate_report(output_path, analyzer_data)
    
    def get_basic_blocks(self) -> Dict[int, BasicBlock]:
        """获取基本块（修复：添加此方法）"""
        if self.control_flow:
            return self. control_flow.basic_blocks
        return {}
    
    def get_function_at(self, address: int) -> Optional[Function]:
        """获取指定地址的函数"""
        for func in self.functions.values():
            if func.address <= address < func.end_address:
                return func
        return None
    
    def get_instruction_at(self, address: int) -> Optional[Instruction]: 
        """获取指定地址的指令"""
        for instr in self.instructions:
            if instr.address == address:
                return instr
        return None
    
    def search_instructions(self, pattern: str) -> List[Instruction]:
        """搜索指令"""
        pattern = pattern.lower()
        results = []
        for instr in self. instructions:
            full_instr = f"{instr.mnemonic} {instr.op_str}". lower()
            if pattern in full_instr:
                results.append(instr)
        return results
    
    def extract_strings(self, min_length: int = 4) -> List[Tuple[int, str]]: 
        """提取字符串"""
        if not self.file_data:
            return []
        
        strings = []
        current = b""
        start_offset = 0
        
        for i, byte in enumerate(self.file_data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    start_offset = i
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    try:
                        strings.append((start_offset, current.decode('ascii')))
                    except: 
                        pass
                current = b""
        
        # 处理最后一个字符串
        if len(current) >= min_length:
            try:
                strings.append((start_offset, current.decode('ascii')))
            except:
                pass
        
        return strings

# ============================================================================
# 交互式分析器
# ============================================================================

class InteractiveAnalyzer:
    """交互式反汇编分析器"""
    
    def __init__(self, ollama_url: str = None, model:  str = None, use_llm:  bool = True):
        self.analyzer = None
        self.current_address = 0
        self.bookmarks = {}
        self.comments = {}
        self.history = []
        
        # Ollama配置
        self.ollama_url = ollama_url
        self.model = model
        self.use_llm = use_llm
    
    def run(self):
        """运行交互式模式"""
        print("\n" + "="*70)
        print("  🔬 AI反汇编交互式分析器")
        print("  输入 'help' 查看命令列表")
        if self.use_llm: 
            print(f"  LLM模式:  启用")
        else: 
            print("  LLM模式: 禁用 (使用 --llm 启用)")
        print("="*70 + "\n")
        
        while True:
            try:
                prompt = f"0x{self.current_address:08x}> " if self.analyzer else "disasm> "
                cmd = input(prompt).strip()
                
                if not cmd: 
                    continue
                
                self.history.append(cmd)
                parts = cmd.split()
                command = parts[0]. lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if command in ['exit', 'quit', 'q']: 
                    print("再见!")
                    break
                elif command == 'help':
                    self._show_help()
                elif command == 'load':
                    self._load_file(args)
                elif command == 'analyze':
                    self._run_analysis()
                elif command == 'disasm': 
                    self._show_disasm(args)
                elif command == 'func':
                    self._show_function(args)
                elif command == 'funcs':
                    self._list_functions()
                elif command == 'imports':
                    self._show_imports(args)
                elif command == 'xref':
                    self._show_xrefs(args)
                elif command == 'patch':
                    self._show_patches(args)
                elif command == 'goto':
                    self._goto_address(args)
                elif command == 'search':
                    self._search(args)
                elif command == 'ai':
                    self._ai_analysis()
                elif command == 'comment':
                    self._add_comment(args)
                elif command == 'bookmark':
                    self._manage_bookmark(args)
                elif command == 'export':
                    self._export_results(args)
                elif command == 'pseudo':
                    self._show_pseudocode(args)
                elif command == 'graph':
                    self._show_cfg(args)
                elif command == 'strings':
                    self._show_strings()
                elif command == 'info':
                    self._show_info()
                elif command == 'llm':
                    self._llm_query(args)
                else:
                    print(f"未知命令: {command}.  输入 'help' 查看帮助.")
                    
            except KeyboardInterrupt: 
                print("\n使用 'exit' 退出")
            except Exception as e: 
                print(f"错误: {e}")
                import traceback
                traceback.print_exc()
    
    def _show_help(self):
        """显示帮助"""
        help_text = """
=== 文件操作 ===
  load <文件>          加载PE文件
  analyze             执行完整分析
  info                显示文件信息
  export [目录]        导出分析结果

=== 反汇编查看 ===
  disasm [地址] [数量]  显示反汇编 (默认当前地址, 20条)
  goto <地址>          跳转到地址
  func [地址/名称]     显示函数详情
  funcs               列出所有函数
  pseudo [地址]        显示伪代码

=== 分析功能 ===
  imports [过滤]       显示导入表
  xref <地址>          显示交叉引用
  patch [类型]         显示可修改点
  search <模式>        搜索指令/字符串
  strings             显示字符串
  graph [地址]         显示控制流图

=== AI分析 ===
  ai                  运行AI团队分析
  llm <问题>           直接询问LLM
  
=== 注释和书签 ===
  comment <地址> <内容>  添加注释
  bookmark [add/del/list] <地址> <名称>  管理书签

=== 其他 ===
  help                显示帮助
  exit/quit           退出
"""
        print(help_text)
    
    def _load_file(self, args:  List[str]):
        """加载文件"""
        if not args:
            print("用法: load <文件路径>")
            return
        
        file_path = ' '.join(args)
        
        if not os. path.exists(file_path):
            print(f"文件不存在:  {file_path}")
            return
        
        self.analyzer = AIDisassemblyAnalyzer(
            file_path,
            ollama_url=self.ollama_url,
            model=self. model,
            use_llm=self.use_llm
        )
        
        if self.analyzer.load():
            print("文件加载成功，使用 'analyze' 执行分析")
            
            if self.analyzer.pe:
                self.current_address = (self.analyzer.pe.OPTIONAL_HEADER.ImageBase +
                                       self.analyzer.pe. OPTIONAL_HEADER.AddressOfEntryPoint)
                print(f"入口点:  0x{self.current_address:08x}")
    
    def _run_analysis(self):
        """执行分析"""
        if not self. analyzer:
            print("请先加载文件:  load <文件>")
            return
        
        self.analyzer.disassemble()
        self.analyzer.analyze_control_flow()
        self.analyzer. analyze_data_flow()
        self.analyzer.analyze_semantics()
        self.analyzer.find_patch_points()
        
        print("\n分析完成!  使用以下命令查看结果:")
        print("  funcs    - 列出函数")
        print("  disasm   - 查看反汇编")
        print("  patch    - 查看可修改点")
        print("  ai       - AI团队分析")
    
    def _show_disasm(self, args: List[str]):
        """显示反汇编"""
        if not self.analyzer or not self.analyzer. instructions:
            print("请先执行分析")
            return
        
        address = self.current_address
        count = 20
        
        if args:
            try: 
                address = int(args[0], 16) if args[0]. startswith('0x') else int(args[0])
            except ValueError:
                print(f"无效地址: {args[0]}")
                return
            
            if len(args) > 1:
                try:
                    count = int(args[1])
                except ValueError:
                    pass
        
        found = False
        displayed = 0
        
        for instr in self.analyzer.instructions:
            if instr.address >= address:
                if not found:
                    found = True
                
                prefix = ""
                if hex(instr.address) in self.bookmarks:
                    prefix = f"📌 [{self.bookmarks[hex(instr. address)]}] "
                
                comment = ""
                if hex(instr.address) in self.comments:
                    comment = f"  ; {self.comments[hex(instr. address)]}"
                
                highlight = ""
                if instr.is_call:
                    highlight = "📞"
                elif instr.is_ret:
                    highlight = "🔙"
                elif instr.is_conditional: 
                    highlight = "🔀"
                elif instr.is_jump:
                    highlight = "➡️"
                
                print(f"{prefix}0x{instr.address:08x}: {instr. bytes.hex(): <20} "
                      f"{instr.mnemonic: <8} {instr.op_str: <30} {highlight}{comment}")
                
                displayed += 1
                if displayed >= count:
                    break
        
        if not found: 
            print(f"未找到地址 0x{address: x} 处的指令")
        else:
            self.current_address = address
    
    def _show_function(self, args: List[str]):
        """显示函数详情"""
        if not self.analyzer or not self.analyzer. functions:
            print("请先执行分析")
            return
        
        func = None
        
        if not args:
            func = self.analyzer. get_function_at(self.current_address)
            if not func: 
                print("当前地址不在任何函数内")
                return
        else:
            query = args[0]
            
            try:
                addr = int(query, 16) if query.startswith('0x') else int(query)
                func = self.analyzer.functions.get(addr)
            except ValueError:
                pass
            
            if not func:
                for f in self.analyzer. functions.values():
                    if query. lower() in f.name.lower():
                        func = f
                        break
            
            if not func:
                print(f"未找到函数:  {query}")
                return
        
        print(f"\n{'='*60}")
        print(f"函数:  {func.name}")
        print(f"{'='*60}")
        print(f"地址:      0x{func. address:08x}")
        print(f"大小:     {func.size} bytes")
        print(f"基本块:   {len(func.basic_blocks)} 个")
        print(f"调用:      {len(func.calls)} 个")
        
        if func.ai_analysis:
            print(f"\nAI分析:")
            print(f"  描述: {func. ai_analysis.get('description', 'N/A')}")
            print(f"  可疑:  {'是' if func.ai_analysis.get('is_suspicious') else '否'}")
            if func.ai_analysis.get('api_categories'):
                print(f"  API类别: {', '. join(func.ai_analysis['api_categories'])}")
        
        if func.llm_analysis:
            print(f"\nLLM分析:")
            print(f"  {func.llm_analysis[: 200]}...")
        
        print(f"\n调用的函数:")
        for call_addr in func.calls[: 10]: 
            target_name = self._resolve_call_target(call_addr)
            print(f"  0x{call_addr:08x}:  {target_name}")
        
        if len(func.calls) > 10:
            print(f"  ... 还有 {len(func.calls) - 10} 个")
    
    def _resolve_call_target(self, address: int) -> str:
        """解析调用目标名称"""
        for imp in self.analyzer. imports:
            imp_addr = imp.get('address')
            if imp_addr: 
                try:
                    if isinstance(imp_addr, str):
                        imp_addr = int(imp_addr, 16)
                    if imp_addr == address: 
                        return f"{imp['dll']}! {imp['function']}"
                except: 
                    pass
        
        if address in self.analyzer.functions:
            return self.analyzer.functions[address].name
        
        return "unknown"
    
    def _list_functions(self):
        """列出所有函数"""
        if not self.analyzer or not self.analyzer.functions:
            print("请先执行分析")
            return
        
        print(f"\n函数列表 ({len(self.analyzer.functions)} 个):\n")
        print(f"{'地址':<14} {'名称':<30} {'大小':<10} {'块数':<8} {'调用数'}")
        print("-" * 75)
        
        for addr, func in sorted(self.analyzer. functions.items()):
            suspicious = "⚠️" if func.ai_analysis.get('is_suspicious') else ""
            print(f"0x{addr: 08x}   {func.name:<30} {func. size: <10} "
                  f"{len(func.basic_blocks):<8} {len(func.calls)} {suspicious}")
    
    def _show_imports(self, args: List[str]):
        """显示导入表"""
        if not self.analyzer:
            print("请先加载文件")
            return
        
        imports = self.analyzer. imports
        filter_text = ' '.join(args).lower() if args else None
        
        if filter_text: 
            imports = [i for i in imports
                      if filter_text in i.get('dll', '').lower()
                      or filter_text in i. get('function', '').lower()]
        
        print(f"\n导入函数 ({len(imports)} 个):\n")
        
        by_dll = defaultdict(list)
        for imp in imports: 
            by_dll[imp['dll']].append(imp)
        
        for dll, funcs in sorted(by_dll.items()):
            print(f"[{dll}] ({len(funcs)} 个)")
            for f in funcs[: 15]: 
                print(f"  {f.get('address', 'N/A')}: {f['function']}")
            if len(funcs) > 15:
                print(f"  ... 还有 {len(funcs) - 15} 个")
            print()
    
    def _show_xrefs(self, args: List[str]):
        """显示交叉引用"""
        if not self.analyzer:
            print("请先执行分析")
            return
        
        if not args:
            print("用法: xref <地址>")
            return
        
        try:
            address = int(args[0], 16) if args[0]. startswith('0x') else int(args[0])
        except ValueError:
            print(f"无效地址: {args[0]}")
            return
        
        print(f"\n交叉引用 0x{address: 08x}:\n")
        
        refs_to = []
        refs_from = []
        
        for instr in self.analyzer.instructions:
            if instr.branch_target == address:
                refs_to.append(instr)
            if instr.address == address and instr.branch_target:
                refs_from.append(instr)
        
        print("引用到此地址:")
        for ref in refs_to[: 20]: 
            print(f"  0x{ref.address:08x}: {ref.mnemonic} {ref.op_str}")
        if not refs_to: 
            print("  (无)")
        
        print("\n从此地址引用:")
        for ref in refs_from[:20]:
            print(f"  -> 0x{ref.branch_target:08x}")
        if not refs_from:
            print("  (无)")
    
    def _show_patches(self, args: List[str]):
        """显示可修改点"""
        if not self.analyzer or not self.analyzer. patch_points:
            print("请先执行分析")
            return
        
        patches = self.analyzer. patch_points
        
        if args:
            filter_type = args[0]. lower()
            patches = [p for p in patches if filter_type in p. patch_type.lower()]
        
        print(f"\n可修改点 ({len(patches)} 个):\n")
        
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        patches = sorted(patches, key=lambda x: risk_order. get(x.risk_level, 4))
        
        for i, patch in enumerate(patches[: 30], 1):
            risk_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW':  '🟢'}.get(
                patch.risk_level, '⚪')
            
            print(f"{i: 3}. {risk_icon} 0x{patch.address:08x} [{patch.patch_type}]")
            print(f"     原始:  {patch.original_instruction}")
            print(f"     描述: {patch. description}")
            
            if patch.suggested_patches:
                print(f"     补丁选项:")
                for j, sugg in enumerate(patch.suggested_patches[: 3], 1):
                    bytes_hex = sugg['bytes'].hex() if sugg. get('bytes') else 'N/A'
                    print(f"       {j}) {sugg['name']}: {bytes_hex}")
            print()
        
        if len(self.analyzer.patch_points) > 30:
            print(f"... 还有 {len(self.analyzer.patch_points) - 30} 个")
    
    def _goto_address(self, args: List[str]):
        """跳转到地址"""
        if not args:
            print("用法: goto <地址>")
            return
        
        try:
            address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
            self.current_address = address
            print(f"跳转到 0x{address:08x}")
            self._show_disasm([])
        except ValueError: 
            print(f"无效地址: {args[0]}")
    
    def _search(self, args: List[str]):
        """搜索"""
        if not self.analyzer or not self.analyzer. instructions:
            print("请先执行分析")
            return
        
        if not args:
            print("用法:  search <模式>")
            return
        
        pattern = ' '.join(args).lower()
        matches = self.analyzer.search_instructions(pattern)
        
        print(f"\n搜索 '{pattern}' 找到 {len(matches)} 个结果:\n")
        
        for instr in matches[:30]:
            print(f"  0x{instr.address:08x}: {instr.mnemonic} {instr.op_str}")
        
        if len(matches) > 30:
            print(f"\n... 还有 {len(matches) - 30} 个结果")
    
    def _ai_analysis(self):
        """运行AI分析"""
        if not self.analyzer:
            print("请先加载并分析文件")
            return
        
        if not self.analyzer. instructions:
            print("请先执行 'analyze' 命令")
            return
        
        results = self.analyzer. run_ai_analysis()
        
        consensus = results.get('consensus', {})
        print(f"\n{'='*60}")
        print("🤖 AI团队分析结果")
        print(f"{'='*60}")
        print(f"\n整体评估:  {consensus.get('overall_assessment', 'N/A')}")
        print(f"风险级别: {consensus.get('risk_level', 'UNKNOWN')}")
        
        print(f"\n关键发现:")
        for finding in consensus.get('key_findings', [])[:5]:
            print(f"  - [{finding['priority']}] {finding['finding']}")
        
        print(f"\n优先修改目标:")
        for target in consensus.get('priority_targets', [])[:5]:
            print(f"  - {target['address']}:  {target['action']}")
        
        if results.get('llm_summary'):
            print(f"\n🧠 LLM综合分析:")
            print(results['llm_summary'][:500])
            if len(results. get('llm_summary', '')) > 500:
                print("...")
        
        print(f"\n使用 'export' 命令保存完整报告")
    
    def _llm_query(self, args: List[str]):
        """直接询问LLM"""
        if not args:
            print("用法: llm <问题>")
            return
        
        if not self.analyzer or not self.analyzer. ai_team:
            print("请先运行AI分析")
            return
        
        ollama = self.analyzer.ai_team.ollama
        if not ollama or not ollama.is_available():
            print("LLM不可用")
            return
        
        question = ' '.join(args)
        
        # 构建上下文
        context = ""
        if self. analyzer.instructions:
            context = "当前分析的代码:\n"
            # 获取当前地址附近的指令
            nearby = []
            for instr in self.analyzer. instructions:
                if abs(instr.address - self.current_address) < 0x100:
                    nearby.append(f"0x{instr.address:08x}: {instr.mnemonic} {instr.op_str}")
            context += '\n'.join(nearby[: 20])
        
        print("正在查询LLM...")
        response = ollama. analyze_code(context, question, "逆向工程专家")
        
        if response: 
            print(f"\n🤖 LLM回答:\n")
            print(response)
        else:
            print("LLM查询失败")
    
    def _add_comment(self, args: List[str]):
        """添加注释"""
        if len(args) < 2:
            print("用法: comment <地址> <内容>")
            return
        
        try:
            address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
            comment = ' '.join(args[1:])
            self.comments[hex(address)] = comment
            print(f"注释已添加: 0x{address:08x} ; {comment}")
        except ValueError:
            print(f"无效地址: {args[0]}")
    
    def _manage_bookmark(self, args: List[str]):
        """管理书签"""
        if not args:
            if self.bookmarks:
                print("\n书签列表:")
                for addr, name in self.bookmarks.items():
                    print(f"  {addr}:  {name}")
            else:
                print("无书签")
            return
        
        action = args[0]. lower()
        
        if action == 'add' and len(args) >= 3:
            try:
                address = int(args[1], 16) if args[1]. startswith('0x') else int(args[1])
                name = ' '.join(args[2:])
                self.bookmarks[hex(address)] = name
                print(f"书签已添加: {name} @ 0x{address:08x}")
            except ValueError: 
                print(f"无效地址:  {args[1]}")
        elif action == 'del' and len(args) >= 2:
            addr = args[1] if args[1]. startswith('0x') else f"0x{int(args[1]):x}"
            if addr in self.bookmarks:
                del self.bookmarks[addr]
                print(f"书签已删除: {addr}")
            else:
                print(f"书签不存在: {addr}")
        elif action == 'list': 
            self._manage_bookmark([])
        else:
            print("用法: bookmark [add <地址> <名称>|del <地址>|list]")
    
    def _export_results(self, args: List[str]):
        """导出结果"""
        if not self. analyzer: 
            print("请先加载并分析文件")
            return
        
        output_path = args[0] if args else "output"
        report_path = self.analyzer.generate_report(output_path)
        if report_path: 
            print(f"报告已导出到: {report_path}")
    
    def _show_pseudocode(self, args: List[str]):
        """显示伪代码"""
        if not self.analyzer or not self.analyzer.functions:
            print("请先执行分析")
            return
        
        func = None
        if args:
            try:
                address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
                func = self.analyzer. functions.get(address)
            except ValueError:
                func = None
        else:
            func = self.analyzer.get_function_at(self.current_address)
        
        if not func: 
            print("未找到函数")
            return
        
        print(f"\n// 函数: {func. name}")
        print(f"// 地址: 0x{func.address:08x}")
        print(f"// 大小:  {func.size} bytes")
        print()
        
        pseudocode = self._generate_pseudocode(func)
        print(pseudocode)
    
    def _generate_pseudocode(self, func:  Function) -> str:
        """生成伪代码"""
        lines = []
        lines.append(f"int {func.name}() {{")
        
        indent = "    "
        
        for bb in func.basic_blocks:
            lines.append(f"\n{indent}// 基本块 0x{bb.start_address:08x}")
            
            for instr in bb.instructions:
                pseudo = self._instruction_to_pseudo(instr)
                if pseudo: 
                    lines.append(f"{indent}{pseudo}")
            
            if bb.instructions:
                last = bb.instructions[-1]
                if last.is_conditional and last.branch_target:
                    lines.append(f"{indent}if (condition) goto 0x{last.branch_target:x};")
                elif last.is_jump and not last.is_ret and last.branch_target:
                    lines. append(f"{indent}goto 0x{last.branch_target:x};")
        
        lines.append("}")
        return '\n'.join(lines)
    
    def _instruction_to_pseudo(self, instr: Instruction) -> Optional[str]:
        """将指令转换为伪代码"""
        mnemonic = instr.mnemonic. lower()
        op = instr.op_str
        
        conversions = {
            'mov': lambda:  f"{op. split(',')[0].strip()} = {op.split(',')[1].strip()};" if ',' in op else None,
            'add': lambda: f"{op.split(',')[0].strip()} += {op.split(',')[1].strip()};" if ',' in op else None,
            'sub': lambda: f"{op. split(',')[0].strip()} -= {op.split(',')[1].strip()};" if ',' in op else None,
            'xor': lambda: self._xor_to_pseudo(op),
            'push': lambda: f"push({op});",
            'pop': lambda: f"{op} = pop();",
            'call': lambda: f"call {op};",
            'ret': lambda:  "return;",
            'cmp': lambda: f"// compare {op}",
            'test': lambda: f"// test {op}",
            'nop': lambda: None,
            'lea': lambda: f"{op. split(',')[0].strip()} = &{op.split(',')[1].strip()};" if ',' in op else None,
            'inc': lambda: f"{op}++;",
            'dec': lambda: f"{op}--;",
        }
        
        if mnemonic in conversions:
            try:
                return conversions[mnemonic]()
            except:
                pass
        
        return f"// {instr.mnemonic} {instr. op_str}"
    
    def _xor_to_pseudo(self, op: str) -> str:
        if ',' in op: 
            parts = op.split(',')
            if parts[0].strip() == parts[1].strip():
                return f"{parts[0].strip()} = 0;  // xor self"
            return f"{parts[0].strip()} ^= {parts[1].strip()};"
        return None
    
    def _show_cfg(self, args:  List[str]):
        """显示控制流图"""
        if not self. analyzer or not self. analyzer.functions:
            print("请先执行分析")
            return
        
        func = None
        if args: 
            try: 
                address = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
                func = self.analyzer.functions. get(address)
            except ValueError: 
                func = None
        else:
            func = self.analyzer.get_function_at(self.current_address)
        
        if not func:
            print("未找到函数")
            return
        
        print(f"\n控制流图:  {func.name}")
        print(f"{'='*50}\n")
        
        for bb in func.basic_blocks:
            print(f"┌─ 基本块 0x{bb.start_address:08x} ─┐")
            for instr in bb. instructions[: 5]: 
                print(f"│ {instr.mnemonic: <6} {instr. op_str:<20} │")
            if len(bb.instructions) > 5:
                print(f"│ ... ({len(bb.instructions) - 5} more)          │")
            print(f"└─────────────────────────────┘")
            
            if bb. successors:
                for succ in bb. successors:
                    print(f"         │")
                    print(f"         ▼ 0x{succ: 08x}")
            print()
    
    def _show_strings(self):
        """显示字符串"""
        if not self. analyzer or not self. analyzer.file_data:
            print("请先加载文件")
            return
        
        strings = self.analyzer. extract_strings(min_length=4)
        
        print(f"\n字符串 ({len(strings)} 个):\n")
        
        keywords = ['http', 'www', 'password', 'error', 'file', 'open', 'create',
                   'registry', 'key', 'value', 'dll', 'exe', 'cmd', 'admin']
        
        interesting = []
        for offset, s in strings: 
            is_interesting = any(kw in s.lower() for kw in keywords)
            if is_interesting or len(s) > 10:
                interesting. append((offset, s, is_interesting))
        
        for offset, s, is_interesting in interesting[: 50]:
            marker = "⭐" if is_interesting else "  "
            display = s[:60] + "..." if len(s) > 60 else s
            print(f"{marker} 0x{offset: 08x}: {display}")
        
        if len(interesting) > 50:
            print(f"\n... 还有 {len(interesting) - 50} 个")
    
    def _show_info(self):
        """显示文件信息"""
        if not self. analyzer:
            print("请先加载文件")
            return
        
        print(f"\n文件信息:")
        print(f"{'='*50}")
        print(f"路径: {self. analyzer.file_path}")
        
        if self.analyzer.file_data:
            print(f"大小: {len(self.analyzer.file_data):,} bytes")
            file_hash = hashlib.sha256(self.analyzer.file_data).hexdigest()
            print(f"SHA256: {file_hash[: 32]}...")
        
        if self.analyzer.pe: 
            pe = self.analyzer.pe
            print(f"\nPE信息:")
            print(f"  架构: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
            print(f"  入口点: 0x{pe. OPTIONAL_HEADER. AddressOfEntryPoint:08x}")
            print(f"  镜像基址: 0x{pe. OPTIONAL_HEADER. ImageBase:08x}")
            print(f"  节数量: {pe.FILE_HEADER.NumberOfSections}")
            
            print(f"\n节表:")
            for section in pe.sections:
                name = section.Name. decode('utf-8', errors='ignore').strip('\x00')
                print(f"  {name: <10} VA: 0x{section.VirtualAddress:08x}  "
                      f"Size: {section. Misc_VirtualSize:>8}")
        
        if self.analyzer.instructions:
            basic_blocks = self. analyzer.get_basic_blocks()
            print(f"\n分析状态:")
            print(f"  指令:  {len(self. analyzer.instructions)}")
            print(f"  基本块: {len(basic_blocks)}")
            print(f"  函数: {len(self.analyzer.functions)}")
            print(f"  导入: {len(self.analyzer.imports)}")
            print(f"  可修改点: {len(self.analyzer.patch_points)}")
        
        # LLM状态
        if self.analyzer.ai_team and self.analyzer.ai_team.ollama:
            ollama = self.analyzer.ai_team. ollama
            print(f"\nLLM状态:")
            print(f"  服务:  {ollama.base_url}")
            print(f"  模型: {ollama.model}")
            print(f"  可用:  {'是' if ollama. is_available() else '否'}")

# ============================================================================
# 补丁生成器
# ============================================================================

class PatchGenerator:
    """补丁文件生成器"""
    
    def __init__(self, analyzer:  AIDisassemblyAnalyzer):
        self.analyzer = analyzer
    
    def generate_ips_patch(self, patches: List[Tuple[int, bytes]], output_path: str) -> bool:
        """生成IPS格式补丁"""
        try:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            
            with open(output_path, 'wb') as f:
                # IPS头
                f.write(b'PATCH')
                
                for offset, data in patches:
                    if offset > 0xFFFFFF: 
                        print(f"警告: 偏移 0x{offset:x} 超出IPS范围")
                        continue
                    
                    # 3字节偏移
                    f.write(offset.to_bytes(3, 'big'))
                    # 2字节长度
                    f.write(len(data).to_bytes(2, 'big'))
                    # 数据
                    f.write(data)
                
                # IPS尾
                f.write(b'EOF')
            
            print(f"IPS补丁已生成: {output_path}")
            return True
            
        except Exception as e:
            print(f"生成IPS补丁失败: {e}")
            return False
    
    def generate_python_patcher(self, patches:  List[Dict], output_path: str) -> bool:
        """生成Python补丁脚本"""
        script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动生成的补丁脚本
目标文件: {os.path.basename(self.analyzer.file_path)}
生成时间: {datetime.now().isoformat()}
"""

import os
import sys
import shutil

# 补丁定义
PATCHES = [
'''
        
        for patch in patches:
            original_hex = patch. get("original", b"").hex() if patch.get("original") else ""
            patched_hex = patch.get("patched", b"").hex() if patch.get("patched") else ""
            
            script += f'''    {{
        'name': '{patch.get("name", "unnamed")}',
        'offset': 0x{patch. get("offset", 0):x},
        'original': bytes.fromhex('{original_hex}'),
        'patched': bytes.fromhex('{patched_hex}'),
        'description': '{patch.get("description", "")}'
    }},
'''
        
        script += ''']

def apply_patches(file_path, create_backup=True):
    """应用补丁"""
    if not os.path. exists(file_path):
        print(f"文件不存在:  {file_path}")
        return False
    
    # 创建备份
    if create_backup:
        backup_path = file_path + '. bak'
        if not os.path.exists(backup_path):
            shutil. copy2(file_path, backup_path)
            print(f"已创建备份:  {backup_path}")
    
    # 读取文件
    with open(file_path, 'rb') as f:
        data = bytearray(f. read())
    
    # 应用补丁
    applied = 0
    for patch in PATCHES: 
        offset = patch['offset']
        original = patch['original']
        patched = patch['patched']
        
        if offset + len(original) > len(data):
            print(f"[✗] 偏移超出文件范围: {patch['name']}")
            continue
        
        # 验证原始字节
        current = bytes(data[offset: offset + len(original)])
        if current == original:
            data[offset:offset + len(patched)] = patched
            print(f"[✓] 已应用:  {patch['name']}")
            applied += 1
        elif current == patched:
            print(f"[=] 已存在: {patch['name']}")
        else:
            print(f"[✗] 不匹配: {patch['name']}")
            print(f"    预期: {original. hex()}")
            print(f"    实际: {current.hex()}")
    
    # 写入文件
    if applied > 0:
        with open(file_path, 'wb') as f:
            f.write(data)
        print(f"\\n成功应用 {applied} 个补丁")
    else:
        print("\\n没有补丁被应用")
    
    return applied > 0

def restore_backup(file_path):
    """恢复备份"""
    backup_path = file_path + '.bak'
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, file_path)
        print(f"已恢复:  {file_path}")
        return True
    else:
        print(f"备份不存在: {backup_path}")
        return False

def show_patches():
    """显示补丁列表"""
    print("\\n补丁列表:")
    print("-" * 60)
    for i, patch in enumerate(PATCHES, 1):
        print(f"{i}. {patch['name']}")
        print(f"   偏移: 0x{patch['offset']: x}")
        print(f"   描述: {patch['description']}")
        print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"用法: python {sys.argv[0]} <目标文件> [选项]")
        print("选项:")
        print("  --restore  恢复备份")
        print("  --list     显示补丁列表")
        sys.exit(1)
    
    if '--list' in sys.argv:
        show_patches()
        sys.exit(0)
    
    target = sys.argv[1]
    
    if '--restore' in sys. argv:
        restore_backup(target)
    else: 
        apply_patches(target)
'''
        
        try:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"Python补丁脚本已生成: {output_path}")
            return True
        except Exception as e: 
            print(f"生成补丁脚本失败: {e}")
            return False
    
    def generate_x64dbg_script(self, patches:  List[Dict], output_path: str) -> bool:
        """生成x64dbg脚本"""
        script = f'''// x64dbg补丁脚本
// 目标:  {os.path. basename(self.analyzer.file_path)}
// 生成时间: {datetime.now().isoformat()}

// 使用方法:  在x64dbg中执行 scriptload "{os.path.basename(output_path)}"

log "开始应用补丁..."

'''
        
        for i, patch in enumerate(patches, 1):
            offset = patch. get('offset', 0)
            patched = patch.get('patched', b'')
            name = patch.get('name', f'patch_{i}')
            desc = patch.get('description', '')
            
            script += f'// 补丁 {i}: {name}\n'
            script += f'// {desc}\n'
            
            # 写入每个字节
            for j, byte in enumerate(patched):
                script += f'wb {offset + j: x},{byte:02x}\n'
            
            script += '\n'
        
        script += '''log "补丁应用完成"
ret
'''
        
        try:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"x64dbg脚本已生成: {output_path}")
            return True
        except Exception as e:
            print(f"生成x64dbg脚本失败:  {e}")
            return False
    
    def generate_ida_script(self, patches: List[Dict], output_path:  str) -> bool:
        """生成IDA Python脚本"""
        script = f'''# -*- coding: utf-8 -*-
"""
IDA Pro 补丁脚本
目标: {os.path.basename(self.analyzer. file_path)}
生成时间:  {datetime.now().isoformat()}

使用方法: 在IDA中执行 File -> Script file... 
"""

import idaapi
import idc

PATCHES = [
'''
        
        for patch in patches: 
            patched_hex = patch.get("patched", b"").hex() if patch.get("patched") else ""
            script += f'''    {{
        'name': '{patch.get("name", "unnamed")}',
        'address': 0x{patch.get("offset", 0):x},
        'bytes': bytes.fromhex('{patched_hex}'),
        'description': '{patch.get("description", "")}'
    }},
'''
        
        script += ''']

def apply_patches():
    """应用补丁"""
    applied = 0
    for patch in PATCHES: 
        addr = patch['address']
        data = patch['bytes']
        
        try:
            for i, byte in enumerate(data):
                idc.patch_byte(addr + i, byte)
            print(f"[✓] 已应用: {patch['name']} @ 0x{addr:x}")
            applied += 1
        except Exception as e:
            print(f"[✗] 失败: {patch['name']} - {e}")
    
    print(f"\\n完成，应用了 {applied} 个补丁")

if __name__ == '__main__':
    apply_patches()
'''
        
        try:
            os. makedirs(os. path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script)
            print(f"IDA脚本已生成: {output_path}")
            return True
        except Exception as e:
            print(f"生成IDA脚本失败: {e}")
            return False


# ============================================================================
# 命令行接口
# ============================================================================

def print_banner():
    """打印横幅"""
    banner = f"""
{'='*70}
    🔬 AI团队反汇编分析工具 v2.0
    
    核心功能: 
    ✓ 智能反汇编 (x86/x64)      ✓ 控制流分析
    ✓ 数据流分析                ✓ 语义分析
    ✓ 可修改点识别              ✓ 补丁生成
    
    AI团队: 
    ✓ 逻辑分析师                ✓ 安全分析师
    ✓ 补丁专家                  ✓ 逆向工程师
    ✓ 行为分析师
    
    LLM支持: 
    ✓ Ollama 本地大模型         ✓ 智能代码分析
    
    依赖状态:
    - pefile:    {'✓ 已安装' if HAS_PEFILE else '✗ 未安装 (pip install pefile)'}
    - capstone: {'✓ 已安装' if HAS_CAPSTONE else '✗ 未安装 (pip install capstone)'}
    - keystone: {'✓ 已安装' if HAS_KEYSTONE else '✗ 未安装 (pip install keystone-engine)'}
    - requests: {'✓ 已安装' if HAS_REQUESTS else '✗ 未安装 (pip install requests)'}
{'='*70}
"""
    print(banner)


def print_usage():
    """打印使用说明"""
    usage = f"""
用法: python {sys.argv[0]} <命令> [选项]

命令: 
    analyze <文件>      分析PE文件
    interactive         进入交互式模式
    patch <文件>        生成补丁脚本
    help               显示帮助

Ollama LLM选项: 
    --ollama-url <URL>  Ollama服务地址 (默认: http://localhost:11434)
    --model <名称>      模型名称 (默认: llama3)
    --no-llm           禁用LLM，使用基础分析模式

其他选项: 
    --output <目录>     指定输出目录 (默认:  output)
    --format <格式>     补丁格式 (python/ips/x64dbg/ida)

示例:
    # 基础分析（无LLM）
    python {sys. argv[0]} analyze target.exe --no-llm
    
    # 使用Ollama分析
    python {sys.argv[0]} analyze target.exe --model llama3
    
    # 使用CodeLlama分析
    python {sys.argv[0]} analyze target.exe --model codellama
    
    # 交互式模式
    python {sys.argv[0]} interactive --model llama3
    
    # 生成补丁脚本
    python {sys.argv[0]} patch target. exe --format python
    
    # 指定Ollama服务器
    python {sys.argv[0]} analyze target.exe --ollama-url http://192.168.1.100:11434
"""
    print(usage)


def parse_args(args:  List[str]) -> Dict[str, Any]: 
    """解析命令行参数"""
    parsed = {
        'command': None,
        'file': None,
        'output': 'output',
        'format': 'python',
        'ollama_url':  'http://localhost:11434',
        'model': 'llama3',
        'use_llm': True,
    }
    
    i = 0
    while i < len(args):
        arg = args[i]
        
        if arg in ['analyze', 'interactive', 'patch', 'help', '-i']: 
            parsed['command'] = 'interactive' if arg == '-i' else arg
            if arg in ['analyze', 'patch'] and i + 1 < len(args) and not args[i + 1].startswith('-'):
                parsed['file'] = args[i + 1]
                i += 1
        elif arg == '--output' and i + 1 < len(args):
            parsed['output'] = args[i + 1]
            i += 1
        elif arg == '--format' and i + 1 < len(args):
            parsed['format'] = args[i + 1]. lower()
            i += 1
        elif arg == '--ollama-url' and i + 1 < len(args):
            parsed['ollama_url'] = args[i + 1]
            i += 1
        elif arg == '--model' and i + 1 < len(args):
            parsed['model'] = args[i + 1]
            i += 1
        elif arg == '--no-llm': 
            parsed['use_llm'] = False
        elif arg == '--llm':
            parsed['use_llm'] = True
        elif not arg.startswith('-') and parsed['command'] in ['analyze', 'patch'] and not parsed['file']:
            parsed['file'] = arg
        
        i += 1
    
    return parsed


def cmd_analyze(args:  Dict[str, Any]):
    """执行分析命令"""
    file_path = args['file']
    
    if not file_path:
        print("错误:  请指定要分析的文件")
        print_usage()
        return
    
    if not os.path. exists(file_path):
        print(f"文件不存在:  {file_path}")
        return
    
    # 创建分析器
    analyzer = AIDisassemblyAnalyzer(
        file_path,
        ollama_url=args['ollama_url'],
        model=args['model'],
        use_llm=args['use_llm']
    )
    
    # 执行完整分析
    results = analyzer.full_analysis()
    
    if results:
        # 生成报告
        report_path = analyzer.generate_report(args['output'])
        
        # 显示摘要
        print(f"\n{'='*60}")
        print("✅ 分析完成")
        print(f"{'='*60}")
        
        consensus = results.get('consensus', {})
        print(f"\n风险级别: {consensus. get('risk_level', 'UNKNOWN')}")
        print(f"整体评估: {consensus.get('overall_assessment', 'N/A')}")
        
        print(f"\n优先修改目标:")
        for target in consensus.get('priority_targets', [])[:3]:
            print(f"  - {target['address']}: {target['action']}")
        
        if results.get('llm_summary'):
            print(f"\n🧠 AI综合分析:")
            summary = results['llm_summary']
            print(summary[: 300] + "..." if len(summary) > 300 else summary)
        
        print(f"\n报告已保存:  {report_path}")
    else: 
        print("分析失败")


def cmd_interactive(args: Dict[str, Any]):
    """进入交互式模式"""
    interactive = InteractiveAnalyzer(
        ollama_url=args['ollama_url'],
        model=args['model'],
        use_llm=args['use_llm']
    )
    interactive.run()


def cmd_patch(args: Dict[str, Any]):
    """生成补丁命令"""
    file_path = args['file']
    
    if not file_path:
        print("错误: 请指定要分析的文件")
        return
    
    if not os.path. exists(file_path):
        print(f"文件不存在: {file_path}")
        return
    
    # 分析文件
    print("[*] 正在分析文件...")
    analyzer = AIDisassemblyAnalyzer(
        file_path,
        ollama_url=args['ollama_url'],
        model=args['model'],
        use_llm=False  # 补丁生成不需要LLM
    )
    
    if not analyzer.load():
        print("加载文件失败")
        return
    
    analyzer.disassemble()
    analyzer.analyze_control_flow()
    analyzer.find_patch_points()
    
    if not analyzer.patch_points:
        print("未找到可修改点")
        return
    
    # 准备补丁数据
    patches = []
    for pp in analyzer.patch_points[: 20]:  # 限制数量
        if pp.suggested_patches:
            sugg = pp.suggested_patches[0]
            if sugg.get('bytes'):
                patches.append({
                    'name': f"patch_{pp.address:x}",
                    'offset': pp.address,
                    'original': pp.original_bytes,
                    'patched': sugg['bytes'],
                    'description':  sugg['description']
                })
    
    if not patches:
        print("没有可用的补丁建议")
        return
    
    print(f"[*] 找到 {len(patches)} 个可用补丁")
    
    # 生成补丁
    generator = PatchGenerator(analyzer)
    output_dir = args['output']
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    patch_format = args['format']
    
    if patch_format == 'python':
        generator.generate_python_patcher(
            patches, 
            os.path.join(output_dir, f"patcher_{timestamp}.py")
        )
    elif patch_format == 'ips':
        ips_patches = [(p['offset'], p['patched']) for p in patches]
        generator.generate_ips_patch(
            ips_patches, 
            os.path.join(output_dir, f"patch_{timestamp}.ips")
        )
    elif patch_format == 'x64dbg':
        generator.generate_x64dbg_script(
            patches, 
            os.path. join(output_dir, f"patch_{timestamp}.x64dbg. txt")
        )
    elif patch_format == 'ida': 
        generator.generate_ida_script(
            patches, 
            os.path.join(output_dir, f"patch_{timestamp}_ida.py")
        )
    else:
        print(f"不支持的格式: {patch_format}")
        print("支持的格式: python, ips, x64dbg, ida")


def main():
    """主函数"""
    print_banner()
    
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)
    
    # 解析参数
    args = parse_args(sys.argv[1:])
    
    command = args['command']
    
    if command == 'help' or command is None:
        print_usage()
        sys.exit(0)
    
    elif command == 'interactive':
        cmd_interactive(args)
    
    elif command == 'analyze': 
        cmd_analyze(args)
    
    elif command == 'patch': 
        cmd_patch(args)
    
    else:
        print(f"未知命令: {command}")
        print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()
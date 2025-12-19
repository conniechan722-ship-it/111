#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI x64dbg 辅助分析工具 v1.0
"""

import os
import sys
import json
import struct
import re
import time
import socket
import threading
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from enum import Enum, auto
from abc import ABC, abstractmethod
import configparser

if sys.platform == 'win32': 
    import io
    sys.stdout = io. TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr. buffer, encoding='utf-8', errors='replace')
    os.system('chcp 65001 >nul 2>&1')

DEPENDENCIES = {}

try:
    import requests
    DEPENDENCIES['requests'] = True
except ImportError: 
    DEPENDENCIES['requests'] = False

try:
    import pefile
    DEPENDENCIES['pefile'] = True
except ImportError:
    DEPENDENCIES['pefile'] = False

try: 
    from capstone import *
    DEPENDENCIES['capstone'] = True
except ImportError:
    DEPENDENCIES['capstone'] = False

try:
    from keystone import *
    DEPENDENCIES['keystone'] = True
except ImportError:
    DEPENDENCIES['keystone'] = False


@dataclass
class Config:
    ollama_url: str = "http://localhost:11434"
    default_model: str = "qwen2.5-coder: 7b"
    available_models: List[str] = field(default_factory=list)
    timeout: int = 300
    max_context:  int = 4096
    x64dbg_bridge_port: int = 27042
    x64dbg_path: str = ""
    max_instructions: int = 50000
    max_functions: int = 500
    auto_patch: bool = False
    output_dir: str = "output"
    requirements_file: str = ""
    requirements_content: str = ""
    
    @classmethod
    def load(cls, path: str = "config.ini") -> 'Config':
        cfg = cls()
        if os.path.exists(path):
            p = configparser.ConfigParser()
            p.read(path, encoding='utf-8')
            if 'ollama' in p: 
                cfg.ollama_url = p. get('ollama', 'url', fallback=cfg.ollama_url)
                cfg. default_model = p.get('ollama', 'model', fallback=cfg. default_model)
                cfg.timeout = p.getint('ollama', 'timeout', fallback=cfg.timeout)
            if 'x64dbg' in p:
                cfg.x64dbg_bridge_port = p.getint('x64dbg', 'port', fallback=cfg.x64dbg_bridge_port)
        return cfg
    
    def save(self, path:  str = "config. ini"):
        p = configparser.ConfigParser()
        p['ollama'] = {'url': self.ollama_url, 'model': self. default_model, 'timeout': str(self.timeout)}
        p['x64dbg'] = {'port': str(self.x64dbg_bridge_port)}
        with open(path, 'w') as f:
            p.write(f)


def load_requirements_file(file_path: str) -> str:
    """
    加载需求文件并返回其内容
    
    Args:
        file_path: 需求文件路径（.txt格式）
        
    Returns:
        需求文件的内容字符串
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"[需求] 已加载: {file_path}")
        return content
    except Exception as e:
        print(f"[错误] 无法加载需求文件: {e}")
        return ""


class OllamaClient:
    def __init__(self, config: Config):
        self.config = config
        self.base_url = config.ollama_url.rstrip('/')
        self.model = config.default_model
        self.requested_model = config.default_model  # 保存用户请求的模型
        self.timeout = config.timeout
        self.available = False
        self.models: List[str] = []
        self._init()
    
    def _init(self):
        if not DEPENDENCIES.get('requests'):
            return
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if r.status_code == 200:
                self.models = [m['name'] for m in r.json().get('models', [])]
                if self.models:
                    # 尝试匹配用户指定的模型
                    matched_model = self._find_best_model_match(self.model)
                    if matched_model:
                        if matched_model != self.model:
                            print(f"[Ollama] 模型 '{self.model}' 匹配到: {matched_model}")
                        self.model = matched_model
                    else:
                        print(f"[Ollama] 警告: 未找到模型 '{self.model}'，使用默认: {self.models[0]}")
                        self.model = self.models[0]
                    self.available = True
                    print(f"[Ollama] 当前模型: {self.model}")
        except Exception as e:
            print(f"[Ollama] 连接失败: {self.base_url} - {e}")
    
    def _find_best_model_match(self, requested: str) -> Optional[str]:
        """查找最佳匹配的模型"""
        # 1. 精确匹配
        if requested in self.models:
            return requested
        
        # 2. 不区分大小写的精确匹配
        requested_lower = requested.lower()
        for m in self.models:
            if m.lower() == requested_lower:
                return m
        
        # 3. 前缀匹配 (比如 qwen2.5:32b 匹配 qwen2.5:32b-instruct)
        for m in self.models:
            if m.lower().startswith(requested_lower):
                return m
        
        # 4. 基础名称匹配 (比如 qwen2.5 匹配 qwen2.5:32b)
        base = requested.split(':')[0].lower()
        # 优先匹配带有相同标签的
        if ':' in requested:
            tag = requested.split(':')[1].lower()
            for m in self.models:
                if base in m.lower() and tag in m.lower():
                    return m
        
        # 5. 只匹配基础名称
        for m in self.models:
            if base in m.lower():
                return m
        
        return None
    
    def list_models(self) -> List[str]: 
        return self.models
    
    def switch_model(self, name: str) -> bool:
        if name in self.models:
            self.model = name
            return True
        for m in self.models:
            if name in m:
                self.model = m
                return True
        return False
    
    def generate(self, prompt: str, system: str = None, temperature: float = 0.7, max_tokens: int = 2048) -> Optional[str]:
        if not self.available:
            return None
        try:
            payload = {"model": self.model, "prompt": prompt, "stream": False, "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": self.config. max_context}}
            if system:
                payload["system"] = system
            r = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            if r.status_code == 200:
                return r. json().get('response', '')
        except Exception as e:
            print(f"[Ollama] 错误: {e}")
        return None
    
    def analyze_code(self, code: str, question: str, role: str = "逆向工程专家", requirements: str = "") -> Optional[str]:
        if len(code) > 3000:
            code = code[:3000] + "\n..."
        system = f"你是{role}，精通x86/x64汇编和逆向工程。用中文简洁回答。"
        if requirements:
            system += f"\n\n当前调试需求：\n{requirements}\n\n请围绕这些需求进行针对性分析。"
        prompt = f"代码:\n```\n{code}\n```\n\n问题:  {question}\n\n分析:"
        return self.generate(prompt, system=system)
    
    def suggest_patch(self, instr: str, ctx: str, goal: str, requirements: str = "") -> Optional[Dict]: 
        system = "你是补丁专家。返回JSON:  {\"方法\": \"\", \"补丁字节\": \"hex\", \"风险\": \"LOW/MEDIUM/HIGH\", \"说明\": \"\"}"
        if requirements:
            system += f"\n\n当前调试需求：\n{requirements}\n\n请围绕这些需求提供补丁建议。"
        prompt = f"指令:  {instr}\n上下文: {ctx}\n目标:  {goal}\n\n补丁建议:"
        result = self.generate(prompt, system=system)
        if result:
            try:
                m = re.search(r'\{[^{}]*\}', result, re.DOTALL)
                if m:
                    return json.loads(m.group())
            except:
                pass
            return {"raw": result}
        return None
    
    def is_available(self) -> bool:
        return self.available
class PatchStatus(Enum):
    PENDING = auto()
    APPLIED = auto()
    VERIFIED = auto()
    FAILED = auto()
    REVERTED = auto()


@dataclass
class Instruction:
    address:  int
    size:  int
    mnemonic: str
    op_str:  str
    bytes_hex: str
    is_call: bool = False
    is_jump: bool = False
    is_conditional: bool = False
    is_ret:  bool = False
    branch_target: Optional[int] = None
    ai_comment: str = ""
    
    def __str__(self):
        return f"0x{self.address:08X}:  {self.mnemonic} {self. op_str}"
    
    def to_dict(self):
        return {'address': hex(self.address), 'size': self.size, 'mnemonic': self.mnemonic, 'op_str': self.op_str, 'bytes':  self.bytes_hex}


@dataclass
class PatchPoint:
    address:  int
    size:  int
    original_bytes: bytes
    patched_bytes: Optional[bytes] = None
    instruction: str = ""
    patch_type: str = ""
    description: str = ""
    risk_level: str = "MEDIUM"
    status: PatchStatus = PatchStatus. PENDING
    ai_suggestion: str = ""
    
    def __str__(self):
        return f"[{self.status. name}] 0x{self.address:08X}:  {self.patch_type}"
    
    def to_dict(self):
        return {'address': hex(self.address), 'size': self.size, 'original':  self.original_bytes.hex(), 'patched': self. patched_bytes. hex() if self.patched_bytes else None, 'type': self.patch_type, 'risk': self.risk_level, 'status': self.status. name}


@dataclass
class Function:
    address:  int
    name: str
    size: int = 0
    end_address: int = 0
    instructions: List[Instruction] = field(default_factory=list)
    calls_to: List[int] = field(default_factory=list)
    purpose: str = ""
    is_security_related: bool = False
    ai_analysis: str = ""
    
    def get_disasm(self, limit: int = 50) -> str:
        lines = [f"0x{i.address:08X}: {i.mnemonic:8} {i.op_str}" for i in self.instructions[:limit]]
        if len(self.instructions) > limit:
            lines.append(f"... ({len(self.instructions)-limit} more)")
        return '\n'.join(lines)


@dataclass
class AnalysisResult: 
    file_path: str
    file_hash: str
    timestamp: str
    instruction_count: int = 0
    function_count: int = 0
    patch_point_count: int = 0
    functions: Dict[int, Function] = field(default_factory=dict)
    patch_points: List[PatchPoint] = field(default_factory=list)
    imports: List[Dict] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return {'file':  self.file_path, 'hash':  self.file_hash, 'timestamp':  self.timestamp, 'stats': {'instructions': self.instruction_count, 'functions': self.function_count, 'patches': self.patch_point_count}, 'risk': self.risk_level, 'summary': self.summary, 'patches': [p.to_dict() for p in self.patch_points[: 100]]}


class Disassembler: 
    BRANCHES = {'jmp','je','jne','jz','jnz','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jo','jno','loop'}
    CALLS = {'call'}
    RETS = {'ret','retn','retf'}
    COND_JUMPS = BRANCHES - {'jmp'}
    
    def __init__(self, arch: str = 'x86', mode: str = '32'):
        self.arch = arch
        self.mode = mode
        self.cs = None
        self. ks = None
        if DEPENDENCIES. get('capstone'):
            cs_mode = CS_MODE_64 if mode == '64' else CS_MODE_32
            self.cs = Cs(CS_ARCH_X86, cs_mode)
            self.cs.detail = True
        if DEPENDENCIES.get('keystone'):
            ks_mode = KS_MODE_64 if mode == '64' else KS_MODE_32
            self.ks = Ks(KS_ARCH_X86, ks_mode)
    
    def disassemble(self, code: bytes, base: int = 0, max_count: int = 0) -> List[Instruction]:
        instrs = []
        if self.cs:
            for i, insn in enumerate(self.cs.disasm(code, base)):
                if max_count and i >= max_count: 
                    break
                mn = insn.mnemonic. lower()
                target = None
                if insn.operands and mn in self.BRANCHES | self.CALLS: 
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            target = op.imm
                            break
                instrs.append(Instruction(address=insn.address, size=insn.size, mnemonic=mn, op_str=insn.op_str, bytes_hex=insn.bytes. hex(), is_call=mn in self.CALLS, is_jump=mn in self. BRANCHES, is_conditional=mn in self. COND_JUMPS, is_ret=mn in self.RETS, branch_target=target))
        else:
            instrs = self._simple(code, base, max_count)
        return instrs
    
    def _simple(self, code: bytes, base:  int, max_count: int) -> List[Instruction]: 
        instrs = []
        off = 0
        opcodes = {0x90: ('nop',1), 0xC3:('ret',1), 0xCC:('int3',1), 0x55:('push ebp',1), 0x5D:('pop ebp',1)}
        while off < len(code) and (not max_count or len(instrs) < max_count):
            addr = base + off
            op = code[off]
            if op in opcodes:
                txt, sz = opcodes[op]
                parts = txt.split(' ',1)
                mn, ops = parts[0], parts[1] if len(parts)>1 else ""
            elif op == 0xE8 and off+5 <= len(code):
                rel = struct.unpack('<i', code[off+1:off+5])[0]
                mn, ops, sz = 'call', f'0x{addr+5+rel: x}', 5
            elif op == 0xE9 and off+5 <= len(code):
                rel = struct.unpack('<i', code[off+1:off+5])[0]
                mn, ops, sz = 'jmp', f'0x{addr+5+rel:x}', 5
            elif op == 0xEB and off+2 <= len(code):
                rel = struct.unpack('<b', code[off+1:off+2])[0]
                mn, ops, sz = 'jmp', f'0x{addr+2+rel:x}', 2
            elif 0x70 <= op <= 0x7F and off+2 <= len(code):
                jcc = ['jo','jno','jb','jnb','jz','jnz','jbe','ja','js','jns','jp','jnp','jl','jge','jle','jg'][op-0x70]
                rel = struct.unpack('<b', code[off+1:off+2])[0]
                mn, ops, sz = jcc, f'0x{addr+2+rel:x}', 2
            else:
                mn, ops, sz = 'db', f'0x{op:02x}', 1
            instrs.append(Instruction(address=addr, size=sz, mnemonic=mn, op_str=ops, bytes_hex=code[off:off+sz].hex(), is_call=mn=='call', is_jump=mn in self.BRANCHES, is_conditional=mn in self.COND_JUMPS, is_ret=mn in self. RETS))
            off += sz
        return instrs
    
    def assemble(self, asm:  str, addr: int = 0) -> Optional[bytes]:
        if self. ks:
            try:
                enc, _ = self. ks. asm(asm, addr)
                return bytes(enc)
            except:
                pass
        return None
    
    def nop(self, size: int) -> bytes:
        return b'\x90' * size
class PEAnalyzer:
    def __init__(self, path: str):
        self.path = path
        self.data:  bytes = b''
        self. pe = None
        self.is_64 = False
        self.imports: List[Dict] = []
        self.exports: List[Dict] = []
        self.sections: List[Dict] = []
        self.disasm:  Optional[Disassembler] = None
        self.instructions: List[Instruction] = []
        self.functions: Dict[int, Function] = {}
    
    def load(self) -> bool:
        try:
            with open(self.path, 'rb') as f:
                self.data = f.read()
            print(f"[*] 文件:  {len(self.data):,} 字节")
        except Exception as e:
            print(f"[错误] {e}")
            return False
        
        if not DEPENDENCIES.get('pefile'):
            return True
        
        try:
            self. pe = pefile. PE(data=self.data)
            self.is_64 = self.pe. FILE_HEADER.Machine == 0x8664
            print(f"[*] 架构: {'x64' if self.is_64 else 'x86'}")
            self.disasm = Disassembler('x86', '64' if self.is_64 else '32')
            
            for s in self.pe. sections:
                name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
                self.sections.append({'name': name, 'va': s.VirtualAddress, 'size': s. Misc_VirtualSize, 'exec': bool(s.Characteristics & 0x20000000)})
            
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe. DIRECTORY_ENTRY_IMPORT: 
                    dll = entry.dll.decode('utf-8', errors='ignore') if entry.dll else ''
                    for imp in entry.imports:
                        fn = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ord_{imp.ordinal}"
                        self.imports.append({'dll': dll, 'func': fn, 'addr': imp.address})
            print(f"[*] 导入:  {len(self. imports)}")
            return True
        except Exception as e:
            print(f"[错误] PE解析:  {e}")
            return False
    
    def disassemble_code(self, max_instrs: int = 50000) -> List[Instruction]:
        if not self.pe or not self.disasm:
            return []
        code_sec = next((s for s in self.sections if s['exec']), None)
        if not code_sec:
            return []
        for s in self.pe.sections:
            name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
            if name == code_sec['name']: 
                code = s.get_data()
                base = self.pe. OPTIONAL_HEADER. ImageBase + s.VirtualAddress
                print(f"[*] 反汇编: {name} @ 0x{base:X}")
                self.instructions = self.disasm.disassemble(code, base, max_instrs)
                print(f"[*] 指令: {len(self.instructions)}")
                return self.instructions
        return []
    
    def identify_functions(self) -> Dict[int, Function]:
        if not self.instructions:
            return {}
        starts = set()
        addr_set = {i.address for i in self.instructions}
        for i, ins in enumerate(self. instructions):
            if ins.mnemonic == 'push' and ('ebp' in ins.op_str. lower() or 'rbp' in ins. op_str.lower()):
                if i+1 < len(self.instructions) and self.instructions[i+1].mnemonic == 'mov':
                    starts.add(ins.address)
            if ins.is_call and ins. branch_target and ins.branch_target in addr_set: 
                starts.add(ins.branch_target)
        
        sorted_starts = sorted(starts)
        for i, start in enumerate(sorted_starts):
            end = sorted_starts[i+1] if i+1 < len(sorted_starts) else start + 0x1000
            func_ins = []
            for ins in self.instructions:
                if ins. address < start:
                    continue
                if ins.address >= end:
                    break
                func_ins. append(ins)
                if ins.is_ret:
                    break
            if func_ins: 
                f = Function(address=start, name=f"sub_{start: X}", size=func_ins[-1]. address+func_ins[-1].size-start, end_address=func_ins[-1]. address+func_ins[-1].size, instructions=func_ins)
                for ins in func_ins: 
                    if ins.is_call and ins.branch_target:
                        f.calls_to. append(ins.branch_target)
                self.functions[start] = f
        print(f"[*] 函数:  {len(self. functions)}")
        return self.functions
    
    def get_hash(self) -> str:
        return hashlib.sha256(self.data).hexdigest()
    
    def va_to_offset(self, va: int) -> int:
        if self.pe:
            rva = va - self.pe.OPTIONAL_HEADER.ImageBase
            return self.pe.get_offset_from_rva(rva)
        return va


class PatchAnalyzer: 
    NOP = b'\x90'
    JMP_SHORT = b'\xEB'
    
    def __init__(self, pe:  PEAnalyzer):
        self.pe = pe
        self.patches: List[PatchPoint] = []
    
    def find_patches(self) -> List[PatchPoint]:
        self.patches = []
        self._find_cond_jumps()
        self._find_calls()
        self._find_comparisons()
        return self.patches
    
    def _find_cond_jumps(self):
        for ins in self.pe. instructions:
            if ins.is_conditional: 
                pp = PatchPoint(address=ins.address, size=ins.size, original_bytes=bytes. fromhex(ins.bytes_hex), instruction=str(ins), patch_type='conditional_jump', description=f'条件跳转:  {ins.mnemonic}', risk_level='MEDIUM')
                pp.patched_bytes = self.NOP * ins.size
                self.patches.append(pp)
    
    def _find_calls(self):
        security_funcs = {'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'gettickcount', 'queryperformancecounter'}
        for ins in self.pe.instructions:
            if ins.is_call:
                is_sec = any(sf in ins.op_str.lower() for sf in security_funcs)
                pp = PatchPoint(address=ins.address, size=ins. size, original_bytes=bytes.fromhex(ins.bytes_hex), instruction=str(ins), patch_type='security_call' if is_sec else 'call', description=f'调用: {ins.op_str}', risk_level='HIGH' if is_sec else 'MEDIUM')
                pp.patched_bytes = self.NOP * ins.size
                self.patches.append(pp)
    
    def _find_comparisons(self):
        for i, ins in enumerate(self.pe.instructions):
            if ins.mnemonic in ['cmp', 'test']: 
                if i+1 < len(self.pe. instructions):
                    nxt = self.pe. instructions[i+1]
                    if nxt.is_conditional:
                        total = ins.size + nxt.size
                        pp = PatchPoint(address=ins.address, size=total, original_bytes=bytes.fromhex(ins.bytes_hex + nxt.bytes_hex), instruction=f"{ins}; {nxt}", patch_type='comparison', description='条件检查', risk_level='MEDIUM')
                        pp.patched_bytes = self. NOP * total
                        self.patches.append(pp)
    
    def get_high_priority(self, limit: int = 20) -> List[PatchPoint]:
        security = [p for p in self. patches if 'security' in p.patch_type]
        cond = [p for p in self.patches if p.patch_type == 'conditional_jump']
        return (security + cond)[:limit]
    
    def generate_script(self, patches: List[PatchPoint], fmt: str = 'python') -> str:
        if fmt == 'python': 
            return self._gen_python(patches)
        elif fmt == 'x64dbg':
            return self._gen_x64dbg(patches)
        return ""
    
    def _gen_python(self, patches:  List[PatchPoint]) -> str:
        lines = ['#!/usr/bin/env python3', '# Auto-generated patch script', '', 'PATCHES = [']
        for p in patches:
            if p.patched_bytes: 
                lines.append(f"    {{'addr': 0x{p. address:X}, 'orig':  bytes. fromhex('{p.original_bytes.hex()}'), 'patch': bytes.fromhex('{p. patched_bytes. hex()}'), 'desc': '{p.description}'}},")
        lines.append(']')
        lines.append('''
def apply(path):
    import shutil
    shutil.copy(path, path + '. bak')
    with open(path, 'r+b') as f:
        data = bytearray(f. read())
        for p in PATCHES: 
            off = p['addr']  # TODO: VA to offset
            if data[off:off+len(p['orig'])] == p['orig']:
                data[off:off+len(p['patch'])] = p['patch']
                print(f"Applied:  {p['desc']}")
        f.seek(0)
        f.write(data)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        apply(sys. argv[1])
''')
        return '\n'.join(lines)
    
    def _gen_x64dbg(self, patches: List[PatchPoint]) -> str:
        lines = ['// x64dbg patch script', '']
        for p in patches:
            if p.patched_bytes:
                lines.append(f'// {p.description}')
                for i, b in enumerate(p. patched_bytes):
                    lines. append(f'wb {p.address+i:X},{b:02X}')
                lines.append('')
        return '\n'.join(lines)


class AICodeAnalyst(ABC):
    """AI代码分析师基类"""
    
    def __init__(self, name: str, role: str, ollama: OllamaClient, requirements: str = ""):
        self.name = name
        self.role = role
        self.ollama = ollama
        self.requirements = requirements
        self.findings: List[Dict] = []
    
    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        pass
    
    def _get_requirements_context(self) -> str:
        """获取需求上下文"""
        if not self.requirements:
            return ""
        return f"\n调试需求: {self.requirements}\n请围绕这些需求进行针对性分析。"


class LogicAnalyst(AICodeAnalyst):
    """逻辑分析师"""
    def __init__(self, ollama: OllamaClient, requirements: str = ""):
        super().__init__("逻辑分析师", "理解代码逻辑流程", ollama, requirements)
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        print(f"[{self.name}] 分析中...")
        result = {'analyst': self.name, 'findings': [], 'summary': ''}
        
        if not self.ollama.is_available():
            result['summary'] = "LLM不可用"
            return result
        
        # 分析主要函数逻辑
        functions = data.get('functions', {})
        if functions:
            func_list = list(functions.values())[:5]
            func_summary = "\n".join([f"- {f.name} @ 0x{f.address:X}: {len(f.instructions)}条指令" 
                                     for f in func_list])
            
            prompt = f"分析以下函数的逻辑流程：\n{func_summary}{self._get_requirements_context()}"
            resp = self.ollama.generate(prompt, system="你是逻辑分析师，专注于理解代码执行流程。用中文简洁回答。")
            if resp:
                result['summary'] = resp[:200]
                result['findings'].append({'type': 'logic', 'content': resp})
        
        return result


class SecurityAnalyst(AICodeAnalyst):
    """安全分析师"""
    def __init__(self, ollama: OllamaClient, requirements: str = ""):
        super().__init__("安全分析师", "识别安全问题和保护机制", ollama, requirements)
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        print(f"[{self.name}] 分析中...")
        result = {'analyst': self.name, 'findings': [], 'summary': ''}
        
        if not self.ollama.is_available():
            result['summary'] = "LLM不可用"
            return result
        
        # 分析安全相关API调用
        imports = data.get('imports', [])
        security_apis = [imp for imp in imports if any(api in imp.get('func', '').lower() 
                        for api in ['debug', 'protect', 'check', 'verify', 'crypt'])]
        
        if security_apis:
            api_list = "\n".join([f"- {imp['dll']}.{imp['func']}" for imp in security_apis[:10]])
            prompt = f"分析这些安全相关的API调用：\n{api_list}{self._get_requirements_context()}"
            resp = self.ollama.generate(prompt, system="你是安全分析师，专注于识别安全机制和漏洞。用中文简洁回答。")
            if resp:
                result['summary'] = resp[:200]
                result['findings'].append({'type': 'security', 'severity': 'HIGH', 'content': resp})
        
        return result


class PatchExpert(AICodeAnalyst):
    """补丁专家"""
    def __init__(self, ollama: OllamaClient, requirements: str = ""):
        super().__init__("补丁专家", "提供修改建议", ollama, requirements)
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        print(f"[{self.name}] 分析中...")
        result = {'analyst': self.name, 'findings': [], 'summary': ''}
        
        if not self.ollama.is_available():
            result['summary'] = "LLM不可用"
            return result
        
        # 分析补丁点
        patches = data.get('patches', [])
        if patches:
            patch_summary = "\n".join([f"- 0x{p.address:X}: {p.patch_type} ({p.risk_level})" 
                                      for p in patches[:5]])
            
            prompt = f"提供以下补丁点的修改建议：\n{patch_summary}{self._get_requirements_context()}"
            resp = self.ollama.generate(prompt, system="你是补丁专家，专注于提供安全有效的代码修改方案。用中文简洁回答。")
            if resp:
                result['summary'] = resp[:200]
                result['findings'].append({'type': 'patch', 'content': resp})
        
        return result


class ReverseEngineer(AICodeAnalyst):
    """逆向工程师"""
    def __init__(self, ollama: OllamaClient, requirements: str = ""):
        super().__init__("逆向工程师", "深度代码理解", ollama, requirements)
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        print(f"[{self.name}] 分析中...")
        result = {'analyst': self.name, 'findings': [], 'summary': ''}
        
        if not self.ollama.is_available():
            result['summary'] = "LLM不可用"
            return result
        
        # 深度分析指令模式
        instructions = data.get('instructions', [])
        if instructions:
            instr_sample = "\n".join([f"0x{i.address:X}: {i.mnemonic} {i.op_str}" 
                                     for i in instructions[:20]])
            
            prompt = f"深度分析以下汇编代码：\n{instr_sample}{self._get_requirements_context()}"
            resp = self.ollama.generate(prompt, system="你是资深逆向工程师，精通汇编语言和程序分析。用中文简洁回答。")
            if resp:
                result['summary'] = resp[:200]
                result['findings'].append({'type': 'reverse', 'content': resp})
        
        return result


class BehaviorAnalyst(AICodeAnalyst):
    """行为分析师"""
    def __init__(self, ollama: OllamaClient, requirements: str = ""):
        super().__init__("行为分析师", "分析程序运行时行为", ollama, requirements)
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        print(f"[{self.name}] 分析中...")
        result = {'analyst': self.name, 'findings': [], 'summary': ''}
        
        if not self.ollama.is_available():
            result['summary'] = "LLM不可用"
            return result
        
        # 分析程序行为特征
        imports = data.get('imports', [])
        behavior_keywords = ['file', 'registry', 'network', 'process', 'thread']
        behavior_apis = [imp for imp in imports if any(kw in imp.get('func', '').lower() 
                        for kw in behavior_keywords)]
        
        if behavior_apis:
            api_list = "\n".join([f"- {imp['dll']}.{imp['func']}" for imp in behavior_apis[:10]])
            prompt = f"分析程序的运行时行为特征：\n{api_list}{self._get_requirements_context()}"
            resp = self.ollama.generate(prompt, system="你是行为分析师，专注于理解程序的运行时行为和意图。用中文简洁回答。")
            if resp:
                result['summary'] = resp[:200]
                result['findings'].append({'type': 'behavior', 'content': resp})
        
        return result


class AITeamManager:
    """AI团队管理器"""
    
    def __init__(self, ollama: OllamaClient, requirements: str = ""):
        self.ollama = ollama
        self.requirements = requirements
        self.analysts = {
            'logic': LogicAnalyst(ollama, requirements),
            'security': SecurityAnalyst(ollama, requirements),
            'patch': PatchExpert(ollama, requirements),
            'reverse': ReverseEngineer(ollama, requirements),
            'behavior': BehaviorAnalyst(ollama, requirements),
        }
    
    def run_full_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """运行完整的团队分析"""
        print("\n[AI团队] 开始协同分析...")
        
        results = {}
        for name, analyst in self.analysts.items():
            try:
                results[name] = analyst.analyze(data)
            except Exception as e:
                print(f"[AI团队] {analyst.name} 分析出错: {e}")
                results[name] = {'analyst': analyst.name, 'error': str(e), 'findings': []}
        
        # 整合分析结果
        consensus = self._build_consensus(results)
        
        print("[AI团队] 协同分析完成")
        return {
            'team_results': results,
            'consensus': consensus,
            'requirements': self.requirements
        }
    
    def _build_consensus(self, results: Dict) -> Dict:
        """整合各分析师的结论"""
        all_findings = []
        for analyst_name, result in results.items():
            if 'findings' in result:
                all_findings.extend(result['findings'])
        
        # 收集所有摘要
        summaries = []
        for analyst_name, result in results.items():
            if result.get('summary'):
                summaries.append(f"[{result.get('analyst', analyst_name)}] {result['summary']}")
        
        # 生成共识报告
        high_priority = [f for f in all_findings if f.get('severity') == 'HIGH']
        
        return {
            'total_findings': len(all_findings),
            'high_priority': high_priority,
            'analyst_summaries': summaries,
            'recommendations': self._generate_recommendations(results)
        }
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """生成建议"""
        recommendations = []
        
        # 从各分析师的发现中提取建议
        for analyst_name, result in results.items():
            if result.get('findings'):
                recommendations.append(f"参考{result.get('analyst', analyst_name)}的分析结果")
        
        return recommendations[:5]

class AIAnalyzer: 
    SECURITY_APIS = {'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'gettickcount', 'queryperformancecounter', 'outputdebugstring', 'virtualprotect', 'virtualallocex', 'writeprocessmemory', 'createremotethread'}
    
    def __init__(self, ollama:  OllamaClient, pe: PEAnalyzer, requirements: str = ""):
        self.ollama = ollama
        self.pe = pe
        self.requirements = requirements
        # Only create team manager if ollama is available
        self.team_manager = AITeamManager(ollama, requirements) if ollama.is_available() else None
    
    def analyze_function(self, func:  Function) -> Dict:
        result = {'address': hex(func.address), 'name': func.name, 'purpose': '', 'security':  False, 'risk':  'LOW', 'suggestion': ''}
        
        code = func.get_disasm(30)
        
        for api in self.SECURITY_APIS: 
            if api in code. lower():
                result['security'] = True
                result['risk'] = 'HIGH'
                break
        
        # 如果有需求，检查函数是否与需求相关
        if self.requirements:
            req_lower = self.requirements.lower()
            code_lower = code.lower()
            # 提取关键词：去除常见词汇，保留API名称和技术关键词
            keywords = [w for w in req_lower.split() if len(w) > 3 and w not in {'关注', '相关', '调用', '功能', '代码', '文件', '示例'}]
            # 检查关键词是否出现在代码中
            relevant = any(keyword in code_lower for keyword in keywords)
            if not relevant and not result['security']:
                # 如果不相关且不是安全相关，可以跳过详细分析
                return result
        
        if self.ollama.is_available():
            question = "分析这个函数的功能，判断是否是安全检查或保护机制，给出修改建议"
            if self.requirements:
                question = f"基于以下需求分析这个函数：\n{self.requirements}\n\n判断该函数是否与需求相关，如果相关请给出详细分析和修改建议。"
            resp = self.ollama.analyze_code(code, question, requirements=self.requirements)
            if resp:
                result['ai_analysis'] = resp
                func.ai_analysis = resp
        
        return result
    
    def analyze_patch_point(self, pp: PatchPoint) -> Dict:
        result = {'address':  hex(pp.address), 'type': pp.patch_type, 'risk': pp.risk_level, 'suggestion': ''}
        
        if self.ollama.is_available():
            ctx = self._get_context(pp. address, 5)
            goal = "绕过这个检查"
            if self.requirements:
                goal = f"基于需求绕过这个检查：\n{self.requirements}"
            resp = self.ollama.suggest_patch(pp. instruction, ctx, goal, requirements=self.requirements)
            if resp:
                result['ai_suggestion'] = resp
                pp.ai_suggestion = str(resp)
        
        return result
    
    def _get_context(self, addr: int, count: int) -> str:
        lines = []
        found = False
        c = 0
        for ins in self.pe. instructions:
            if ins.address == addr:
                found = True
            if found: 
                lines.append(str(ins))
                c += 1
                if c >= count: 
                    break
        return '\n'.join(lines)
    
    def full_analysis(self) -> AnalysisResult: 
        result = AnalysisResult(file_path=self.pe.path, file_hash=self.pe.get_hash(), timestamp=datetime.now().isoformat(), instruction_count=len(self.pe. instructions), function_count=len(self.pe. functions), imports=self.pe. imports)
        
        print("\n[AI分析] 分析函数...")
        sec_funcs = []
        
        # 如果有需求，优先分析与需求相关的函数
        funcs_to_analyze = list(self.pe.functions.items())[:50]
        if self.requirements:
            print(f"[AI分析] 使用需求文件进行针对性分析")
            # 可以在这里添加更智能的过滤逻辑，现在简单地分析前50个
            
        for addr, func in funcs_to_analyze: 
            analysis = self.analyze_function(func)
            if analysis. get('security'):
                sec_funcs.append(func)
                func.is_security_related = True
        print(f"[AI分析] 安全相关函数: {len(sec_funcs)}")
        
        print("[AI分析] 分析补丁点...")
        pa = PatchAnalyzer(self. pe)
        patches = pa.find_patches()
        result.patch_points = patches
        result.patch_point_count = len(patches)
        
        high_pri = pa.get_high_priority(10)
        for pp in high_pri:
            self.analyze_patch_point(pp)
        
        if len(sec_funcs) > 5 or len([p for p in patches if 'security' in p.patch_type]) > 3:
            result. risk_level = 'HIGH'
        elif len(sec_funcs) > 0:
            result. risk_level = 'MEDIUM'
        else:
            result.risk_level = 'LOW'
        
        result.functions = self.pe.functions
        
        # 使用 AI 团队进行协同分析
        if self.ollama.is_available() and self.team_manager:
            print("\n[AI分析] 启动AI团队协同分析...")
            team_data = {
                'instructions': self.pe.instructions,
                'functions': self.pe.functions,
                'imports': self.pe.imports,
                'patches': patches,
                'requirements': self.requirements
            }
            team_results = self.team_manager.run_full_analysis(team_data)
            
            # 将团队分析结果添加到AnalysisResult
            # 由于AnalysisResult没有team_analysis字段，我们将其添加到recommendations中
            consensus = team_results.get('consensus', {})
            if consensus.get('analyst_summaries'):
                result.recommendations.extend(consensus['analyst_summaries'][:3])
        
        if self.ollama. is_available():
            summary_ctx = f"文件: {self. pe.path}\n函数数:  {len(self. pe.functions)}\n安全函数: {len(sec_funcs)}\n补丁点:  {len(patches)}"
            if self.requirements:
                summary_ctx += f"\n\n调试需求:\n{self.requirements}"
            resp = self.ollama. generate(f"根据以下分析结果生成简要总结和修改建议:\n{summary_ctx}", system="你是逆向工程专家，用中文简洁回答")
            if resp:
                result.summary = resp
        
        return result


class X64DbgBridge:
    def __init__(self, port: int = 27042):
        self.port = port
        self.sock = None
        self.connected = False
    
    def connect(self) -> bool:
        try:
            self.sock = socket. socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect(('127.0.0.1', self.port))
            self.connected = True
            print(f"[x64dbg] 已连接到端口 {self. port}")
            return True
        except Exception as e:
            print(f"[x64dbg] 连接失败: {e}")
            return False
    
    def disconnect(self):
        if self.sock:
            self. sock.close()
            self.connected = False
    
    def send_cmd(self, cmd:  str) -> Optional[str]:
        if not self.connected:
            return None
        try: 
            self.sock.send((cmd + '\n').encode())
            return self.sock.recv(4096).decode()
        except: 
            return None
    
    def read_memory(self, addr:  int, size: int) -> Optional[bytes]:
        resp = self.send_cmd(f"readmem {addr: X} {size}")
        if resp:
            try:
                return bytes.fromhex(resp. strip())
            except:
                pass
        return None
    
    def write_memory(self, addr: int, data: bytes) -> bool:
        resp = self.send_cmd(f"writemem {addr:X} {data.hex()}")
        return resp and 'ok' in resp. lower()
    
    def set_breakpoint(self, addr: int) -> bool:
        resp = self.send_cmd(f"bp {addr:X}")
        return resp and 'ok' in resp.lower()
    
    def run(self) -> bool:
        resp = self.send_cmd("run")
        return resp is not None
    
    def step(self) -> bool:
        resp = self.send_cmd("step")
        return resp is not None
    
    def get_regs(self) -> Dict:
        resp = self.send_cmd("regs")
        if resp:
            regs = {}
            for line in resp. split('\n'):
                if '=' in line:
                    k, v = line. split('=', 1)
                    regs[k. strip()] = v.strip()
            return regs
        return {}


class PatchManager:
    def __init__(self, pe:  PEAnalyzer, bridge: Optional[X64DbgBridge] = None):
        self.pe = pe
        self.bridge = bridge
        self.applied:  List[PatchPoint] = []
        self.history: List[Tuple[PatchPoint, bytes]] = []
    
    def apply_patch(self, pp: PatchPoint, live:  bool = False) -> bool:
        if not pp.patched_bytes: 
            print(f"[补丁] 无补丁数据:  {pp}")
            return False
        
        if live and self.bridge and self.bridge.connected:
            if self.bridge.write_memory(pp.address, pp.patched_bytes):
                pp.status = PatchStatus.APPLIED
                self.applied.append(pp)
                self.history.append((pp, pp. original_bytes))
                print(f"[补丁] 已应用(实时): {pp}")
                return True
            else:
                pp.status = PatchStatus.FAILED
                return False
        else: 
            pp.status = PatchStatus. APPLIED
            self.applied.append(pp)
            self.history.append((pp, pp.original_bytes))
            print(f"[补丁] 已记录: {pp}")
            return True
    
    def revert_patch(self, pp: PatchPoint, live: bool = False) -> bool:
        if pp not in self.applied:
            return False
        
        if live and self. bridge and self.bridge.connected:
            if self.bridge. write_memory(pp.address, pp. original_bytes):
                pp.status = PatchStatus. REVERTED
                self.applied.remove(pp)
                print(f"[补丁] 已撤销(实时): {pp}")
                return True
            return False
        else:
            pp. status = PatchStatus.REVERTED
            self.applied. remove(pp)
            print(f"[补丁] 已撤销: {pp}")
            return True
    
    def save_to_file(self, output_path: str) -> bool:
        if not self.applied:
            print("[补丁] 无已应用补丁")
            return False
        
        try:
            data = bytearray(self. pe.data)
            for pp in self.applied:
                off = self.pe.va_to_offset(pp.address)
                if off < len(data):
                    data[off:off+len(pp.patched_bytes)] = pp.patched_bytes
            
            with open(output_path, 'wb') as f:
                f.write(data)
            print(f"[补丁] 已保存:  {output_path}")
            return True
        except Exception as e:
            print(f"[补丁] 保存失败: {e}")
            return False
    
    def export_script(self, path: str, fmt: str = 'python'):
        pa = PatchAnalyzer(self.pe)
        script = pa.generate_script(self.applied, fmt)
        with open(path, 'w') as f:
            f.write(script)
        print(f"[补丁] 脚本已导出: {path}")

class InteractiveShell:
    def __init__(self, config:  Config):
        self.config = config
        self.ollama:  Optional[OllamaClient] = None
        self.pe: Optional[PEAnalyzer] = None
        self. analyzer: Optional[AIAnalyzer] = None
        self. patch_analyzer: Optional[PatchAnalyzer] = None
        self.patch_mgr: Optional[PatchManager] = None
        self.bridge: Optional[X64DbgBridge] = None
        self.result: Optional[AnalysisResult] = None
        self. running = True
        self.requirements = config.requirements_content
    
    def run(self):
        self._banner()
        self.ollama = OllamaClient(self. config)
        
        while self.running:
            try:
                cmd = input("\n> ").strip()
                if not cmd:
                    continue
                self._execute(cmd)
            except KeyboardInterrupt: 
                print("\n使用 'quit' 退出")
            except Exception as e: 
                print(f"错误: {e}")
    
    def _banner(self):
        print("="*60)
        print("  AI x64dbg 辅助分析工具 v1.0")
        print("  输入 'help' 查看命令")
        print("="*60)
    
    def _execute(self, cmd:  str):
        parts = cmd.split()
        c = parts[0]. lower()
        args = parts[1:]
        
        commands = {
            'help': self._help, 'quit': self._quit, 'exit': self._quit,
            'load': self._load, 'analyze': self._analyze, 'info': self._info,
            'funcs': self._funcs, 'func': self._func, 'disasm': self._disasm,
            'patches': self._patches, 'patch': self._patch_cmd,
            'apply': self._apply, 'revert':  self._revert, 'save': self._save,
            'models': self._models, 'model': self._model,
            'connect': self._connect, 'disconnect': self._disconnect,
            'ai':  self._ai, 'export': self._export,
            'requirements': self._requirements, 'loadreq': self._loadreq
        }
        
        if c in commands:
            commands[c](args)
        else:
            print(f"未知命令: {c}")
    
    def _help(self, args):
        print("""
命令: 
  load <file>       加载PE文件
  analyze           执行AI分析
  info              显示文件信息
  funcs             列出函数
  func <addr>       显示函数详情
  disasm <addr> [n] 反汇编
  patches           显示补丁点
  patch <idx>       查看补丁详情
  apply <idx>       应用补丁
  revert <idx>      撤销补丁
  save <file>       保存修改后的文件
  export <file>     导出补丁脚本
  
AI命令:
  models            列出可用模型
  model <name>      切换模型
  ai <question>     询问AI
  
需求命令:
  requirements      查看当前调试需求
  loadreq <file>    加载需求文件
  
x64dbg命令:
  connect           连接x64dbg
  disconnect        断开连接
  
其他: 
  help              显示帮助
  quit              退出
""")
    
    def _quit(self, args):
        self.running = False
        if self.bridge:
            self.bridge. disconnect()
        print("再见!")
    
    def _load(self, args):
        if not args: 
            print("用法: load <file>")
            return
        path = ' '.join(args)
        self.pe = PEAnalyzer(path)
        if self.pe.load():
            self.pe.disassemble_code(self.config.max_instructions)
            self.pe.identify_functions()
            self.patch_analyzer = PatchAnalyzer(self.pe)
            self.patch_mgr = PatchManager(self.pe, self.bridge)
            print("文件已加载，使用 'analyze' 执行AI分析")
    
    def _analyze(self, args):
        if not self.pe:
            print("请先加载文件")
            return
        self.analyzer = AIAnalyzer(self. ollama, self. pe, requirements=self.requirements)
        self.result = self.analyzer. full_analysis()
        
        print(f"\n{'='*50}")
        print(f"风险级别: {self.result.risk_level}")
        print(f"补丁点: {self.result.patch_point_count}")
        if self.result.summary:
            print(f"\n摘要: {self.result.summary[: 500]}")
    
    def _info(self, args):
        if not self.pe:
            print("请先加载文件")
            return
        print(f"文件: {self.pe.path}")
        print(f"大小: {len(self.pe. data):,}")
        print(f"架构: {'x64' if self.pe.is_64 else 'x86'}")
        print(f"指令:  {len(self.pe. instructions)}")
        print(f"函数:  {len(self. pe.functions)}")
        print(f"导入: {len(self.pe.imports)}")
    
    def _funcs(self, args):
        if not self.pe:
            return
        for addr, f in list(self. pe.functions.items())[:30]:
            sec = "⚠️" if f.is_security_related else ""
            print(f"0x{addr:08X}:  {f.name} ({len(f.instructions)} instrs) {sec}")
        if len(self.pe.functions) > 30:
            print(f"... ({len(self.pe.functions)-30} more)")
    
    def _func(self, args):
        if not args or not self.pe:
            return
        try:
            addr = int(args[0], 16) if args[0]. startswith('0x') else int(args[0])
            if addr in self.pe.functions:
                f = self.pe. functions[addr]
                print(f"\n函数:  {f.name}")
                print(f"地址: 0x{f.address:08X}")
                print(f"大小: {f.size}")
                print(f"指令:  {len(f.instructions)}")
                if f.ai_analysis:
                    print(f"\nAI分析:\n{f.ai_analysis}")
                print(f"\n反汇编:")
                print(f. get_disasm(20))
        except: 
            print("无效地址")
    
    def _disasm(self, args):
        if not self.pe or not args:
            return
        try:
            addr = int(args[0], 16) if args[0].startswith('0x') else int(args[0])
            count = int(args[1]) if len(args) > 1 else 20
            started = False
            shown = 0
            for ins in self.pe.instructions:
                if ins.address >= addr:
                    started = True
                if started:
                    print(f"0x{ins.address:08X}: {ins.bytes_hex:20} {ins.mnemonic:8} {ins.op_str}")
                    shown += 1
                    if shown >= count:
                        break
        except:
            print("无效参数")
    
    def _patches(self, args):
        if not self.patch_analyzer:
            return
        patches = self.patch_analyzer.find_patches()
        hi = self.patch_analyzer.get_high_priority(20)
        print(f"\n高优先级补丁点 ({len(hi)}/{len(patches)}):\n")
        for i, pp in enumerate(hi):
            status = "✓" if pp.status == PatchStatus.APPLIED else " "
            print(f"[{i}] {status} 0x{pp.address:08X} {pp.patch_type:20} {pp.risk_level}")
    
    def _patch_cmd(self, args):
        if not args or not self.patch_analyzer:
            return
        try:
            idx = int(args[0])
            patches = self.patch_analyzer.get_high_priority(50)
            if 0 <= idx < len(patches):
                pp = patches[idx]
                print(f"\n地址: 0x{pp.address:08X}")
                print(f"类型: {pp. patch_type}")
                print(f"指令: {pp.instruction}")
                print(f"原始:  {pp.original_bytes.hex()}")
                print(f"补丁: {pp.patched_bytes.hex() if pp.patched_bytes else 'N/A'}")
                print(f"风险:  {pp.risk_level}")
                print(f"状态: {pp. status. name}")
                if pp.ai_suggestion:
                    print(f"\nAI建议:  {pp.ai_suggestion}")
        except:
            print("无效索引")
    
    def _apply(self, args):
        if not args or not self.patch_mgr or not self.patch_analyzer:
            return
        try: 
            idx = int(args[0])
            patches = self.patch_analyzer.get_high_priority(50)
            if 0 <= idx < len(patches):
                live = self.bridge and self.bridge. connected
                self.patch_mgr.apply_patch(patches[idx], live)
        except:
            print("无效索引")
    
    def _revert(self, args):
        if not args or not self.patch_mgr or not self.patch_analyzer:
            return
        try:
            idx = int(args[0])
            patches = self.patch_analyzer.get_high_priority(50)
            if 0 <= idx < len(patches):
                live = self.bridge and self.bridge.connected
                self.patch_mgr.revert_patch(patches[idx], live)
        except: 
            print("无效索引")
    
    def _save(self, args):
        if not args or not self.patch_mgr: 
            return
        self.patch_mgr.save_to_file(args[0])
    
    def _export(self, args):
        if not args or not self.patch_mgr: 
            return
        fmt = 'x64dbg' if 'x64dbg' in args[0] else 'python'
        self. patch_mgr. export_script(args[0], fmt)
    
    def _models(self, args):
        if self.ollama:
            print("可用模型:")
            for m in self.ollama.list_models():
                cur = " (当前)" if m == self.ollama. model else ""
                print(f"  {m}{cur}")
    
    def _model(self, args):
        if args and self.ollama:
            if self.ollama.switch_model(args[0]):
                print(f"已切换到:  {self.ollama.model}")
    
    def _connect(self, args):
        port = int(args[0]) if args else self.config.x64dbg_bridge_port
        self.bridge = X64DbgBridge(port)
        if self.bridge.connect():
            if self.patch_mgr: 
                self.patch_mgr.bridge = self.bridge
    
    def _disconnect(self, args):
        if self. bridge:
            self.bridge.disconnect()
            self.bridge = None
    
    def _ai(self, args):
        if not args or not self.ollama:
            return
        q = ' '.join(args)
        ctx = ""
        if self. pe and self.pe.instructions:
            ctx = '\n'.join(str(i) for i in self.pe.instructions[: 20])
        resp = self.ollama.analyze_code(ctx, q, requirements=self.requirements)
        if resp:
            print(f"\n{resp}")
    
    def _requirements(self, args):
        """查看当前调试需求"""
        if self.requirements:
            print(f"\n当前调试需求:\n{self.requirements}")
        else:
            print("\n未加载调试需求")
    
    def _loadreq(self, args):
        """动态加载需求文件"""
        if not args:
            print("用法: loadreq <file>")
            return
        path = ' '.join(args)
        content = load_requirements_file(path)
        if content:
            self.requirements = content
            self.config.requirements_file = path
            self.config.requirements_content = content
            print("需求已加载，重新分析以应用新需求")
def print_banner():
    deps = []
    for name, ok in DEPENDENCIES.items():
        deps.append(f"{'✓' if ok else '✗'} {name}")
    
    print(f"""
{'='*60}
    AI x64dbg 辅助分析工具 v1.0
    
    功能:  反汇编 | AI分析 | 补丁生成 | x64dbg集成
    
    依赖:  {' | '.join(deps)}
{'='*60}

用法:
  python x64-github.py analyze <file> [--txt requirements.txt]
  python x64-github.py interactive [--txt requirements.txt]
  python x64-github.py patch <in> <out> [--txt requirements.txt]
  
选项:
  --txt <file>      指定调试需求文件（.txt格式）
  --model <name>    指定AI模型
  --url <url>       指定Ollama地址
""")


def cmd_analyze(args:  List[str], config: Config):
    if len(args) < 1:
        print("用法:  analyze <file> [--txt requirements.txt]")
        return
    
    path = args[0]
    if not os.path. exists(path):
        print(f"文件不存在: {path}")
        return
    
    ollama = OllamaClient(config)
    pe = PEAnalyzer(path)
    
    if not pe.load():
        return
    
    pe.disassemble_code(config.max_instructions)
    pe.identify_functions()
    
    analyzer = AIAnalyzer(ollama, pe, requirements=config.requirements_content)
    result = analyzer.full_analysis()
    
    os.makedirs(config.output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    json_path = os. path.join(config.output_dir, f"analysis_{ts}.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result. to_dict(), f, indent=2, ensure_ascii=False)
    print(f"[*] 保存:  {json_path}")
    
    pa = PatchAnalyzer(pe)
    patches = pa. get_high_priority(20)
    
    script_path = os. path.join(config.output_dir, f"patch_{ts}.py")
    script = pa.generate_script(patches, 'python')
    with open(script_path, 'w') as f:
        f.write(script)
    print(f"[*] 补丁脚本:  {script_path}")
    
    x64_path = os.path.join(config. output_dir, f"patch_{ts}.x64dbg. txt")
    x64_script = pa.generate_script(patches, 'x64dbg')
    with open(x64_path, 'w') as f:
        f.write(x64_script)
    print(f"[*] x64dbg脚本: {x64_path}")
    
    print(f"\n{'='*50}")
    print(f"风险级别:  {result.risk_level}")
    print(f"补丁点: {result.patch_point_count}")
    print(f"\n高优先级修改点:")
    for i, pp in enumerate(patches[: 10]):
        print(f"  [{i}] 0x{pp.address:08X} {pp.patch_type}")


def cmd_interactive(config: Config):
    shell = InteractiveShell(config)
    shell.run()


def cmd_patch(args: List[str], config: Config):
    if len(args) < 2:
        print("用法: patch <input> <output>")
        return
    
    inp, out = args[0], args[1]
    
    pe = PEAnalyzer(inp)
    if not pe. load():
        return
    
    pe.disassemble_code(config.max_instructions)
    pe.identify_functions()
    
    pa = PatchAnalyzer(pe)
    patches = pa. get_high_priority(20)
    
    pm = PatchManager(pe)
    for pp in patches: 
        if 'security' in pp.patch_type:
            pm.apply_patch(pp)
    
    pm.save_to_file(out)


def main():
    print_banner()
    
    config = Config. load()
    
    if len(sys. argv) < 2:
        print("输入 'interactive' 进入交互模式，或查看上述用法")
        return
    
    # Parse all arguments to find command and options
    cmd = None
    cmd_args = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--model' and i+1 < len(sys.argv):
            config.default_model = sys. argv[i+1]
            i += 2
        elif arg == '--url' and i+1 < len(sys. argv):
            config.ollama_url = sys.argv[i+1]
            i += 2
        elif arg == '--txt' and i+1 < len(sys.argv):
            txt_file = sys.argv[i+1]
            if os.path.exists(txt_file):
                config.requirements_file = txt_file
                config.requirements_content = load_requirements_file(txt_file)
            else:
                print(f"[错误] 需求文件不存在: {txt_file}")
                return
            i += 2
        elif not cmd and arg in ['interactive', '-i', 'analyze', 'patch']:
            cmd = arg
            i += 1
        else:
            # This is a command argument
            cmd_args.append(arg)
            i += 1
    
    if not cmd:
        print("未指定命令")
        return
    
    if cmd == 'interactive' or cmd == '-i':
        cmd_interactive(config)
    elif cmd == 'analyze': 
        cmd_analyze(cmd_args, config)
    elif cmd == 'patch':
        cmd_patch(cmd_args, config)
    else:
        print(f"未知命令: {cmd}")


if __name__ == '__main__':
    main()
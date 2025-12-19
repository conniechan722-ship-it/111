#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto Patcher v1.0
自动补丁工具 - 基于 JSON 分析结果自动修补 PE 文件

支持的 JSON 来源：
- x64-github.py 生成的分析结果
- mix-github.py 生成的分析结果

用法:
  python auto-patcher.py <file>   生成报告文件
"""

import os
import sys
import json
import shutil
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum, auto

# 可选依赖
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


class PatchMode(Enum):
    """补丁模式"""
    ALL = auto()
    SECURITY = auto()
    HIGH_PRIORITY = auto()
    INTERACTIVE = auto()
    BY_TYPE = auto()
    BY_ADDRESS = auto()


@dataclass
class PatchEntry:
    """补丁条目"""
    address: int
    size: int
    original_bytes: bytes
    patched_bytes: bytes
    patch_type: str
    description: str
    risk_level: str = "MEDIUM"
    applied: bool = False
    verified: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PatchEntry':
        """从字典创建补丁条目"""
        # 解析地址
        addr = data.get('address', data.get('addr', '0x0'))
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith('0x') else int(addr)
        
        # 解析原始字节
        orig = data.get('original', data.get('original_bytes', data.get('orig', '')))
        if isinstance(orig, str):
            orig = bytes.fromhex(orig.replace(' ', '')) if orig else b''
        elif isinstance(orig, list):
            orig = bytes(orig)
        
        # 解析补丁字节
        patched = data.get('patched', data.get('patched_bytes', data.get('patch', '')))
        if isinstance(patched, str) and patched:
            patched = bytes.fromhex(patched.replace(' ', ''))
        elif isinstance(patched, list):
            patched = bytes(patched)
        elif not patched:
            # 默认用 NOP 填充
            size = data.get('size', len(orig))
            patched = b'\x90' * size
        
        return cls(
            address=addr,
            size=data.get('size', len(orig) if orig else 0),
            original_bytes=orig if orig else b'',
            patched_bytes=patched if patched else b'',
            patch_type=data.get('type', data.get('patch_type', 'unknown')),
            description=data.get('description', data.get('desc', '')),
            risk_level=data.get('risk_level', data.get('risk', 'MEDIUM')).upper()
        )


class JSONParser:
    """JSON 分析结果解析器"""
    
    @staticmethod
    def detect_format(data: Dict) -> str:
        """检测 JSON 格式来源"""
        if 'stats' in data and 'patch_points' in data:
            return 'x64-github'
        elif 'analysis' in data and 'patch_points' in data.get('analysis', {}):
            return 'mix-github'
        elif 'ai_team_analysis' in data:
            return 'mix-github'
        elif 'patch_points' in data:
            return 'generic'
        elif 'patches' in data or 'patch_entries' in data:
            return 'generic'
        return 'unknown'
    
    @staticmethod
    def parse(json_path: str) -> Tuple[Dict, List[PatchEntry]]:
        """解析 JSON 文件"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        fmt = JSONParser.detect_format(data)
        print(f"[*] 检测到格式: {fmt}")
        
        if fmt == 'x64-github':
            return JSONParser._parse_x64(data)
        elif fmt == 'mix-github':
            return JSONParser._parse_mix(data)
        else:
            return JSONParser._parse_generic(data)
    
    @staticmethod
    def _parse_x64(data: Dict) -> Tuple[Dict, List[PatchEntry]]:
        """解析 x64-github.py 格式"""
        meta = {
            'file': data.get('file', data.get('file_path', '')),
            'hash': data.get('hash', data.get('file_hash', '')),
            'timestamp': data.get('timestamp', ''),
            'stats': data.get('stats', {}),
            'risk_level': data.get('risk_level', 'UNKNOWN'),
            'summary': data.get('summary', '')
        }
        
        patches = []
        for pp in data.get('patch_points', []):
            try:
                patches.append(PatchEntry.from_dict(pp))
            except Exception as e:
                print(f"[警告] 解析补丁失败: {e}")
        
        return meta, patches
    
    @staticmethod
    def _parse_mix(data: Dict) -> Tuple[Dict, List[PatchEntry]]:
        """解析 mix-github.py 格式"""
        meta = {
            'file_info': data.get('file_info', {}),
            'ai_analysis': data.get('ai_team_analysis', {}),
        }
        
        patches = []
        # 尝试多个可能的路径
        patch_points = []
        if 'analysis' in data and 'patch_points' in data['analysis']:
            patch_points = data['analysis']['patch_points']
        elif 'patch_points' in data:
            patch_points = data['patch_points']
        
        for pp in patch_points:
            try:
                patches.append(PatchEntry.from_dict(pp))
            except Exception as e:
                print(f"[警告] 解析补丁失败: {e}")
        
        return meta, patches
    
    @staticmethod
    def _parse_generic(data: Dict) -> Tuple[Dict, List[PatchEntry]]:
        """解析通用格式"""
        patches = []
        patch_list = data.get('patches', data.get('patch_entries', data.get('patch_points', [])))
        for pp in patch_list:
            try:
                patches.append(PatchEntry.from_dict(pp))
            except:
                pass
        return data, patches


class PEPatcher:
    """PE 文件补丁器"""
    
    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self.data: bytearray = bytearray()
        self.pe = None
        self.image_base = 0
        self.sections = []
        
    def load(self) -> bool:
        """加载 PE 文件"""
        try:
            with open(self.pe_path, 'rb') as f:
                self.data = bytearray(f.read())
            print(f"[*] 已加载: {self.pe_path} ({len(self.data):,} 字节)")
            
            if HAS_PEFILE:
                try:
                    self.pe = pefile.PE(data=bytes(self.data))
                    self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
                    for s in self.pe.sections:
                        name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
                        self.sections.append({
                            'name': name,
                            'va': s.VirtualAddress,
                            'raw': s.PointerToRawData,
                            'size': s.SizeOfRawData
                        })
                    print(f"[*] Image Base: 0x{self.image_base:X}")
                    print(f"[*] Sections: {len(self.sections)}")
                except Exception as e:
                    print(f"[警告] PE 解析失败，使用原始模式: {e}")
            return True
        except Exception as e:
            print(f"[错误] 加载失败: {e}")
            return False
    
    def va_to_offset(self, va: int) -> int:
        """虚拟地址转文件偏移"""
        if self.pe:
            try:
                rva = va - self.image_base
                return self.pe.get_offset_from_rva(rva)
            except:
                pass
        # 如果没有 pefile 或转换失败，尝试简单计算
        if self.image_base and va >= self.image_base:
            rva = va - self.image_base
            for sec in self.sections:
                if sec['va'] <= rva < sec['va'] + sec['size']:
                    return sec['raw'] + (rva - sec['va'])
        return va  # 假设地址就是偏移
    
    def apply_patch(self, patch: PatchEntry, verify: bool = True) -> bool:
        """应用单个补丁"""
        try:
            offset = self.va_to_offset(patch.address)
            
            if offset < 0 or offset + patch.size > len(self.data):
                print(f"[错误] 无效偏移: 0x{offset:X} (地址: 0x{patch.address:X})")
                return False
            
            # 验证原始字节
            if verify and patch.original_bytes:
                current = bytes(self.data[offset:offset + len(patch.original_bytes)])
                if current != patch.original_bytes:
                    print(f"[警告] 0x{patch.address:X}: 原始字节不匹配")
                    print(f"  期望: {patch.original_bytes.hex()}")
                    print(f"  实际: {current.hex()}")
                    return False
            
            # 应用补丁
            patch_len = len(patch.patched_bytes)
            self.data[offset:offset + patch_len] = patch.patched_bytes
            patch.applied = True
            patch.verified = verify
            
            return True
        except Exception as e:
            print(f"[错误] 应用补丁失败 @ 0x{patch.address:X}: {e}")
            return False
    
    def save(self, output_path: str) -> bool:
        """保存修改后的文件"""
        try:
            with open(output_path, 'wb') as f:
                f.write(self.data)
            print(f"[*] 已保存: {output_path}")
            return True
        except Exception as e:
            print(f"[错误] 保存失败: {e}")
            return False
    
    def get_hash(self) -> str:
        """获取当前数据的 SHA256"""
        return hashlib.sha256(self.data).hexdigest()


class AutoPatcher:
    """自动补丁主类"""
    
    def __init__(self):
        self.meta: Dict = {}
        self.patches: List[PatchEntry] = []
        self.patcher: Optional[PEPatcher] = None
        self.applied_count = 0
        self.failed_count = 0
    
    def load_json(self, json_path: str) -> bool:
        """加载 JSON 分析结果"""
        if not os.path.exists(json_path):
            print(f"[错误] JSON 文件不存在: {json_path}")
            return False
        
        try:
            self.meta, self.patches = JSONParser.parse(json_path)
            print(f"[*] 加载了 {len(self.patches)} 个补丁点")
            return len(self.patches) > 0
        except Exception as e:
            print(f"[错误] 解析 JSON 失败: {e}")
            return False
    
    def load_pe(self, pe_path: str) -> bool:
        """加载目标 PE 文件"""
        self.patcher = PEPatcher(pe_path)
        return self.patcher.load()
    
    def filter_patches(self, mode: PatchMode, **kwargs) -> List[PatchEntry]:
        """根据模式筛选补丁"""
        if mode == PatchMode.ALL:
            return self.patches
        
        elif mode == PatchMode.SECURITY:
            keywords = ['security', 'debug', 'check', 'verify', 'auth', 'license', 
                       'protect', 'anti', 'crc', 'hash', 'validate']
            return [p for p in self.patches 
                   if any(k in p.patch_type.lower() or k in p.description.lower() 
                         for k in keywords)]
        
        elif mode == PatchMode.HIGH_PRIORITY:
            return [p for p in self.patches if p.risk_level in ('HIGH', 'CRITICAL')]
        
        elif mode == PatchMode.BY_TYPE:
            types = [t.lower().strip() for t in kwargs.get('types', [])]
            return [p for p in self.patches 
                   if any(t in p.patch_type.lower() for t in types)]
        
        elif mode == PatchMode.BY_ADDRESS:
            start = kwargs.get('start', 0)
            end = kwargs.get('end', 0xFFFFFFFF)
            return [p for p in self.patches if start <= p.address <= end]
        
        return self.patches
    
    def apply_patches(self, patches: List[PatchEntry], verify: bool = True) -> Tuple[int, int]:
        """应用补丁列表"""
        if not self.patcher:
            print("[错误] 请先加载 PE 文件")
            return 0, 0
        
        success = 0
        failed = 0
        
        for i, patch in enumerate(patches):
            status = f"[{i+1}/{len(patches)}] 0x{patch.address:08X} - {patch.patch_type}"
            print(f"{status}...", end=' ')
            if self.patcher.apply_patch(patch, verify):
                print("✓")
                success += 1
            else:
                print("✗")
                failed += 1
        
        self.applied_count = success
        self.failed_count = failed
        return success, failed
    
    def save(self, output_path: str) -> bool:
        """保存修改后的文件"""
        if not self.patcher:
            return False
        return self.patcher.save(output_path)
    
    def generate_report(self, output_path: str = None) -> str:
        """生成补丁报告"""
        lines = [
            "=" * 60,
            "Auto Patcher 补丁报告",
            "=" * 60,
            f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"补丁总数: {len(self.patches)}",
            f"成功应用: {self.applied_count}",
            f"应用失败: {self.failed_count}",
            "",
            "已应用的补丁:",
        ]
        
        for p in self.patches:
            if p.applied:
                lines.append(f"  [✓] 0x{p.address:08X} - {p.patch_type} ({p.risk_level})")
                if p.description:
                    lines.append(f"      {p.description[:60]}")
        
        lines.append("\n未应用的补丁:")
        for p in self.patches:
            if not p.applied:
                lines.append(f"  [✗] 0x{p.address:08X} - {p.patch_type}")
        
        report = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[*] 报告已保存: {output_path}")
        
        return report
    
    def interactive_select(self) -> List[PatchEntry]:
        """交互式选择补丁"""
        print("\n" + "=" * 50)
        print("交互式补丁选择")
        print("=" * 50)
        
        # 按类型分组统计
        by_type: Dict[str, List[PatchEntry]] = {}
        for p in self.patches:
            t = p.patch_type
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(p)
        
        print(f"\n补丁类型统计 (共 {len(self.patches)} 个):")
        type_list = list(by_type.keys())
        for i, t in enumerate(type_list):
            patches = by_type[t]
            high = len([p for p in patches if p.risk_level in ('HIGH', 'CRITICAL')])
            print(f"  {i+1}. {t}: {len(patches)} 个 (高风险: {high})")
        
        print("\n选项:")
        print("  a - 应用所有补丁")
        print("  s - 仅安全相关补丁")
        print("  h - 仅高优先级补丁")
        print("  t - 按类型选择")
        print("  m - 手动逐个选择")
        print("  q - 退出")
        
        choice = input("\n请选择: ").strip().lower()
        
        if choice == 'q':
            return []
        elif choice == 'a':
            return self.patches
        elif choice == 's':
            return self.filter_patches(PatchMode.SECURITY)
        elif choice == 'h':
            return self.filter_patches(PatchMode.HIGH_PRIORITY)
        elif choice == 't':
            print("\n输入类型编号 (逗号分隔):")
            indices = input("> ").strip()
            selected_types = []
            for idx in indices.split(','):
                try:
                    i = int(idx.strip()) - 1
                    if 0 <= i < len(type_list):
                        selected_types.append(type_list[i])
                except:
                    pass
            return self.filter_patches(PatchMode.BY_TYPE, types=selected_types)
        elif choice == 'm':
            selected = []
            print("\n逐个选择 (y=应用, n=跳过, q=完成):")
            for p in self.patches[:100]:  # 限制显示数量
                print(f"  0x{p.address:08X} {p.patch_type} - {p.description[:40]}")
                ans = input("  应用? [y/n/q]: ").strip().lower()
                if ans == 'q':
                    break
                elif ans == 'y':
                    selected.append(p)
            return selected
        
        return []


def print_banner():
    print("""
============================================================
    Auto Patcher v1.0
    
    基于 JSON 分析结果的自动补丁工具
    
    支持来源:
    - x64-github.py 生成的 JSON
    - mix-github.py 生成的 JSON
============================================================
""")


def print_usage():
    print("""
用法:
  python auto-patcher.py <file>   生成报告文件
  --list            仅列出补丁点，不应用

示例:
  python auto-patcher.py analysis.json target.exe
  python auto-patcher.py analysis.json target.exe patched.exe
  python auto-patcher.py analysis.json target.exe --mode security
  python auto-patcher.py analysis.json target.exe --mode interactive
  python auto-patcher.py analysis.json target.exe --type security_call --report report.txt
  python auto-patcher.py analysis.json target.exe --dry-run
""")


def main():
    print_banner()
    
    if len(sys.argv) < 3:
        print_usage()
        return
    
    # 解析参数
    json_path = sys.argv[1]
    pe_path = sys.argv[2]
    output_path = None
    
    mode = PatchMode.ALL
    types: List[str] = []
    verify = True
    backup = True
    dry_run = False
    report_path = None
    list_only = False
    
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--mode' and i + 1 < len(sys.argv):
            mode_str = sys.argv[i + 1].lower()
            mode_map = {
                'all': PatchMode.ALL,
                'security': PatchMode.SECURITY,
                'high': PatchMode.HIGH_PRIORITY,
                'interactive': PatchMode.INTERACTIVE
            }
            mode = mode_map.get(mode_str, PatchMode.ALL)
            i += 2
        elif arg == '--type' and i + 1 < len(sys.argv):
            types = [t.strip() for t in sys.argv[i + 1].split(',')]
            mode = PatchMode.BY_TYPE
            i += 2
        elif arg == '--no-verify':
            verify = False
            i += 1
        elif arg == '--no-backup':
            backup = False
            i += 1
        elif arg == '--dry-run':
            dry_run = True
            i += 1
        elif arg == '--report' and i + 1 < len(sys.argv):
            report_path = sys.argv[i + 1]
            i += 2
        elif arg == '--list':
            list_only = True
            i += 1
        elif not arg.startswith('--'):
            output_path = arg
            i += 1
        else:
            i += 1
    
    # 设置默认输出路径
    if not output_path:
        base, ext = os.path.splitext(pe_path)
        output_path = f"{base}.patched{ext}"
    
    # 创建 AutoPatcher
    patcher = AutoPatcher()
    
    # 加载 JSON
    if not patcher.load_json(json_path):
        print("[错误] 加载 JSON 失败或没有补丁点")
        return
    
    # 仅列出模式
    if list_only:
        print(f"\n补丁点列表 ({len(patcher.patches)} 个):")
        for p in patcher.patches:
            print(f"  0x{p.address:08X} [{p.risk_level:8}] {p.patch_type}")
            if p.description:
                print(f"    {p.description[:70]}")
        return
    
    # 加载 PE
    if not patcher.load_pe(pe_path):
        print("[错误] 加载 PE 失败")
        return
    
    # 筛选补丁
    if mode == PatchMode.INTERACTIVE:
        patches = patcher.interactive_select()
    elif mode == PatchMode.BY_TYPE:
        patches = patcher.filter_patches(mode, types=types)
    else:
        patches = patcher.filter_patches(mode)
    
    print(f"\n[*] 将应用 {len(patches)} 个补丁")
    
    if not patches:
        print("[*] 没有符合条件的补丁")
        return
    
    # 模拟运行
    if dry_run:
        print("[*] 模拟模式，不实际修改文件")
        print("\n将应用的补丁:")
        for p in patches:
            print(f"  [DRY] 0x{p.address:08X} - {p.patch_type}")
        return
    
    # 创建备份
    if backup and pe_path != output_path:
        backup_path = pe_path + '.backup'
        if not os.path.exists(backup_path):
            shutil.copy(pe_path, backup_path)
            print(f"[*] 备份: {backup_path}")
    
    # 应用补丁
    print("\n[*] 开始应用补丁...")
    success, failed = patcher.apply_patches(patches, verify)
    
    print(f"\n[*] 结果: 成功 {success}, 失败 {failed}")
    
    # 保存
    if success > 0:
        patcher.save(output_path)
        new_hash = patcher.patcher.get_hash()
        print(f"[*] 新文件 SHA256: {new_hash[:16]}...")
    
    # 生成报告
    if report_path:
        patcher.generate_report(report_path)
    
    print("\n[*] 完成!")


if __name__ == '__main__':
    main()

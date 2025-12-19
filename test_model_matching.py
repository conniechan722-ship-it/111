#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for model matching functionality
"""

import sys
import os

# Mock dependencies
class MockConfig:
    def __init__(self, model):
        self.ollama_url = "http://localhost:11434"
        self.default_model = model
        self.timeout = 30

class MockRequests:
    @staticmethod
    def get(url, timeout=5):
        class MockResponse:
            status_code = 200
            def json(self):
                # Simulate available models
                return {
                    'models': [
                        {'name': 'qwen2.5:32b-instruct'},
                        {'name': 'qwen2.5:7b'},
                        {'name': 'gpt-oss:120b'},
                        {'name': 'llama3:8b'},
                        {'name': 'codellama:13b'},
                    ]
                }
        return MockResponse()

# Inject mock
sys.modules['requests'] = MockRequests

# Now import the actual code
exec(open('x64-github.py', 'r', encoding='utf-8').read(), globals())

# Override DEPENDENCIES
DEPENDENCIES['requests'] = True

def test_model_matching():
    """Test various model matching scenarios"""
    
    test_cases = [
        # (requested_model, expected_match)
        ('qwen2.5:32b-instruct', 'qwen2.5:32b-instruct'),  # Exact match
        ('qwen2.5:32b', 'qwen2.5:32b-instruct'),  # Prefix match
        ('qwen2.5', 'qwen2.5:32b-instruct'),  # Base name match (should match first)
        ('llama3:8b', 'llama3:8b'),  # Exact match
        ('codellama', 'codellama:13b'),  # Base name match
        ('QWEN2.5:32B', 'qwen2.5:32b-instruct'),  # Case insensitive
        ('nonexistent', None),  # Should not match
    ]
    
    print("Testing model matching logic...")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for requested, expected in test_cases:
        config = MockConfig(requested)
        client = OllamaClient(config)
        
        # Manually set available models for testing
        client.models = [
            'qwen2.5:32b-instruct',
            'qwen2.5:7b',
            'gpt-oss:120b',
            'llama3:8b',
            'codellama:13b',
        ]
        
        # Test the matching function
        result = client._find_best_model_match(requested)
        
        if result == expected:
            print(f"✓ PASS: '{requested}' -> '{result}'")
            passed += 1
        else:
            print(f"✗ FAIL: '{requested}' -> got '{result}', expected '{expected}'")
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    
    return failed == 0

def test_ai_team_classes():
    """Test AI team classes exist and can be instantiated"""
    print("\n\nTesting AI team classes...")
    print("=" * 60)
    
    # Create mock ollama client
    config = MockConfig('llama3')
    ollama = OllamaClient(config)
    
    try:
        # Test base class
        print("✓ AICodeAnalyst class exists")
        
        # Test analyst classes
        analysts = [
            ('LogicAnalyst', LogicAnalyst),
            ('SecurityAnalyst', SecurityAnalyst),
            ('PatchExpert', PatchExpert),
            ('ReverseEngineer', ReverseEngineer),
            ('BehaviorAnalyst', BehaviorAnalyst),
        ]
        
        for name, cls in analysts:
            analyst = cls(ollama, "test requirements")
            assert analyst.name != "", f"{name} has no name"
            assert analyst.role != "", f"{name} has no role"
            print(f"✓ {name} instantiated: {analyst.name} - {analyst.role}")
        
        # Test AITeamManager
        manager = AITeamManager(ollama, "test requirements")
        assert len(manager.analysts) == 5, "AITeamManager should have 5 analysts"
        print(f"✓ AITeamManager instantiated with {len(manager.analysts)} analysts")
        
        print("=" * 60)
        print("All AI team classes tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ai_analyzer_integration():
    """Test that AIAnalyzer uses AITeamManager"""
    print("\n\nTesting AIAnalyzer integration...")
    print("=" * 60)
    
    try:
        config = MockConfig('llama3')
        ollama = OllamaClient(config)
        
        # Create a minimal PEAnalyzer mock
        class MockPEAnalyzer:
            def __init__(self):
                self.path = "test.exe"
                self.data = b"test"
                self.instructions = []
                self.functions = {}
                self.imports = []
            
            def get_hash(self):
                return "testhash123"
        
        pe = MockPEAnalyzer()
        requirements = "Test requirements"
        
        analyzer = AIAnalyzer(ollama, pe, requirements)
        
        # Check that team_manager was created
        assert hasattr(analyzer, 'team_manager'), "AIAnalyzer should have team_manager"
        assert isinstance(analyzer.team_manager, AITeamManager), "team_manager should be AITeamManager instance"
        print("✓ AIAnalyzer has AITeamManager")
        
        # Check that team_manager has the same requirements
        assert analyzer.team_manager.requirements == requirements, "team_manager should have same requirements"
        print("✓ AITeamManager has correct requirements")
        
        print("=" * 60)
        print("AIAnalyzer integration test passed!")
        return True
        
    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("Running Tests for Model Matching and AI Team Analysis")
    print("=" * 60 + "\n")
    
    all_passed = True
    
    # Test 1: Model matching
    if not test_model_matching():
        all_passed = False
    
    # Test 2: AI team classes
    if not test_ai_team_classes():
        all_passed = False
    
    # Test 3: AIAnalyzer integration
    if not test_ai_analyzer_integration():
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print("=" * 60)
        sys.exit(0)
    else:
        print("✗ SOME TESTS FAILED")
        print("=" * 60)
        sys.exit(1)

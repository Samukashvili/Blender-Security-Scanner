bl_info = {
    "name": "Blender Security Scanner",
    "author": "Giorgi Samukashvili",
    "version": (1, 0, 0),
    "blender": (4, 4, 0),
    "location": "File > Security Scan",
    "description": "Scans Python scripts in blend files for malicious code patterns",
    "category": "System",
}

import bpy
import re
import ast
import textwrap
from bpy.types import Operator, Panel, PropertyGroup
from bpy.props import BoolProperty, StringProperty, CollectionProperty, IntProperty
from bpy.app.handlers import persistent

# Enhanced malicious patterns with regex support for obfuscation detection
MALICIOUS_PATTERNS = {
    'subprocess_calls': [
        r'subprocess\.',
        r'import\s+subprocess',
        r'from\s+subprocess\s+import',
        r'sub(?:process|proc)', # Obfuscated variants
    ],
    'system_calls': [
        r'os\.system\s*\(',
        r'os\.popen\s*\(',
        r'os\.execv?\w*\s*\(',
        r'o\w*s\.\w*system',  # Obfuscated os.system
    ],
    'network_requests': [
        r'import\s+requests',
        r'from\s+requests\s+import',
        r'import\s+urllib',
        r'from\s+urllib\s+import',
        r'urlopen\s*\(',
        r'\.get\s*\(',
        r'\.post\s*\(',
        r'\.download\w*\s*\(',
        r'WebClient',
        r'u\w*r\w*l\w*l\w*i\w*b',  # Obfuscated urllib
    ],
    'encoding_operations': [
        r'base64\.',
        r'import\s+base64',
        r'from\s+base64\s+import',
        r'\.b64decode\s*\(',
        r'\.b64encode\s*\(',
        r'b\w*a\w*s\w*e\w*6\w*4',  # Obfuscated base64
    ],
    'code_execution': [
        r'exec\s*\(',
        r'eval\s*\(',
        r'compile\s*\(',
        r'e\w*x\w*e\w*c\s*\(',  # Obfuscated exec
        r'e\w*v\w*a\w*l\s*\(',  # Obfuscated eval
        r'\\x65\\x78\\x65\\x63',  # Hex encoded 'exec'
        r'\\u0065\\u0078\\u0065\\u0063',  # Unicode encoded 'exec'
        r'getattr\s*\(\s*__builtins__\s*,\s*[\'"]exec[\'"]',  # Dynamic access
        r'getattr\s*\(\s*__builtins__\s*,\s*[\'"]eval[\'"]',  # Dynamic access
    ],
    'timer_registration': [
        r'bpy\.app\.timers\.register',
        r'timers\.register',
        r't\w*i\w*m\w*e\w*r\w*s\.\w*r\w*e\w*g\w*i\w*s\w*t\w*e\w*r',  # Obfuscated
    ],
    'event_handlers': [
        r'bpy\.app\.handlers\.',
        r'handlers\.\w+\.append',
        r'load_post\.append',
        r'save_pre\.append',
        r'h\w*a\w*n\w*d\w*l\w*e\w*r\w*s',  # Obfuscated handlers
    ],
    'powershell_execution': [
        r'powershell',
        r'PowerShell',
        r'\.exe',
        r'cmd\.exe',
        r'WindowStyle\s+Hidden',
        r'p\w*o\w*w\w*e\w*r\w*s\w*h\w*e\w*l\w*l',  # Obfuscated powershell
    ],
    'file_operations': [
        r'open\s*\([^)]*["\']w["\']',
        r'\.write\s*\(',
        r'shutil\.',
        r'tempfile\.',
        r'w\w*r\w*i\w*t\w*e\s*\(',  # Obfuscated write
    ],
    'suspicious_strings': [
        r'workers\.dev',
        r'\.zip',
        r'TEMP',
        r'APPDATA',
        r'Startup',
        r'hidden',
        r'stealth',
        r'w\w*o\w*r\w*k\w*e\w*r\w*s',  # Obfuscated workers
    ]
}

# Critical patterns that should almost never be in blend files
CRITICAL_PATTERNS = {
    'shell_commands': [
        r'subprocess\.call',
        r'subprocess\.run',
        r'subprocess\.Popen',
        r'os\.system',
    ],
    'network_downloads': [
        r'\.download',
        r'requests\.get',
        r'urllib\.request',
        r'WebClient',
    ],
    'auto_execution': [
        r'bpy\.app\.timers\.register',
        r'load_post\.append',
    ]
}

class SecurityThreat(PropertyGroup):
    script_name: StringProperty(name="Script Name")
    threat_type: StringProperty(name="Threat Type")
    line_number: IntProperty(name="Line Number")
    code_snippet: StringProperty(name="Code Snippet")
    full_context: StringProperty(name="Full Context")  # More lines around the threat
    severity: StringProperty(name="Severity")
    pattern_matched: StringProperty(name="Pattern Matched")  # What pattern was detected

class WhitelistedScript(PropertyGroup):
    name: StringProperty(name="Script Name")
    reason: StringProperty(name="Whitelist Reason")

class SECURITY_OT_scan_blend_file(Operator):
    bl_idname = "security.scan_blend_file"
    bl_label = "Scan Current Blend File"
    bl_description = "Scan all Python scripts in the current blend file for malicious patterns"
    bl_options = {'REGISTER'}

    def execute(self, context):
        print("Security Scanner: Starting comprehensive scan...")
        
        # Debug: List all text blocks
        print(f"Found {len(bpy.data.texts)} text blocks:")
        for text_block in bpy.data.texts:
            print(f"  - {text_block.name} ({len(text_block.lines)} lines)")
        
        threats = self.scan_all_scripts()
        
        print(f"Security Scanner: Found {len(threats)} potential threats")
        
        if threats:
            # Store threats in scene properties for the dialog
            context.scene.security_threats.clear()
            for threat in threats:
                item = context.scene.security_threats.add()
                item.script_name = threat['script_name']
                item.threat_type = threat['threat_type']
                item.line_number = threat['line_number']
                item.code_snippet = threat['code_snippet']
                item.full_context = threat['full_context']
                item.severity = threat['severity']
                item.pattern_matched = threat['pattern_matched']
                print(f"  {threat['severity']}: {threat['threat_type']} in {threat['script_name']}:{threat['line_number']}")
                print(f"    Pattern: {threat['pattern_matched']}")
                print(f"    Context: {threat['code_snippet']}")
            
            # Show security dialog
            bpy.ops.security.show_threats_dialog('INVOKE_DEFAULT')
        else:
            self.report({'INFO'}, "✅ No security threats detected in Python scripts")
            print("Security Scanner: No threats detected")
        
        return {'FINISHED'}
    
    def scan_all_scripts(self):
        threats = []
        
        print(f"Scanning {len(bpy.data.texts)} text blocks...")
        
        # Get whitelisted scripts
        whitelisted_scripts = set()
        if hasattr(bpy.context.scene, 'security_whitelisted_scripts'):
            whitelisted_scripts = {item.name for item in bpy.context.scene.security_whitelisted_scripts}
        
        # Scan all text blocks in the blend file
        for text_block in bpy.data.texts:
            # Check if script is whitelisted
            if text_block.name in whitelisted_scripts:
                print(f"Skipping whitelisted script: {text_block.name}")
                continue
            
            # Always scan text blocks that end with .py or contain Python code
            should_scan = (text_block.name.endswith('.py') or 
                          self.contains_python_code(text_block) or
                          len(text_block.lines) > 0)  # Scan any non-empty text block
            
            if should_scan:
                print(f"Scanning text block: {text_block.name}")
                script_threats = self.scan_script(text_block)
                threats.extend(script_threats)
            else:
                print(f"Skipping text block: {text_block.name} (no Python code detected)")
        
        return threats
    
    def contains_python_code(self, text_block):
        """Check if text block contains Python code"""
        content = text_block.as_string()
        
        # Check for common Python patterns
        python_keywords = [
            'import ', 'from ', 'def ', 'class ', 'if __name__', 'bpy.',
            'subprocess', 'requests', 'base64', 'exec(', 'eval(',
            'os.system', 'timers.register', 'handlers.'
        ]
        
        # More lenient detection
        content_lower = content.lower()
        for keyword in python_keywords:
            if keyword.lower() in content_lower:
                return True
        
        return False
    
    def scan_script(self, text_block):
        """Scan a single script for malicious patterns with enhanced context"""
        threats = []
        content = text_block.as_string()
        lines = content.split('\n')
        
        print(f"Scanning {text_block.name} ({len(lines)} lines)")
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Get context around the suspicious line (3 lines before and after)
            context_start = max(0, line_num - 4)
            context_end = min(len(lines), line_num + 3)
            context_lines = []
            
            for i in range(context_start, context_end):
                prefix = ">>> " if i == line_num - 1 else "    "
                context_lines.append(f"{prefix}{i+1:3d}: {lines[i]}")
            
            full_context = "\n".join(context_lines)
            
            # Check critical patterns first
            for category, patterns in CRITICAL_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        print(f"  CRITICAL: Found '{pattern}' in line {line_num}")
                        threats.append({
                            'script_name': text_block.name,
                            'threat_type': f"CRITICAL: {category}",
                            'line_number': line_num,
                            'code_snippet': line_stripped[:150],
                            'full_context': full_context,
                            'severity': 'CRITICAL',
                            'pattern_matched': pattern
                        })
            
            # Check general malicious patterns
            for category, patterns in MALICIOUS_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        severity = 'HIGH' if category in ['subprocess_calls', 'system_calls', 'code_execution'] else 'MEDIUM'
                        print(f"  {severity}: Found '{pattern}' in line {line_num}")
                        threats.append({
                            'script_name': text_block.name,
                            'threat_type': category.replace('_', ' ').title(),
                            'line_number': line_num,
                            'code_snippet': line_stripped[:150],
                            'full_context': full_context,
                            'severity': severity,
                            'pattern_matched': pattern
                        })
        
        print(f"  Scan complete: {len(threats)} threats found in {text_block.name}")
        return threats

class SECURITY_OT_show_threats_dialog(Operator):
    bl_idname = "security.show_threats_dialog"
    bl_label = "Security Threats Detected"
    bl_description = "Show detected security threats and quarantine options"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        return {'FINISHED'}
    
    def invoke(self, context, event):
        return context.window_manager.invoke_props_dialog(self, width=600)
    
    def draw(self, context):
        layout = self.layout
        
        layout.label(text="⚠️ SECURITY THREATS DETECTED ⚠️", icon='ERROR')
        layout.separator()
        
        threats = context.scene.security_threats
        
        if len(threats) > 0:
            layout.label(text=f"Found {len(threats)} potential threats:")
            
            # Add health status indicator
            critical_count = sum(1 for t in threats if t.severity == 'CRITICAL')
            high_count = sum(1 for t in threats if t.severity == 'HIGH')
            medium_count = sum(1 for t in threats if t.severity == 'MEDIUM')
            
            status_box = layout.box()
            status_box.label(text="📊 Threat Summary:", icon='INFO')
            if critical_count > 0:
                status_box.label(text=f"🔴 Critical: {critical_count}", icon='CANCEL')
            if high_count > 0:
                status_box.label(text=f"🟠 High: {high_count}", icon='ERROR')
            if medium_count > 0:
                status_box.label(text=f"🟡 Medium: {medium_count}", icon='INFO')
            
            layout.separator()
            
            # Scrollable threat list
            box = layout.box()
            for i, threat in enumerate(threats):
                if i >= 10:  # Limit display to prevent UI overflow
                    remaining = len(threats) - 10
                    box.label(text=f"... and {remaining} more threats")
                    break
                    
                threat_box = box.box()
                
                # Severity color coding
                if threat.severity == 'CRITICAL':
                    threat_box.alert = True
                
                row = threat_box.row()
                severity_icon = 'CANCEL' if threat.severity == 'CRITICAL' else 'ERROR' if threat.severity == 'HIGH' else 'INFO'
                row.label(text=f"[{threat.severity}] {threat.threat_type}", icon=severity_icon)
                
                threat_box.label(text=f"📄 Script: {threat.script_name}")
                threat_box.label(text=f"📍 Line {threat.line_number}: {threat.code_snippet[:80]}...")
                threat_box.label(text=f"🔍 Pattern: {threat.pattern_matched}")
                
                # Show context button
                if threat.full_context:
                    threat_box.operator("security.show_threat_context", text="📋 Show Context").threat_index = i
                
                # Whitelist button for this script
                row = threat_box.row()
                whitelist_op = row.operator("security.whitelist_script", text="✅ Whitelist Script", icon='CHECKMARK')
                whitelist_op.script_name = threat.script_name
        
        layout.separator()
        
        # Action buttons
        row = layout.row()
        row.scale_y = 1.5
        
        op_quarantine = row.operator("security.quarantine_threats", text="🛡️ Quarantine All Threats", icon='LOCKED')
        op_keep = row.operator("security.keep_file", text="⚠️ Keep Anyway", icon='UNLOCKED')
        
        layout.separator()
        layout.label(text="⚠️ WARNING: Quarantining will comment out suspicious code!", icon='INFO')

class SECURITY_OT_show_threat_context(Operator):
    bl_idname = "security.show_threat_context"
    bl_label = "Show Threat Context"
    bl_description = "Show the full context around the detected threat"
    bl_options = {'REGISTER'}
    
    threat_index: IntProperty()

    def execute(self, context):
        threats = context.scene.security_threats
        if 0 <= self.threat_index < len(threats):
            threat = threats[self.threat_index]
            self.report({'INFO'}, f"Check console for context around line {threat.line_number}")
            print(f"\n=== THREAT CONTEXT: {threat.script_name} ===")
            print(f"Threat: {threat.threat_type}")
            print(f"Pattern: {threat.pattern_matched}")
            print(f"Severity: {threat.severity}")
            print("Context:")
            print(threat.full_context)
            print("=" * 50)
        return {'FINISHED'}

class SECURITY_OT_whitelist_script(Operator):
    bl_idname = "security.whitelist_script"
    bl_label = "Whitelist Script"
    bl_description = "Add this script to the whitelist to skip future scans"
    bl_options = {'REGISTER', 'UNDO'}
    
    script_name: StringProperty()

    def invoke(self, context, event):
        return context.window_manager.invoke_props_dialog(self, width=400)
    
    def draw(self, context):
        layout = self.layout
        layout.label(text=f"Whitelist '{self.script_name}'?", icon='QUESTION')
        layout.separator()
        layout.label(text="⚠️ Only whitelist scripts you trust!")
        layout.label(text="Whitelisted scripts will not be scanned for threats.")

    def execute(self, context):
        # Add to whitelist
        if not hasattr(context.scene, 'security_whitelisted_scripts'):
            return {'CANCELLED'}
        
        # Check if already whitelisted
        for item in context.scene.security_whitelisted_scripts:
            if item.name == self.script_name:
                self.report({'INFO'}, f"'{self.script_name}' is already whitelisted")
                return {'FINISHED'}
        
        # Add to whitelist
        item = context.scene.security_whitelisted_scripts.add()
        item.name = self.script_name
        item.reason = f"User whitelisted on {bpy.app.build_date}"
        
        self.report({'INFO'}, f"✅ Added '{self.script_name}' to whitelist")
        print(f"Security Scanner: Whitelisted script '{self.script_name}'")
        return {'FINISHED'}

class SECURITY_OT_manage_whitelist(Operator):
    bl_idname = "security.manage_whitelist"
    bl_label = "Manage Whitelist"
    bl_description = "Manage whitelisted scripts"
    bl_options = {'REGISTER'}

    def invoke(self, context, event):
        return context.window_manager.invoke_props_dialog(self, width=500)
    
    def draw(self, context):
        layout = self.layout
        layout.label(text="📋 Whitelisted Scripts", icon='DOCUMENTS')
        layout.separator()
        
        if hasattr(context.scene, 'security_whitelisted_scripts'):
            whitelist = context.scene.security_whitelisted_scripts
            if len(whitelist) == 0:
                layout.label(text="No scripts whitelisted")
            else:
                for i, item in enumerate(whitelist):
                    box = layout.box()
                    row = box.row()
                    row.label(text=f"📄 {item.name}")
                    remove_op = row.operator("security.remove_from_whitelist", text="", icon='X')
                    remove_op.index = i
                    if item.reason:
                        box.label(text=f"Reason: {item.reason}")

    def execute(self, context):
        return {'FINISHED'}

class SECURITY_OT_remove_from_whitelist(Operator):
    bl_idname = "security.remove_from_whitelist"
    bl_label = "Remove from Whitelist"
    bl_description = "Remove script from whitelist"
    bl_options = {'REGISTER', 'UNDO'}
    
    index: IntProperty()

    def execute(self, context):
        if hasattr(context.scene, 'security_whitelisted_scripts'):
            whitelist = context.scene.security_whitelisted_scripts
            if 0 <= self.index < len(whitelist):
                script_name = whitelist[self.index].name
                whitelist.remove(self.index)
                self.report({'INFO'}, f"Removed '{script_name}' from whitelist")
                print(f"Security Scanner: Removed '{script_name}' from whitelist")
        return {'FINISHED'}

class SECURITY_OT_quarantine_threats(Operator):
    bl_idname = "security.quarantine_threats"
    bl_label = "Quarantine Detected Threats"
    bl_description = "Comment out all detected malicious code patterns"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        threats = context.scene.security_threats
        quarantined_scripts = set()
        
        for threat in threats:
            script_name = threat.script_name
            if script_name in quarantined_scripts:
                continue
                
            text_block = bpy.data.texts.get(script_name)
            if text_block:
                self.quarantine_script(text_block, threats)
                quarantined_scripts.add(script_name)
        
        self.report({'INFO'}, f"🛡️ Quarantined {len(quarantined_scripts)} scripts")
        print(f"Security Scanner: Quarantined {len(quarantined_scripts)} scripts")
        
        # Clear threats after quarantine
        context.scene.security_threats.clear()
        
        return {'FINISHED'}
    
    def quarantine_script(self, text_block, all_threats):
        """Comment out the entire script with enhanced security warning"""
        original_content = text_block.as_string()
        
        # Get threats for this specific script
        script_threats = [t for t in all_threats if t.script_name == text_block.name]
        
        quarantine_header = f'''"""
⚠️⚠️⚠️ SECURITY QUARANTINE ⚠️⚠️⚠️
This script has been quarantined by Blender Security Scanner.
Potentially malicious patterns were detected.
DO NOT UNCOMMENT without thorough security review!

DETECTED THREATS:
'''
        
        for threat in script_threats:
            quarantine_header += f'''
- {threat.threat_type} (Line {threat.line_number})
  Pattern: {threat.pattern_matched}
  Severity: {threat.severity}
  Code: {threat.code_snippet[:60]}...
'''
        
        quarantine_header += f'''
Quarantine Date: {bpy.app.build_date}
Total Threats: {len(script_threats)}

Original script content below:
"""

'''
        
        # Comment out each line of original content
        commented_lines = []
        for line in original_content.split('\n'):
            commented_lines.append(f"# {line}")
        
        quarantined_content = quarantine_header + '\n'.join(commented_lines)
        
        # Replace content
        text_block.clear()
        text_block.write(quarantined_content)
    bl_idname = "security.quarantine_threats"
    bl_label = "Quarantine Detected Threats"
    bl_description = "Comment out all detected malicious code patterns"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        threats = context.scene.security_threats
        quarantined_scripts = set()
        
        for threat in threats:
            script_name = threat.script_name
            if script_name in quarantined_scripts:
                continue
                
            text_block = bpy.data.texts.get(script_name)
            if text_block:
                self.quarantine_script(text_block)
                quarantined_scripts.add(script_name)
        
        self.report({'INFO'}, f"Quarantined {len(quarantined_scripts)} scripts")
        
        # Clear threats after quarantine
        context.scene.security_threats.clear()
        
        return {'FINISHED'}
    
    def quarantine_script(self, text_block):
        """Comment out the entire script with security warning"""
        original_content = text_block.as_string()
        
        quarantine_header = '''"""
⚠️⚠️⚠️ SECURITY QUARANTINE ⚠️⚠️⚠️
This script has been quarantined by Blender Security Scanner.
Potentially malicious patterns were detected.
DO NOT UNCOMMENT without thorough security review!

Original script content below:
"""

'''
        
        # Comment out each line of original content
        commented_lines = []
        for line in original_content.split('\n'):
            commented_lines.append(f"# {line}")
        
        quarantined_content = quarantine_header + '\n'.join(commented_lines)
        
        # Replace content
        text_block.clear()
        text_block.write(quarantined_content)

class SECURITY_OT_clear_blocked_log(Operator):
    bl_idname = "security.clear_blocked_log"
    bl_label = "Clear Blocked Functions Log"
    bl_description = "Clear the log of blocked functions to see new blocks"
    bl_options = {'REGISTER'}

    def execute(self, context):
        global blocked_functions_log
        blocked_functions_log.clear()
        self.report({'INFO'}, "Cleared blocked functions log")
        print("🧹 Security Scanner: Cleared blocked functions log")
        return {'FINISHED'}

class SECURITY_OT_show_blocked_functions(Operator):
    bl_idname = "security.show_blocked_functions"
    bl_label = "Show Blocked Functions"
    bl_description = "Show all functions that have been blocked"
    bl_options = {'REGISTER'}

    def execute(self, context):
        global blocked_functions_log
        if blocked_functions_log:
            print("🚫 Security Scanner: Blocked functions:")
            for func_name in blocked_functions_log:
                print(f"  - {func_name}")
            self.report({'INFO'}, f"Blocked {len(blocked_functions_log)} unique functions - check console")
        else:
            self.report({'INFO'}, "No functions have been blocked yet")
            print("✅ Security Scanner: No functions blocked")
        return {'FINISHED'}

class SECURITY_OT_test_auto_scan(Operator):
    bl_idname = "security.test_auto_scan"
    bl_label = "Test Auto-Scan System"
    bl_description = "Test the automatic scanning system manually"
    bl_options = {'REGISTER'}

    def execute(self, context):
        self.report({'INFO'}, "Testing auto-scan system - check console")
        print("🧪 Security Scanner: Testing auto-scan system...")
        
        # Manually trigger the auto-scan system
        try:
            manual_auto_scan()
            print("✅ Auto-scan test completed")
        except Exception as e:
            print(f"❌ Auto-scan test failed: {e}")
        
        return {'FINISHED'}

class SECURITY_OT_test_addon(Operator):
    bl_idname = "security.test_addon"
    bl_label = "Test Security Addon"
    bl_description = "Quick test to verify the addon is working"
    bl_options = {'REGISTER'}

    def execute(self, context):
        self.report({'INFO'}, "🛡️ Security Scanner is working! Check console for details.")
        print("Security Scanner Test:")
        print(f"  Addon loaded and operational")
        print(f"  Found {len(bpy.data.texts)} text blocks")
        print(f"  Auto-scan enabled: {context.scene.get('security_auto_scan_enabled', True)}")
        print(f"  Original timer register available: {original_timer_register is not None}")
        
        # Test whitelist
        if hasattr(context.scene, 'security_whitelisted_scripts'):
            whitelist_count = len(context.scene.security_whitelisted_scripts)
            print(f"  Whitelisted scripts: {whitelist_count}")
        else:
            print("  Whitelist not initialized")
            
        return {'FINISHED'}

class SECURITY_OT_keep_file(Operator):
    bl_idname = "security.keep_file"
    bl_label = "Keep File With Threats"
    bl_description = "Keep the file as-is but be aware of security risks"
    bl_options = {'REGISTER'}

    def execute(self, context):
        self.report({'WARNING'}, "File kept with security threats - Use at your own risk!")
        context.scene.security_threats.clear()
        return {'FINISHED'}

class SECURITY_PT_panel(Panel):
    bl_label = "Security Scanner"
    bl_idname = "SECURITY_PT_panel"
    bl_space_type = 'TEXT_EDITOR'
    bl_region_type = 'UI'
    bl_category = "Security"

    @classmethod
    def poll(cls, context):
        return True

    def draw(self, context):
        layout = self.layout
        
        layout.label(text="🛡️ Blend File Security", icon='LOCKED')
        layout.separator()
        
        # Auto-scan toggle
        layout.prop(context.scene, "security_auto_scan_enabled", text="Auto-scan on file load")
        layout.separator()
        
        # Main scan button
        col = layout.column()
        col.scale_y = 1.5
        col.operator("security.scan_blend_file", icon='ZOOM_SELECTED')
        
        layout.separator()
        
        # File health status
        threats = context.scene.security_threats
        if len(threats) > 0:
            critical_count = sum(1 for t in threats if t.severity == 'CRITICAL')
            high_count = sum(1 for t in threats if t.severity == 'HIGH')
            medium_count = sum(1 for t in threats if t.severity == 'MEDIUM')
            
            status_box = layout.box()
            status_box.alert = critical_count > 0
            status_box.label(text="📊 Security Status: THREATS DETECTED", icon='ERROR')
            
            if critical_count > 0:
                status_box.label(text=f"🔴 Critical: {critical_count}")
            if high_count > 0:
                status_box.label(text=f"🟠 High: {high_count}")
            if medium_count > 0:
                status_box.label(text=f"🟡 Medium: {medium_count}")
                
            status_box.operator("security.show_threats_dialog", text="View All Threats", icon='VIEWZOOM')
        else:
            status_box = layout.box()
            status_box.label(text="✅ Security Status: CLEAN", icon='CHECKMARK')
        
        layout.separator()
        
        # Whitelist management
        layout.label(text="📋 Whitelist Management:", icon='DOCUMENTS')
        whitelist_box = layout.box()
        
        if hasattr(context.scene, 'security_whitelisted_scripts'):
            whitelist_count = len(context.scene.security_whitelisted_scripts)
            whitelist_box.label(text=f"Whitelisted Scripts: {whitelist_count}")
        else:
            whitelist_box.label(text="Whitelist: Not initialized")
            
        whitelist_box.operator("security.manage_whitelist", text="Manage Whitelist", icon='SETTINGS')
        
        layout.separator()
        
        # Test and management buttons
        layout.label(text="🔧 Tools & Testing:", icon='TOOL_SETTINGS')
        tools_box = layout.box()
        
        row = tools_box.row(align=True)
        row.operator("security.test_addon", text="Test", icon='CONSOLE')
        row.operator("security.test_auto_scan", text="Auto-Scan", icon='PLAY')
        
        row = tools_box.row(align=True)
        row.operator("security.show_blocked_functions", text="Blocked", icon='VIEWZOOM')
        row.operator("security.clear_blocked_log", text="Clear", icon='X')

# Alternative panel for 3D Viewport
class SECURITY_PT_panel_3d(Panel):
    bl_label = "Security Scanner"
    bl_idname = "SECURITY_PT_panel_3d"
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_category = "Security"

    @classmethod
    def poll(cls, context):
        return True

    def draw(self, context):
        layout = self.layout
        
        layout.label(text="Blend File Security", icon='LOCKED')
        layout.separator()
        
        # Auto-scan toggle
        layout.prop(context.scene, "security_auto_scan_enabled", text="Auto-scan on file load")
        layout.separator()
        
        col = layout.column()
        col.scale_y = 1.5
        col.operator("security.scan_blend_file", icon='ZOOM_SELECTED')
        
        layout.separator()
        row = layout.row(align=True)
        row.operator("security.test_addon", text="Test Addon", icon='CONSOLE')
        row.operator("security.test_auto_scan", text="Test Auto-Scan", icon='PLAY')
        layout.separator()
        
        # Show current threats if any
        threats = context.scene.security_threats
        if len(threats) > 0:
            layout.label(text=f"⚠️ {len(threats)} threats detected!", icon='ERROR')
            layout.operator("security.show_threats_dialog", text="View Threats", icon='VIEWZOOM')

# Menu item in File menu
class SECURITY_MT_menu(bpy.types.Menu):
    bl_label = "Security Scanner"
    bl_idname = "SECURITY_MT_menu"

    def draw(self, context):
        layout = self.layout
        layout.operator("security.scan_blend_file", icon='LOCKED')
        layout.separator()
        layout.operator("security.test_addon", icon='CONSOLE')
        layout.operator("security.test_auto_scan", icon='PLAY')
        layout.separator()
        layout.operator("security.show_blocked_functions", icon='VIEWZOOM')
        layout.operator("security.clear_blocked_log", icon='X')

def menu_func(self, context):
    self.layout.separator()
    self.layout.menu("SECURITY_MT_menu", icon='LOCKED')

@persistent
def security_scan_on_load(dummy):
    """Automatically scan for threats when loading a file"""
    print("🔄 Security Scanner: File load detected")
    
    # Check if auto-scan is enabled
    try:
        auto_scan_enabled = bpy.context.scene.get('security_auto_scan_enabled', True)
        if not auto_scan_enabled:
            print("🔄 Security Scanner: Auto-scan disabled in settings")
            return
    except:
        print("🔄 Security Scanner: Using default auto-scan setting (enabled)")
    
    # Schedule delayed scan
    if original_timer_register:
        original_timer_register(delayed_security_scan, first_interval=0.5)
        print("🔄 Security Scanner: Scheduled delayed scan (0.5s)")
    else:
        print("❌ Security Scanner: Cannot schedule auto-scan - timer override issue")

def delayed_security_scan():
    """Delayed security scan to run after file load"""
    print("🔍 Security Scanner: Running auto-scan...")
    
    try:
        # Ensure we have a valid context
        if not bpy.context or not bpy.context.scene:
            print("❌ Security Scanner: No valid context for auto-scan")
            return None
        
        # Check if there are any text blocks to scan
        text_blocks = bpy.data.texts
        if not text_blocks:
            print("📝 Security Scanner: No text blocks found")
            return None
        
        print(f"📝 Security Scanner: Found {len(text_blocks)} text blocks")
        
        # Check for Python-like content
        python_scripts = []
        for text_block in text_blocks:
            content = text_block.as_string().lower()
            if (text_block.name.endswith('.py') or 
                'import' in content or 'def ' in content or 'bpy.' in content or
                'subprocess' in content or 'requests' in content or 'base64' in content):
                python_scripts.append(text_block)
                print(f"  📄 Found Python-like content: {text_block.name}")
        
        if python_scripts:
            print(f"🔍 Security Scanner: Auto-scanning {len(python_scripts)} Python scripts...")
            
            # Try to run the scan operator
            try:
                bpy.ops.security.scan_blend_file()
                print("✅ Security Scanner: Auto-scan completed successfully")
            except Exception as op_error:
                print(f"❌ Security Scanner: Operator failed - {op_error}")
                
                # Fallback: Manual scan without operator
                print("🔄 Security Scanner: Attempting fallback scan...")
                manual_auto_scan()
        else:
            print("📝 Security Scanner: No Python scripts detected for auto-scan")
            
    except Exception as e:
        print(f"❌ Security Scanner auto-scan error: {e}")
        import traceback
        traceback.print_exc()
    
    return None  # Don't repeat timer

def manual_auto_scan():
    """Manual fallback scan when operator fails"""
    try:
        # Create a temporary instance of the scan operator
        scan_op = SECURITY_OT_scan_blend_file()
        threats = scan_op.scan_all_scripts()
        
        if threats:
            print(f"⚠️ Auto-scan found {len(threats)} threats!")
            for threat in threats:
                print(f"  🚨 {threat['severity']}: {threat['threat_type']} in {threat['script_name']}")
            
            # Store in scene if possible and context is available
            if bpy.context and hasattr(bpy.context, 'scene') and bpy.context.scene:
                try:
                    # Clear existing threats
                    bpy.context.scene.security_threats.clear()
                    
                    # Add new threats
                    for threat in threats:
                        item = bpy.context.scene.security_threats.add()
                        item.script_name = threat['script_name']
                        item.threat_type = threat['threat_type']
                        item.line_number = threat['line_number']
                        item.code_snippet = threat['code_snippet']
                        item.severity = threat['severity']
                    
                    print("💾 Threats stored in scene properties")
                except Exception as storage_error:
                    print(f"⚠️ Could not store threats in scene: {storage_error}")
            else:
                print("⚠️ No valid scene context - threats not stored but still detected")
        else:
            print("✅ Auto-scan: No threats detected")
            
    except Exception as e:
        print(f"❌ Manual auto-scan failed: {e}")
        # Print more detailed error info
        import traceback
        traceback.print_exc()

# Prevent auto-execution by overriding dangerous functions
original_timer_register = None
blocked_functions_log = set()  # Track what we've already logged

# Whitelist of legitimate Blender functions that should be allowed
LEGITIMATE_TIMER_FUNCTIONS = {
    'client_communication_timer',  # Blender internal
    'timer_image_cleanup',         # Blender internal  
    'queue_worker',               # Blender internal
    'bg_update',                  # Blender internal
    'delayed_security_scan',      # Our own security function
    'update_fps',                 # Blender internal
    'modal_timer',               # Blender modal operators
    'auto_save',                 # Blender auto-save
    'render_timer',              # Rendering system
    'animation_timer',           # Animation system
}

def safe_timer_register(func, *args, **kwargs):
    """Safe wrapper for timer registration"""
    func_name = getattr(func, '__name__', str(func))
    
    # Allow our own security scanner timers
    if func_name == 'delayed_security_scan':
        return original_timer_register(func, *args, **kwargs)
    
    # Allow whitelisted legitimate functions
    if func_name in LEGITIMATE_TIMER_FUNCTIONS:
        return original_timer_register(func, *args, **kwargs)
    
    # Block and log suspicious functions (but only once per function)
    if func_name not in blocked_functions_log:
        print(f"⚠️ SECURITY: Blocked timer registration for suspicious function: {func_name}")
        blocked_functions_log.add(func_name)
    
    return None

def safe_handler_append(handler_func, *args, **kwargs):
    """Safe wrapper for handler registration"""
    func_name = getattr(handler_func, '__name__', str(handler_func))
    
    # Only log once per function
    if func_name not in blocked_functions_log:
        print(f"⚠️ SECURITY: Blocked handler registration for suspicious function: {func_name}")
        blocked_functions_log.add(func_name)
    
    return None

classes = [
    SecurityThreat,
    WhitelistedScript,
    SECURITY_OT_scan_blend_file,
    SECURITY_OT_show_threats_dialog,
    SECURITY_OT_show_threat_context,
    SECURITY_OT_whitelist_script,
    SECURITY_OT_manage_whitelist,
    SECURITY_OT_remove_from_whitelist,
    SECURITY_OT_quarantine_threats,
    SECURITY_OT_test_addon,
    SECURITY_OT_test_auto_scan,
    SECURITY_OT_clear_blocked_log,
    SECURITY_OT_show_blocked_functions,
    SECURITY_OT_keep_file,
    SECURITY_PT_panel,
    SECURITY_PT_panel_3d,
    SECURITY_MT_menu,
]

def register():
    global original_timer_register
    
    print("Security Scanner: Registering addon...")
    
    for cls in classes:
        bpy.utils.register_class(cls)
        print(f"  Registered {cls.__name__}")
    
    # Add menu to File menu
    bpy.types.TOPBAR_MT_file.append(menu_func)
    print("  Added File menu item")
    
    # Add collection properties for storing threats and whitelist
    bpy.types.Scene.security_threats = CollectionProperty(type=SecurityThreat)
    bpy.types.Scene.security_whitelisted_scripts = CollectionProperty(type=WhitelistedScript)
    bpy.types.Scene.security_auto_scan_enabled = BoolProperty(
        name="Auto-scan on file load",
        description="Automatically scan for security threats when loading blend files",
        default=True
    )
    
    # Register load handler for automatic scanning
    bpy.app.handlers.load_post.append(security_scan_on_load)
    print("  Registered load handler")
    
    # Override dangerous functions to prevent auto-execution
    if hasattr(bpy.app.timers, 'register'):
        original_timer_register = bpy.app.timers.register
        bpy.app.timers.register = safe_timer_register
        print("  Overrode timer registration (with whitelist for legitimate functions)")
    else:
        print("  No timers.register found to override")
    
    print("🛡️ Blender Security Scanner activated successfully!")
    print("📍 Access via:")
    print("   • File > Security Scanner")
    print("   • 3D Viewport N-panel > Security tab")
    print("   • Text Editor N-panel > Security tab")
    print("   • Python Console: bpy.ops.security.scan_blend_file()")
    print("Auto-scan will trigger when loading blend files with Python scripts")
    print("Timer protection active - legitimate Blender functions whitelisted")

def unregister():
    global original_timer_register, blocked_functions_log
    
    # Clear the blocked functions log
    blocked_functions_log.clear()
    
    # Restore original timer registration
    if original_timer_register and hasattr(bpy.app.timers, 'register'):
        bpy.app.timers.register = original_timer_register
        print("  Restored original timer registration")
    
    # Remove File menu item
    bpy.types.TOPBAR_MT_file.remove(menu_func)
    
    # Remove load handler
    if security_scan_on_load in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.remove(security_scan_on_load)
    
    # Remove scene properties
    del bpy.types.Scene.security_threats
    del bpy.types.Scene.security_whitelisted_scripts
    del bpy.types.Scene.security_auto_scan_enabled
    
    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)
    
    print("Blender Security Scanner deactivated")

if __name__ == "__main__":
    register()
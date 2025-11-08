#!/usr/bin/env python3
"""
SNMP Browser - Production Ready Enhanced
Professional SNMP Browser with complete v1/v2c/v3 support
Includes logging, credentials encryption, memory management, trap receiver,
performance metrics, batch operations, MIB compilation and multiple profiles
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import time
import json
import os
import sys
import logging
import hashlib
import base64
import secrets
import gc
import traceback
from typing import Dict, List, Optional, Any, Tuple
import ipaddress
import socket
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import psutil
import queue
import struct
import re
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv

# Import SNMPY library
from snmpy import *
import webbrowser

# For performance graphs
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

class MibParser:
    """MIB Parser for descriptive names"""
    
    def __init__(self, logger):
        self.logger = logger
        self.mib_definitions = {}
        self.custom_mibs = {}
        self.load_builtin_mibs()
        
    def load_builtin_mibs(self):
        """Load builtin MIBs for UPS and other common devices"""
        # RFC1628 UPS-MIB
        self.mib_definitions.update({
    # RFC 1628 - UPS MIB Standard
    "1.3.6.1.2.1.33.1.1.1.0": "upsIdentManufacturer",
    "1.3.6.1.2.1.33.1.1.2.0": "upsIdentModel",
    "1.3.6.1.2.1.33.1.1.3.0": "upsIdentUPSSoftwareVersion",
    "1.3.6.1.2.1.33.1.1.4.0": "upsIdentAgentSoftwareVersion",
    "1.3.6.1.2.1.33.1.1.5.0": "upsIdentName",
    "1.3.6.1.2.1.33.1.1.6.0": "upsIdentAttachedDevices",
    "1.3.6.1.2.1.33.1.2.1.0": "upsBatteryStatus",
    "1.3.6.1.2.1.33.1.2.2.0": "upsSecondsOnBattery",
    "1.3.6.1.2.1.33.1.2.3.0": "upsEstimatedMinutesRemaining",
    "1.3.6.1.2.1.33.1.2.4.0": "upsEstimatedChargeRemaining",
    "1.3.6.1.2.1.33.1.2.5.0": "upsBatteryVoltage",
    "1.3.6.1.2.1.33.1.2.6.0": "upsBatteryCurrent",
    "1.3.6.1.2.1.33.1.2.7.0": "upsBatteryTemperature",
    "1.3.6.1.2.1.33.1.3.1.0": "upsInputLineBads",
    "1.3.6.1.2.1.33.1.3.2.0": "upsInputNumLines",
    "1.3.6.1.2.1.33.1.3.3.1.2": "upsInputFrequency",
    "1.3.6.1.2.1.33.1.3.3.1.3": "upsInputVoltage",
    "1.3.6.1.2.1.33.1.3.3.1.4": "upsInputCurrent",
    "1.3.6.1.2.1.33.1.3.3.1.5": "upsInputTruePower",
    "1.3.6.1.2.1.33.1.4.1.0": "upsOutputSource",
    "1.3.6.1.2.1.33.1.4.2.0": "upsOutputFrequency",
    "1.3.6.1.2.1.33.1.4.3.0": "upsOutputNumLines",
    "1.3.6.1.2.1.33.1.4.4.1.2": "upsOutputVoltage",
    "1.3.6.1.2.1.33.1.4.4.1.3": "upsOutputCurrent",
    "1.3.6.1.2.1.33.1.4.4.1.4": "upsOutputPower",
    "1.3.6.1.2.1.33.1.4.4.1.5": "upsOutputPercentLoad",
    "1.3.6.1.2.1.33.1.5.1.0": "upsBypassFrequency",
    "1.3.6.1.2.1.33.1.5.2.0": "upsBypassNumLines",
    "1.3.6.1.2.1.33.1.5.3.1.2": "upsBypassVoltage",
    "1.3.6.1.2.1.33.1.5.3.1.3": "upsBypassCurrent",
    "1.3.6.1.2.1.33.1.5.3.1.4": "upsBypassPower",
    "1.3.6.1.2.1.33.1.6.1.0": "upsAlarmsPresent",
    "1.3.6.1.2.1.33.1.6.2.1.2": "upsAlarmDescr",
    "1.3.6.1.2.1.33.1.6.2.1.3": "upsAlarmTime",
    "1.3.6.1.2.1.33.1.7.1.0": "upsTestId",
    "1.3.6.1.2.1.33.1.7.2.0": "upsTestSpinLock",
    "1.3.6.1.2.1.33.1.7.3.0": "upsTestResultsSummary",
    "1.3.6.1.2.1.33.1.7.4.0": "upsTestResultsDetail",
    "1.3.6.1.2.1.33.1.7.5.0": "upsTestStartTime",
    "1.3.6.1.2.1.33.1.7.6.0": "upsTestElapsedTime",
    "1.3.6.1.2.1.33.1.8.1.0": "upsShutdownType",
    "1.3.6.1.2.1.33.1.8.2.0": "upsShutdownAfterDelay",
    "1.3.6.1.2.1.33.1.8.3.0": "upsStartupAfterDelay",
    "1.3.6.1.2.1.33.1.8.4.0": "upsRebootWithDuration",
    "1.3.6.1.2.1.33.1.8.5.0": "upsAutoRestart",
    "1.3.6.1.2.1.33.1.9.1.0": "upsConfigInputVoltage",
    "1.3.6.1.2.1.33.1.9.2.0": "upsConfigInputFreq",
    "1.3.6.1.2.1.33.1.9.3.0": "upsConfigOutputVoltage",
    "1.3.6.1.2.1.33.1.9.4.0": "upsConfigOutputFreq",
    "1.3.6.1.2.1.33.1.9.5.0": "upsConfigOutputVA",
    "1.3.6.1.2.1.33.1.9.6.0": "upsConfigOutputPower",
    "1.3.6.1.2.1.33.1.9.7.0": "upsConfigLowBattTime",
    "1.3.6.1.2.1.33.1.9.8.0": "upsConfigAudibleStatus",
    "1.3.6.1.2.1.33.1.9.9.0": "upsConfigLowVoltageTransferPoint",
    "1.3.6.1.2.1.33.1.9.10.0": "upsConfigHighVoltageTransferPoint",
    
    # APC UPS Enterprise OIDs
    "1.3.6.1.4.1.318.1.1.1.1.1.1.0": "upsBasicIdentModel",
    "1.3.6.1.4.1.318.1.1.1.1.1.2.0": "upsBasicIdentName",
    "1.3.6.1.4.1.318.1.1.1.2.1.1.0": "upsBasicBatteryStatus",
    "1.3.6.1.4.1.318.1.1.1.2.1.2.0": "upsBasicBatteryTimeOnBattery",
    "1.3.6.1.4.1.318.1.1.1.2.1.3.0": "upsBasicBatteryLastReplaceDate",
    "1.3.6.1.4.1.318.1.1.1.2.2.1.0": "upsAdvBatteryCapacity",
    "1.3.6.1.4.1.318.1.1.1.2.2.2.0": "upsAdvBatteryTemperature",
    "1.3.6.1.4.1.318.1.1.1.2.2.3.0": "upsAdvBatteryRunTimeRemaining",
    "1.3.6.1.4.1.318.1.1.1.2.2.4.0": "upsAdvBatteryReplaceIndicator",
    "1.3.6.1.4.1.318.1.1.1.2.2.5.0": "upsAdvBatteryNumOfBattPacks",
    "1.3.6.1.4.1.318.1.1.1.2.2.6.0": "upsAdvBatteryNumOfBadBattPacks",
    "1.3.6.1.4.1.318.1.1.1.3.1.1.0": "upsBasicInputPhase",
    "1.3.6.1.4.1.318.1.1.1.3.2.1.0": "upsAdvInputLineVoltage",
    "1.3.6.1.4.1.318.1.1.1.3.2.2.0": "upsAdvInputMaxLineVoltage",
    "1.3.6.1.4.1.318.1.1.1.3.2.3.0": "upsAdvInputMinLineVoltage",
    "1.3.6.1.4.1.318.1.1.1.3.2.4.0": "upsAdvInputFrequency",
    "1.3.6.1.4.1.318.1.1.1.3.2.5.0": "upsAdvInputLineFailCause",
    "1.3.6.1.4.1.318.1.1.1.4.1.1.0": "upsBasicOutputStatus",
    "1.3.6.1.4.1.318.1.1.1.4.1.2.0": "upsBasicOutputPhase",
    "1.3.6.1.4.1.318.1.1.1.4.2.1.0": "upsAdvOutputVoltage",
    "1.3.6.1.4.1.318.1.1.1.4.2.2.0": "upsAdvOutputFrequency",
    "1.3.6.1.4.1.318.1.1.1.4.2.3.0": "upsAdvOutputLoad",
    "1.3.6.1.4.1.318.1.1.1.4.2.4.0": "upsAdvOutputCurrent",
    "1.3.6.1.4.1.318.1.1.1.11.1.1.0": "upsBasicStateOutputState",
    "1.3.6.1.4.1.318.1.1.1.12.1.1.0": "upsAdvTestDiagnosticsResults",
    "1.3.6.1.4.1.318.1.1.1.12.2.1.0": "upsAdvTestLastDiagnosticsDate",
    
    # Eaton UPS Enterprise OIDs
    "1.3.6.1.4.1.534.1.1.2.0": "xupsIdentManufacturer",
    "1.3.6.1.4.1.534.1.1.3.0": "xupsIdentModel",
    "1.3.6.1.4.1.534.1.1.4.0": "xupsIdentSoftwareVersion",
    "1.3.6.1.4.1.534.1.1.5.0": "xupsIdentOemCode",
    "1.3.6.1.4.1.534.1.2.1.0": "xupsBatTimeRemaining",
    "1.3.6.1.4.1.534.1.2.2.0": "xupsBatVoltage",
    "1.3.6.1.4.1.534.1.2.3.0": "xupsBatCurrent",
    "1.3.6.1.4.1.534.1.2.4.0": "xupsBatCapacity",
    "1.3.6.1.4.1.534.1.2.5.0": "xupsBatteryAbmStatus",
    "1.3.6.1.4.1.534.1.2.6.0": "xupsBatteryLastReplacedDate",
    "1.3.6.1.4.1.534.1.3.1.0": "xupsInputFrequency",
    "1.3.6.1.4.1.534.1.3.2.0": "xupsInputLineBads",
    "1.3.6.1.4.1.534.1.3.3.0": "xupsInputNumPhases",
    "1.3.6.1.4.1.534.1.3.4.1.2.1": "xupsInputVoltage",
    "1.3.6.1.4.1.534.1.4.1.0": "xupsOutputLoad",
    "1.3.6.1.4.1.534.1.4.2.0": "xupsOutputFrequency",
    "1.3.6.1.4.1.534.1.4.3.0": "xupsOutputNumPhases",
    "1.3.6.1.4.1.534.1.4.4.1.2.1": "xupsOutputVoltage",
    "1.3.6.1.4.1.534.1.4.4.1.3.1": "xupsOutputCurrent",
    "1.3.6.1.4.1.534.1.4.4.1.4.1": "xupsOutputWatts",
    "1.3.6.1.4.1.534.1.6.1.0": "xupsEnvAmbientTemp",
    "1.3.6.1.4.1.534.1.6.2.0": "xupsEnvAmbientLowerLimit",
    "1.3.6.1.4.1.534.1.6.3.0": "xupsEnvAmbientUpperLimit",
    "1.3.6.1.4.1.534.1.6.4.0": "xupsEnvAmbientHumidity",
    
    # CyberPower UPS Enterprise OIDs
    "1.3.6.1.4.1.3808.1.1.1.1.1.1.0": "upsIdentModel",
    "1.3.6.1.4.1.3808.1.1.1.1.1.2.0": "upsIdentName",
    "1.3.6.1.4.1.3808.1.1.1.1.2.1.0": "upsIdentSoftwareVersion",
    "1.3.6.1.4.1.3808.1.1.1.1.2.2.0": "upsIdentSerialNumber",
    "1.3.6.1.4.1.3808.1.1.1.1.2.3.0": "upsIdentManufactureDate",
    "1.3.6.1.4.1.3808.1.1.1.2.1.1.0": "upsBatteryStatus",
    "1.3.6.1.4.1.3808.1.1.1.2.2.1.0": "upsBatteryCapacity",
    "1.3.6.1.4.1.3808.1.1.1.2.2.2.0": "upsBatteryVoltage",
    "1.3.6.1.4.1.3808.1.1.1.2.2.3.0": "upsBatteryTemperature",
    "1.3.6.1.4.1.3808.1.1.1.2.2.4.0": "upsBatteryRunTimeRemaining",
    "1.3.6.1.4.1.3808.1.1.1.2.2.5.0": "upsBatteryReplaceDate",
    "1.3.6.1.4.1.3808.1.1.1.3.1.1.0": "upsInputNumLines",
    "1.3.6.1.4.1.3808.1.1.1.3.2.1.0": "upsInputVoltage",
    "1.3.6.1.4.1.3808.1.1.1.3.2.2.0": "upsInputFrequency",
    "1.3.6.1.4.1.3808.1.1.1.4.1.1.0": "upsOutputStatus",
    "1.3.6.1.4.1.3808.1.1.1.4.2.1.0": "upsOutputVoltage",
    "1.3.6.1.4.1.3808.1.1.1.4.2.2.0": "upsOutputFrequency",
    "1.3.6.1.4.1.3808.1.1.1.4.2.3.0": "upsOutputLoad",
    "1.3.6.1.4.1.3808.1.1.1.4.2.4.0": "upsOutputCurrent",
    "1.3.6.1.4.1.3808.1.1.1.4.2.5.0": "upsOutputPower",
    
    # Riello UPS OIDs
    "1.3.6.1.4.1.5491.10.1.1.1.0": "upsIdentityManufacturer",
    "1.3.6.1.4.1.5491.10.1.1.2.0": "upsIdentityModel",
    "1.3.6.1.4.1.5491.10.1.1.3.0": "upsIdentityUPSSoftwareVersion",
    "1.3.6.1.4.1.5491.10.1.1.4.0": "upsIdentityAgentSoftwareVersion",
    "1.3.6.1.4.1.5491.10.1.1.5.0": "upsIdentityName",
    
    # Vertiv/Liebert UPS OIDs
    "1.3.6.1.4.1.476.1.42.3.4.1.2.1.0": "lgpSysManufacturer",
    "1.3.6.1.4.1.476.1.42.3.4.1.2.2.0": "lgpSysModel",
    "1.3.6.1.4.1.476.1.42.3.4.1.2.3.0": "lgpSysSerialNumber",
    "1.3.6.1.4.1.476.1.42.3.4.1.2.4.0": "lgpSysFirmwareVersion",
    
    # Tripp Lite UPS OIDs
    "1.3.6.1.4.1.850.1.1.1.1.0": "tlUpsIdentManufacturer",
    "1.3.6.1.4.1.850.1.1.1.2.0": "tlUpsIdentModel",
    "1.3.6.1.4.1.850.1.1.1.3.0": "tlUpsIdentSoftwareVersion",
    "1.3.6.1.4.1.850.1.1.2.1.0": "tlUpsBatteryStatus",
    "1.3.6.1.4.1.850.1.1.2.2.0": "tlUpsBatteryVoltage",
    "1.3.6.1.4.1.850.1.1.2.3.0": "tlUpsBatteryCapacity",
})
        
    def load_mib_file(self, filepath):
        """Load a custom MIB file"""
        try:
            self.logger.info(f"Loading MIB from: {filepath}")
            
            # Simple parser for MIB text files
            with open(filepath, 'r') as f:
                content = f.read()
                
            # Extract OBJECT-TYPE definitions
            pattern = r'(\w+)\s+OBJECT-TYPE[\s\S]*?::=\s*\{\s*([\w\s]+)\s+(\d+)\s*\}'
            matches = re.findall(pattern, content)
            
            for name, parent, index in matches:
                # Build full OID
                if parent in self.custom_mibs:
                    parent_oid = self.custom_mibs[parent]
                    full_oid = f"{parent_oid}.{index}"
                    self.custom_mibs[name] = full_oid
                    self.mib_definitions[full_oid] = name
                    
            self.logger.info(f"Loaded {len(matches)} definitions from MIB")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading MIB: {e}")
            return False
            
    def get_name(self, oid):
        """Get descriptive name for OID"""
        return self.mib_definitions.get(oid, "")
        
    def search_name(self, pattern):
        """Search for names matching pattern"""
        results = {}
        pattern_lower = pattern.lower()
        for oid, name in self.mib_definitions.items():
            if pattern_lower in name.lower():
                results[oid] = name
        return results

class TrapReceiver(threading.Thread):
    """Thread-safe SNMP Trap receiver"""
    
    def __init__(self, port=162, callback=None, logger=None):
        super().__init__(daemon=True)
        self.port = port
        self.callback = callback
        self.logger = logger
        self.running = False
        self.socket = None
        self.traps_received = 0
        self.trap_queue = queue.Queue()
        
    def run(self):
        """Main trap receiver loop"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to trap port
            self.socket.bind(('', self.port))
            self.socket.settimeout(1.0)  # Timeout to allow clean stop
            
            self.running = True
            self.logger.info(f"Trap receiver started on port {self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(65535)
                    
                    # Process trap
                    trap_info = self.parse_trap(data, addr)
                    self.traps_received += 1
                    
                    # Add to queue
                    self.trap_queue.put(trap_info)
                    
                    # Callback if defined
                    if self.callback:
                        self.callback(trap_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error receiving trap: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error starting trap receiver: {e}")
        finally:
            if self.socket:
                self.socket.close()
            self.logger.info("Trap receiver stopped")
            
    def parse_trap(self, data, addr):
        """Improved parser for SNMP traps using decode_snmp_hex"""
        trap_info = {
            'timestamp': datetime.now().isoformat(),
            'source': f"{addr[0]}:{addr[1]}",
            'raw_data': data.hex(),
            'size': len(data),
            'type': 'Unknown',
            'decoded': None  # New field for decoded info
        }
        
        try:
            # Use decoding function from library
            from snmpy import decode_snmp_hex
            
            # Decode the trap
            decoded = decode_snmp_hex(data.hex(), return_dict=True)
            
            if decoded and not decoded.get('error'):
                trap_info['decoded'] = decoded
                trap_info['type'] = f"SNMPv{decoded['version']} - {decoded.get('pdu_type', 'Unknown')}"
                
                # If it's a trap, add type info
                if 'trap_type' in decoded:
                    trap_info['trap_type'] = decoded['trap_type']
                    trap_info['type'] = f"SNMPv{decoded['version']} - {decoded['trap_type']}"
                
                # Extract community
                if decoded.get('community'):
                    trap_info['community'] = decoded['community']
                    
        except Exception as e:
            self.logger.debug(f"Error in advanced trap parsing: {e}")
            
        return trap_info
        
    def stop(self):
        """Stop the receiver"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
                
    def get_traps(self, max_count=100):
        """Get traps from queue"""
        traps = []
        while not self.trap_queue.empty() and len(traps) < max_count:
            try:
                traps.append(self.trap_queue.get_nowait())
            except queue.Empty:
                break
        return traps

class PerformanceMonitor:
    """Performance monitor with metrics"""
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.metrics = {
            'response_times': deque(maxlen=window_size),
            'success_rate': deque(maxlen=window_size),
            'queries_per_second': deque(maxlen=window_size),
            'memory_usage': deque(maxlen=window_size),
            'cpu_usage': deque(maxlen=window_size),
            'timestamps': deque(maxlen=window_size)
        }
        self.current_stats = {
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'total_response_time': 0,
            'min_response_time': float('inf'),
            'max_response_time': 0,
            'avg_response_time': 0,
            'last_update': time.time()
        }
        
    def record_query(self, response_time, success):
        """Record a query"""
        now = time.time()
        
        # Update counters
        self.current_stats['total_queries'] += 1
        if success:
            self.current_stats['successful_queries'] += 1
        else:
            self.current_stats['failed_queries'] += 1
            
        # Update response times
        if response_time:
            self.current_stats['total_response_time'] += response_time
            self.current_stats['min_response_time'] = min(
                self.current_stats['min_response_time'], response_time)
            self.current_stats['max_response_time'] = max(
                self.current_stats['max_response_time'], response_time)
            self.current_stats['avg_response_time'] = (
                self.current_stats['total_response_time'] / 
                self.current_stats['successful_queries']
            )
            
        # Add to metrics
        self.metrics['response_times'].append(response_time if response_time else 0)
        self.metrics['success_rate'].append(100 if success else 0)
        self.metrics['timestamps'].append(now)
        
        # Calculate QPS
        if len(self.metrics['timestamps']) > 1:
            time_window = self.metrics['timestamps'][-1] - self.metrics['timestamps'][0]
            if time_window > 0:
                qps = len(self.metrics['timestamps']) / time_window
                self.metrics['queries_per_second'].append(qps)
                
    def update_system_metrics(self):
        """Update system metrics"""
        try:
            process = psutil.Process()
            self.metrics['memory_usage'].append(process.memory_info().rss / 1024 / 1024)
            self.metrics['cpu_usage'].append(process.cpu_percent())
        except:
            pass
            
    def get_summary(self):
        """Get performance summary"""
        if self.current_stats['successful_queries'] == 0:
            success_rate = 0
        else:
            success_rate = (self.current_stats['successful_queries'] / 
                          self.current_stats['total_queries'] * 100)
                          
        return {
            'total_queries': self.current_stats['total_queries'],
            'success_rate': f"{success_rate:.1f}%",
            'avg_response_time': f"{self.current_stats['avg_response_time']:.3f}s",
            'min_response_time': f"{self.current_stats['min_response_time']:.3f}s",
            'max_response_time': f"{self.current_stats['max_response_time']:.3f}s",
            'current_qps': f"{self.metrics['queries_per_second'][-1]:.1f}" if self.metrics['queries_per_second'] else "0",
            'memory_mb': f"{self.metrics['memory_usage'][-1]:.1f}" if self.metrics['memory_usage'] else "0",
            'cpu_percent': f"{self.metrics['cpu_usage'][-1]:.1f}" if self.metrics['cpu_usage'] else "0"
        }

class BatchOperations:
    """Manage batch operations on multiple hosts"""
    
    def __init__(self, logger, max_workers=5):
        self.logger = logger
        self.max_workers = max_workers
        self.results = {}
        self.progress_callback = None
        
    def scan_multiple_hosts(self, hosts, oid, snmp_config, progress_callback=None):
        """Scan OID on multiple hosts"""
        self.results = {}
        self.progress_callback = progress_callback
        total = len(hosts)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for host in hosts:
                future = executor.submit(self._scan_single_host, host, oid, snmp_config)
                futures[future] = host
                
            for future in as_completed(futures):
                host = futures[future]
                try:
                    result = future.result(timeout=30)
                    self.results[host] = result
                except Exception as e:
                    self.results[host] = {'error': str(e)}
                    self.logger.error(f"Scan error {host}: {e}")
                    
                completed += 1
                if self.progress_callback:
                    self.progress_callback(completed, total)
                    
        return self.results
        
    def _scan_single_host(self, host, oid, config):
        """Scan single host"""
        try:
            # Create SNMP client
            if config['version'] == '3':
                # SNMPv3
                user = SnmpV3User(
                    username=config['username'],
                    auth_protocol=config.get('auth_protocol', SnmpV3AuthProtocol.NO_AUTH),
                    auth_password=config.get('auth_password', ''),
                    priv_protocol=config.get('priv_protocol', SnmpV3PrivProtocol.NO_PRIV),
                    priv_password=config.get('priv_password', '')
                )
                client = SnmpClient(
                    host=host,
                    port=config.get('port', 161),
                    version=SnmpVersion.V3,
                    v3_user=user,
                    timeout=config.get('timeout', 5.0),
                    retries=config.get('retries', 3)
                )
            else:
                # SNMPv1/v2c
                version = SnmpVersion.V1 if config['version'] == '1' else SnmpVersion.V2C
                client = SnmpClient(
                    host=host,
                    port=config.get('port', 161),
                    community=config.get('community', 'public'),
                    version=version,
                    timeout=config.get('timeout', 5.0),
                    retries=config.get('retries', 3)
                )
                
            # Execute query
            start_time = time.time()
            
            if isinstance(oid, list):
                # Multi OID
                results = {}
                for single_oid in oid:
                    result = client.get(single_oid)
                    if result:
                        results[single_oid] = self._format_value(result)
                return {
                    'success': True,
                    'results': results,
                    'response_time': time.time() - start_time
                }
            else:
                # Single OID or walk
                if oid.endswith('*'):
                    # Walk
                    base_oid = oid[:-1]
                    results = client.walk(base_oid)
                    formatted = {}
                    for walk_oid, value in results.items():
                        formatted[walk_oid] = self._format_value(value)
                    return {
                        'success': True,
                        'results': formatted,
                        'response_time': time.time() - start_time
                    }
                else:
                    # Single get
                    result = client.get(oid)
                    if result:
                        return {
                            'success': True,
                            'value': self._format_value(result),
                            'response_time': time.time() - start_time
                        }
                    else:
                        return {
                            'success': False,
                            'error': 'No response'
                        }
                        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def _format_value(self, value):
        """Format SNMP value"""
        if isinstance(value, SnmpOctetString):
            try:
                return value.value.decode('utf-8', errors='replace')
            except:
                return value.value.hex()
        elif hasattr(value, 'value'):
            return str(value.value)
        else:
            return str(value)
            
    def export_results(self, filepath, format='csv'):
        """Export batch results"""
        if format == 'csv':
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Host', 'OID', 'Value', 'Response Time', 'Status'])
                
                for host, data in self.results.items():
                    if data.get('success'):
                        if 'results' in data:
                            for oid, value in data['results'].items():
                                writer.writerow([
                                    host, oid, value,
                                    f"{data.get('response_time', 0):.3f}",
                                    'OK'
                                ])
                        else:
                            writer.writerow([
                                host, 'N/A', data.get('value', ''),
                                f"{data.get('response_time', 0):.3f}",
                                'OK'
                            ])
                    else:
                        writer.writerow([
                            host, 'N/A', '', '',
                            f"Error: {data.get('error', 'Unknown')}"
                        ])
                        
        elif format == 'json':
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)

class ProfileManager:
    """Configuration profile management"""
    
    def __init__(self, profiles_file="snmp_profiles.json", credential_manager=None):
        self.profiles_file = profiles_file
        self.credential_manager = credential_manager
        self.profiles = self.load_profiles()
        
    def load_profiles(self):
        """Load saved profiles"""
        try:
            if os.path.exists(self.profiles_file):
                with open(self.profiles_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
        
    def save_profiles(self):
        """Save profiles to file"""
        try:
            with open(self.profiles_file, 'w') as f:
                json.dump(self.profiles, f, indent=2)
            return True
        except Exception:
            return False
            
    def add_profile(self, name, config):
        """Add new profile"""
        # Encrypt passwords if present
        if self.credential_manager:
            if 'community' in config:
                config['community_encrypted'] = self.credential_manager.encrypt_password(
                    config.pop('community', ''))
            if 'v3_auth_password' in config:
                config['v3_auth_password_encrypted'] = self.credential_manager.encrypt_password(
                    config.pop('v3_auth_password', ''))
            if 'v3_priv_password' in config:
                config['v3_priv_password_encrypted'] = self.credential_manager.encrypt_password(
                    config.pop('v3_priv_password', ''))
                    
        self.profiles[name] = config
        self.save_profiles()
        
    def get_profile(self, name):
        """Get decrypted profile"""
        if name not in self.profiles:
            return None
            
        config = self.profiles[name].copy()
        
        # Decrypt passwords
        if self.credential_manager:
            if 'community_encrypted' in config:
                config['community'] = self.credential_manager.decrypt_password(
                    config.pop('community_encrypted', ''))
            if 'v3_auth_password_encrypted' in config:
                config['v3_auth_password'] = self.credential_manager.decrypt_password(
                    config.pop('v3_auth_password_encrypted', ''))
            if 'v3_priv_password_encrypted' in config:
                config['v3_priv_password'] = self.credential_manager.decrypt_password(
                    config.pop('v3_priv_password_encrypted', ''))
                    
        return config
        
    def delete_profile(self, name):
        """Delete profile"""
        if name in self.profiles:
            del self.profiles[name]
            self.save_profiles()
            return True
        return False
        
    def list_profiles(self):
        """List profile names"""
        return list(self.profiles.keys())

class SecureCredentialManager:
    """Manages secure credential storage"""

    def __init__(self, app_name="SNMPBrowser"):
        self.app_name = app_name
        self.key_file = f".{app_name}_key"
        self.cipher = self._get_or_create_cipher()

    def _get_or_create_cipher(self):
        """Get or create encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Protect file on Unix systems
            if hasattr(os, 'chmod'):
                os.chmod(self.key_file, 0o600)

        return Fernet(key)

    def encrypt_password(self, password: str) -> str:
        """Encrypt a password"""
        if not password:
            return ""
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted: str) -> str:
        """Decrypt a password"""
        if not encrypted:
            return ""
        try:
            return self.cipher.decrypt(encrypted.encode()).decode()
        except:
            return ""

    def secure_delete(self, data: str):
        """Secure memory deletion"""
        if data:
            # Overwrite string in memory
            data_len = len(data)
            random_data = secrets.token_bytes(data_len)
            # Force garbage collection
            del data
            gc.collect()


class MemoryLimitedScanner:
    """Memory-limited scanner"""

    def __init__(self, max_results=10000, max_memory_mb=500):
        self.max_results = max_results
        self.max_memory_mb = max_memory_mb
        self.results_count = 0
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024

    def check_limits(self) -> Tuple[bool, str]:
        """Check memory and results limits"""
        # Check results count
        if self.results_count >= self.max_results:
            return False, f"Results limit reached ({self.max_results})"

        # Check memory
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_used = current_memory - self.start_memory

        if memory_used > self.max_memory_mb:
            return False, f"Memory limit reached ({self.max_memory_mb}MB)"

        return True, ""

    def increment(self):
        """Increment results counter"""
        self.results_count += 1


class LanguageManager:
    """Manages multi-language support for the application"""

    def __init__(self, logger, languages_file="languages.json", default_language="en"):
        self.logger = logger
        self.languages_file = languages_file
        self.default_language = default_language
        self.current_language = default_language
        self.languages = {}
        self.translations = {}
        self.load_languages()

    def load_languages(self):
        """Load language definitions from JSON file"""
        try:
            if os.path.exists(self.languages_file):
                with open(self.languages_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.languages = data.get('languages', {})
                    if self.current_language in self.languages:
                        self.translations = self.languages[self.current_language].get('translations', {})
                    self.logger.info(f"Loaded {len(self.languages)} languages from {self.languages_file}")
            else:
                self.logger.warning(f"Languages file not found: {self.languages_file}. Using default English.")
                self.create_default_english()
        except Exception as e:
            self.logger.error(f"Error loading languages: {e}")
            self.create_default_english()

    def create_default_english(self):
        """Create minimal default English translations"""
        self.languages = {
            "en": {
                "name": "English",
                "translations": {
                    "app_title": "SNMP Browser",
                    "file": "File",
                    "tools": "Tools",
                    "help": "Help"
                }
            }
        }
        self.translations = self.languages["en"]["translations"]

    def set_language(self, language_code):
        """Change the current language"""
        if language_code in self.languages:
            self.current_language = language_code
            self.translations = self.languages[language_code].get('translations', {})
            self.logger.info(f"Language changed to: {self.languages[language_code]['name']}")
            return True
        else:
            self.logger.warning(f"Language not found: {language_code}")
            return False

    def get(self, key, default=None, **kwargs):
        """Get translated string for a key with optional formatting

        Args:
            key: Translation key
            default: Default value if key not found
            **kwargs: Format arguments for string formatting

        Returns:
            Translated and formatted string
        """
        text = self.translations.get(key, default or key)

        # Apply formatting if kwargs provided
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, ValueError) as e:
                self.logger.warning(f"Error formatting translation '{key}': {e}")

        return text

    def get_available_languages(self):
        """Get list of available languages with their names"""
        return [(code, lang.get('name', code)) for code, lang in self.languages.items()]

    def get_current_language(self):
        """Get current language code"""
        return self.current_language

    def get_current_language_name(self):
        """Get current language display name"""
        if self.current_language in self.languages:
            return self.languages[self.current_language].get('name', self.current_language)
        return self.current_language


class SnmpBrowserGUI:
    """SNMP Browser Production Ready Enhanced GUI"""

    def __init__(self, root):
        self.root = root
        self.root.title("SNMP Browser")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 750)

        # Setup logging
        self.setup_logging()
        self.logger.info("=" * 60)
        self.logger.info("Starting SNMP Browser")
        self.logger.info(f"System: {sys.platform}, Python: {sys.version}")

        # Initialize language manager first (needed for UI creation)
        self.language_manager = LanguageManager(self.logger)
        self._ = self.language_manager.get  # Shorthand for translations

        # Component managers
        self.credential_manager = SecureCredentialManager()
        self.profile_manager = ProfileManager(credential_manager=self.credential_manager)
        self.mib_parser = MibParser(self.logger)
        self.performance_monitor = PerformanceMonitor()
        self.batch_operations = BatchOperations(self.logger)
        self.trap_receiver = None
        
        # Base configuration variables
        self.host_var = tk.StringVar(value="192.168.1.1")
        self.community_var = tk.StringVar(value="public")
        self.port_var = tk.StringVar(value="161")
        self.version_var = tk.StringVar(value="2c")
        self.timeout_var = tk.StringVar(value="5.0")
        self.retries_var = tk.StringVar(value="3")
        self.current_profile_var = tk.StringVar(value="Default")

        # SNMPv3 variables
        self.v3_user_var = tk.StringVar(value="")
        self.v3_auth_protocol_var = tk.StringVar(value="noAuth")
        self.v3_auth_password_var = tk.StringVar(value="")
        self.v3_priv_protocol_var = tk.StringVar(value="noPriv")
        self.v3_priv_password_var = tk.StringVar(value="")
        self.v3_show_passwords = tk.BooleanVar(value=False)
        self.v3_engine_id_var = tk.StringVar(value="")

        # State variables
        self.scanning = False
        self.scan_thread = None
        self.client = None
        self.scan_results = {}
        self.saved_values = {}
        self.mib_tree_data = {}
        self.extended_scan_var = tk.BooleanVar()
        self.show_errors_var = tk.BooleanVar()
        self.filter_var = tk.StringVar()
        self.auto_refresh_var = tk.BooleanVar()
        self.auto_refresh_timer = None
        self.trap_receiver_enabled = tk.BooleanVar()
        self.received_traps = []

        # Memory limits
        self.max_results_var = tk.StringVar(value="10000")
        self.max_memory_var = tk.StringVar(value="500")
        self.memory_scanner = None

        # Configuration files
        self.config_file = "snmp_browser_config.json"
        self.saved_values_file = "snmp_browser_saved.json"

        # OID dictionary
        self.oid_names = self._build_oid_names_dictionary()

        # Create interface
        self.create_widgets()
        self.create_menu()

        # Load configuration
        self.load_config()
        self.load_saved_values()

        # Bind events
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.version_var.trace('w', self.on_version_change)

        # Memory and performance monitor
        self.start_memory_monitor()
        self.update_performance_metrics()

        self.logger.info("Initialization complete")

    def setup_logging(self):
        """Configure file logging with rotation"""
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Log filename with date
        log_file = os.path.join(log_dir, f"snmp_browser_{datetime.now().strftime('%Y%m%d')}.log")

        # Configure logger
        self.logger = logging.getLogger('SNMPBrowser')
        self.logger.setLevel(logging.DEBUG)

        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def send_trap(self):
        """Send an SNMP trap"""
        try:
            from snmpy import SnmpTrapSender, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol
            from snmpy import SnmpOctetString, SnmpInteger, SnmpObjectIdentifier
            
            # Get parameters
            host = self.trap_dest_host_var.get()
            port = int(self.trap_dest_port_var.get())
            version_str = self.trap_version_var.get()
            community = self.trap_community_var.get()
            
            # Determine version
            if version_str == "1":
                version = SnmpVersion.V1
            elif version_str == "3":
                version = SnmpVersion.V3
                messagebox.showwarning("SNMPv3", "SNMPv3 trap not yet implemented in GUI")
                return
            else:
                version = SnmpVersion.V2C
            
            # Create sender
            sender = SnmpTrapSender(
                trap_host=host,
                trap_port=port,
                community=community,
                version=version
            )
            
            # Send based on type
            trap_type = self.trap_type_var.get()
            success = False
            
            if trap_type == "test":
                message = self.trap_message_var.get()
                success = sender.send_test_trap(message)
                
            elif trap_type == "coldstart":
                success = sender.send_cold_start()
                
            elif trap_type == "warmstart":
                success = sender.send_warm_start()
                
            elif trap_type == "linkdown":
                if_index = int(self.trap_if_index_var.get())
                if_name = self.trap_if_name_var.get()
                success = sender.send_link_down(if_index, if_name)
                
            elif trap_type == "linkup":
                if_index = int(self.trap_if_index_var.get())
                if_name = self.trap_if_name_var.get()
                success = sender.send_link_up(if_index, if_name)
                
            elif trap_type == "authfail":
                success = sender.send_authentication_failure()
                
            elif trap_type == "ups_battery":
                success = sender.send_ups_trap(
                    'on_battery',
                    battery_charge=int(self.trap_battery_var.get()),
                    runtime=int(self.trap_runtime_var.get()),
                    load_percent=int(self.trap_load_var.get()),
                    temperature=int(self.trap_temp_var.get()),
                    message="UPS switched to battery power"
                )
                
            elif trap_type == "ups_low":
                success = sender.send_ups_trap(
                    'battery_low',
                    battery_charge=int(self.trap_battery_var.get()),
                    runtime=int(self.trap_runtime_var.get()),
                    message="UPS battery is critically low"
                )
                
            elif trap_type == "custom":
                # Parse custom varbinds
                varbinds = []
                for line in self.trap_varbinds_text.get(1.0, tk.END).strip().split('\n'):
                    if '=' in line:
                        oid, value = line.split('=', 1)
                        oid = oid.strip()
                        value = value.strip()
                        
                        # Determine value type
                        if value.isdigit():
                            varbinds.append((oid, SnmpInteger(int(value))))
                        else:
                            varbinds.append((oid, SnmpOctetString(value)))
                
                custom_oid = self.trap_custom_oid_var.get()
                success = sender.send_v2c_trap(custom_oid, varbinds=varbinds)
            
            # Show result
            if success:
                self.trap_send_status.config(text=f"Trap sent to {host}:{port}", foreground="green")
                self.logger.info(f"Trap {trap_type} sent successfully to {host}:{port}")
                
                # If receiver is active on same port, we should see it
                if self.trap_receiver and self.trap_receiver.running and host == "localhost":
                    self.status_var.set(f"Trap {trap_type} sent (check receiver)")
            else:
                self.trap_send_status.config(text="Trap sending error", foreground="red")
                self.logger.error(f"Trap sending error {trap_type}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Trap sending error:\n{str(e)}")
            self.logger.error(f"Trap sending error: {e}")

    def send_trap_loop(self):
        """Send 5 test traps with delay"""
        def send_loop():
            for i in range(5):
                self.trap_message_var.set(f"Test trap #{i+1} - {time.strftime('%H:%M:%S')}")
                self.send_trap()
                if i < 4:
                    time.sleep(2)
        
        # Run in separate thread
        threading.Thread(target=send_loop, daemon=True).start()

    def show_trap_templates(self):
        """Show predefined trap templates"""
        template_window = tk.Toplevel(self.root)
        template_window.title("Trap Templates")
        template_window.geometry("600x400")
        template_window.transient(self.root)
        
        # Template list
        templates = [
            {
                'name': 'UPS Power Failure',
                'type': 'ups_battery',
                'params': {'battery': 90, 'runtime': 60, 'load': 75}
            },
            {
                'name': 'UPS Battery Critical',
                'type': 'ups_low',
                'params': {'battery': 10, 'runtime': 5, 'load': 80}
            },
            {
                'name': 'Network Interface Down',
                'type': 'linkdown',
                'params': {'index': 2, 'name': 'eth1'}
            },
            {
                'name': 'System Reboot',
                'type': 'coldstart',
                'params': {}
            },
            {
                'name': 'Test Notification',
                'type': 'test',
                'params': {'message': 'Operating System - Periodic Test'}
            }
        ]
        
        # List
        list_frame = ttk.Frame(template_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        listbox = tk.Listbox(list_frame)
        listbox.pack(fill=tk.BOTH, expand=True)
        
        for template in templates:
            listbox.insert(tk.END, template['name'])
        
        def apply_template():
            selection = listbox.curselection()
            if selection:
                template = templates[selection[0]]
                
                # Apply template
                self.trap_type_var.set(template['type'])
                
                if template['type'] == 'test':
                    self.trap_message_var.set(template['params'].get('message', ''))
                elif template['type'] in ['linkdown', 'linkup']:
                    self.trap_if_index_var.set(str(template['params'].get('index', 1)))
                    self.trap_if_name_var.set(template['params'].get('name', 'eth0'))
                elif template['type'] in ['ups_battery', 'ups_low']:
                    self.trap_battery_var.set(str(template['params'].get('battery', 50)))
                    self.trap_runtime_var.set(str(template['params'].get('runtime', 30)))
                    self.trap_load_var.set(str(template['params'].get('load', 50)))
                
                template_window.destroy()
        
        # Buttons
        btn_frame = ttk.Frame(template_window)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Apply", command=apply_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=template_window.destroy).pack(side=tk.LEFT, padx=5)

    def start_memory_monitor(self):
        """Monitor memory usage"""

        def monitor():
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024

            # Alert if exceeds threshold
            if memory_mb > 800:
                self.logger.warning(f"High memory usage: {memory_mb:.1f}MB")
                self.root.after(0, lambda: self.status_var.set(
                    f"High memory usage: {memory_mb:.1f}MB"))

            # Recheck every 30 seconds
            self.root.after(30000, monitor)

        # Start monitor
        self.root.after(5000, monitor)

    def update_performance_metrics(self):
        """Update performance metrics periodically"""
        self.performance_monitor.update_system_metrics()
        
        # Update display if performance tab is visible
        if hasattr(self, 'performance_tab_active') and self.performance_tab_active:
            self.update_performance_display()
            
        # Call again every 2 seconds
        self.root.after(2000, self.update_performance_metrics)

    def _build_oid_names_dictionary(self):
        """Build extended OID dictionary with SNMPv3 and UPS"""
        base_dict = {
            "1": "iso",
            "1.3": "org",
            "1.3.6": "dod",
            "1.3.6.1": "internet",
            "1.3.6.1.1": "directory",
            "1.3.6.1.2": "mgmt",
            "1.3.6.1.2.1": "mib-2",
            
            # System
            "1.3.6.1.2.1.1": "system",
            "1.3.6.1.2.1.1.1": "sysDescr",
            "1.3.6.1.2.1.1.1.0": "sysDescr.0",
            "1.3.6.1.2.1.1.2": "sysObjectID", 
            "1.3.6.1.2.1.1.2.0": "sysObjectID.0",
            "1.3.6.1.2.1.1.3": "sysUpTime",
            "1.3.6.1.2.1.1.3.0": "sysUpTime.0",
            "1.3.6.1.2.1.1.4": "sysContact",
            "1.3.6.1.2.1.1.4.0": "sysContact.0",
            "1.3.6.1.2.1.1.5": "sysName",
            "1.3.6.1.2.1.1.5.0": "sysName.0",
            "1.3.6.1.2.1.1.6": "sysLocation",
            "1.3.6.1.2.1.1.6.0": "sysLocation.0",
            "1.3.6.1.2.1.1.7": "sysServices",
            "1.3.6.1.2.1.1.7.0": "sysServices.0",
            
            # Interfaces
            "1.3.6.1.2.1.2": "interfaces",
            "1.3.6.1.2.1.2.1": "ifNumber",
            "1.3.6.1.2.1.2.1.0": "ifNumber.0",
            "1.3.6.1.2.1.2.2": "ifTable",
            "1.3.6.1.2.1.2.2.1": "ifEntry",
            "1.3.6.1.2.1.2.2.1.1": "ifIndex",
            "1.3.6.1.2.1.2.2.1.2": "ifDescr",
            "1.3.6.1.2.1.2.2.1.3": "ifType",
            "1.3.6.1.2.1.2.2.1.4": "ifMtu",
            "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
            "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
            "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
            "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
            
            # IP
            "1.3.6.1.2.1.4": "ip",
            "1.3.6.1.2.1.4.1": "ipForwarding",
            "1.3.6.1.2.1.4.20": "ipAddrTable",
            "1.3.6.1.2.1.4.21": "ipRouteTable",
            
            # Host Resources
            "1.3.6.1.2.1.25": "host",
            "1.3.6.1.2.1.25.1": "hrSystem",
            "1.3.6.1.2.1.25.2": "hrStorage",
            "1.3.6.1.2.1.25.3": "hrDevice",
            
            # UPS MIB (RFC 1628)
            "1.3.6.1.2.1.33": "upsMIB",
            "1.3.6.1.2.1.33.1": "upsObjects",
            "1.3.6.1.2.1.33.1.1": "upsIdent",
            "1.3.6.1.2.1.33.1.2": "upsBattery",
            "1.3.6.1.2.1.33.1.3": "upsInput",
            "1.3.6.1.2.1.33.1.4": "upsOutput",
            "1.3.6.1.2.1.33.1.5": "upsBypass",
            "1.3.6.1.2.1.33.1.6": "upsAlarm",
            "1.3.6.1.2.1.33.1.7": "upsTest",
            "1.3.6.1.2.1.33.1.8": "upsControl",
            "1.3.6.1.2.1.33.1.9": "upsConfig",
            
            # SNMPv3
            "1.3.6.1.6": "snmpV2",
            "1.3.6.1.6.3": "snmpModules",
            "1.3.6.1.6.3.1": "snmpFrameworkMIB",
            "1.3.6.1.6.3.15": "usmMIB",
            "1.3.6.1.6.3.16": "vacmMIB",
            
            # Enterprises
            "1.3.6.1.4": "private",
            "1.3.6.1.4.1": "enterprises",
            "1.3.6.1.4.1.318": "apc",
            "1.3.6.1.4.1.534": "eaton",
            "1.3.6.1.4.1.3808": "cyberPower",
        }
        
        # Add MIB parser definitions
        base_dict.update(self.mib_parser.mib_definitions)
        
        return base_dict

    def create_menu(self):
        """Create main menu with new options"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label=self._("file"), menu=file_menu)
        file_menu.add_command(label=self._("save_configuration"), command=self.save_config, accelerator="Ctrl+S")
        file_menu.add_command(label=self._("load_configuration"), command=self.load_config_dialog, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label=self._("profile_manager"), command=self.show_profile_manager)
        file_menu.add_separator()
        file_menu.add_command(label=self._("export_results"), command=self.export_results, accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label=self._("view_logs"), command=self.show_log_viewer)
        file_menu.add_separator()
        file_menu.add_command(label=self._("exit"), command=self.on_closing, accelerator="Ctrl+Q")

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label=self._("tools"), menu=tools_menu)
        tools_menu.add_command(label=self._("test_connection"), command=self.test_connection, accelerator="Ctrl+T")
        tools_menu.add_command(label=self._("full_snmp_walk"), command=self.full_walk)
        tools_menu.add_command(label=self._("batch_operations"), command=self.show_batch_operations)
        tools_menu.add_separator()
        tools_menu.add_command(label=self._("trap_receiver"), command=self.toggle_trap_receiver)
        tools_menu.add_command(label=self._("performance_monitor"), command=self.show_performance_window)
        tools_menu.add_separator()
        tools_menu.add_command(label=self._("load_mib"), command=self.load_mib_file)
        tools_menu.add_command(label=self._("search_mib"), command=self.search_mib_definitions)
        tools_menu.add_separator()
        tools_menu.add_command(label=self._("snmp_hex_decoder"), command=self.show_hex_decoder)
        tools_menu.add_separator()
        tools_menu.add_command(label=self._("snmpv3_wizard"), command=self.show_snmpv3_wizard)
        tools_menu.add_command(label=self._("discover_engine_id"), command=self.discover_engine_id)
        tools_menu.add_separator()
        tools_menu.add_command(label=self._("clear_cache"), command=self.clear_cache)
        tools_menu.add_command(label=self._("settings"), command=self.show_settings)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label=self._("help"), menu=help_menu)
        help_menu.add_command(label=self._("language"), command=self.change_language)
        help_menu.add_separator()
        help_menu.add_command(label=self._("help"), command=self.show_help, accelerator="F1")
        help_menu.add_command(label=self._("shortcuts"), command=self.show_shortcuts)
        help_menu.add_command(label=self._("debug_info"), command=self.show_debug_info)
        help_menu.add_separator()
        help_menu.add_command(label=self._("about"), command=self.show_about)


    def show_hex_decoder(self):
        """Show dialog for manual hex decoding"""
        decoder_window = tk.Toplevel(self.root)
        decoder_window.title("SNMP Hex Decoder")
        decoder_window.geometry("900x700")
        decoder_window.transient(self.root)
        
        # Input
        input_frame = ttk.LabelFrame(decoder_window, text="Hex Input (paste here)")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        input_text = tk.Text(input_frame, height=8, font=('Courier', 10))
        input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Example
        input_text.insert(tk.END, "# Paste SNMP packet hex here\n")
        input_text.insert(tk.END, "# Example: 3081a202010104067075626c6963a78194...")
        
        # Output
        output_frame = ttk.LabelFrame(decoder_window, text="Decoding Result")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        output_text = tk.Text(output_frame, height=15, font=('Courier', 10))
        output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def decode():
            from snmpy import decode_snmp_hex
            import io
            import sys
            
            # Get hex
            hex_data = input_text.get(1.0, tk.END).strip()
            # Remove comments
            hex_data = '\n'.join(line for line in hex_data.split('\n') 
                                if not line.strip().startswith('#'))
            
            if not hex_data:
                messagebox.showwarning("Warning", "Please enter hex data!")
                return
            
            # Capture output
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            
            try:
                decode_snmp_hex(hex_data)
                output = buffer.getvalue()
            except Exception as e:
                output = f"Decoding error:\n{str(e)}"
            finally:
                sys.stdout = old_stdout
            
            # Show result
            output_text.config(state=tk.NORMAL)
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, output)
            output_text.config(state=tk.DISABLED)
        
        # Buttons
        btn_frame = ttk.Frame(decoder_window)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Decode", command=decode,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", 
                command=lambda: input_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", 
                command=decoder_window.destroy).pack(side=tk.LEFT, padx=5)

    def create_widgets(self):
        """Create all widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configuration frame
        self.create_config_frame(main_frame)

        # Notebook for views
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        # Tabs
        self.create_browser_tab()
        self.create_dashboard_tab()
        self.create_mib_tree_tab()
        self.create_trap_tab()
        self.create_performance_tab()

        # Status frame
        self.create_status_frame(main_frame)

    def create_config_frame(self, parent):
        """Configuration frame with profiles"""
        config_frame = ttk.LabelFrame(parent, text=self._("snmp_configuration"))
        config_frame.pack(fill=tk.X, pady=(0, 5))

        # First row - Profiles
        profile_row = ttk.Frame(config_frame)
        profile_row.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(profile_row, text=self._("profile") + ":").pack(side=tk.LEFT)
        self.profile_combo = ttk.Combobox(profile_row, textvariable=self.current_profile_var,
                                          width=15, state='readonly')
        self.profile_combo.pack(side=tk.LEFT, padx=(5, 10))
        self.profile_combo.bind('<<ComboboxSelected>>', self.on_profile_selected)

        ttk.Button(profile_row, text=self._("save"), command=self.save_current_profile).pack(side=tk.LEFT, padx=2)
        ttk.Button(profile_row, text=self._("manage"), command=self.show_profile_manager).pack(side=tk.LEFT, padx=2)

        self.update_profile_list()

        # Second row
        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(row1, text=self._("host") + ":").pack(side=tk.LEFT)
        self.host_entry = ttk.Entry(row1, textvariable=self.host_var, width=15)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(row1, text=self._("port") + ":").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(row1, textvariable=self.port_var, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(row1, text=self._("version") + ":").pack(side=tk.LEFT)
        version_combo = ttk.Combobox(row1, textvariable=self.version_var, width=5,
                                     values=["1", "2c", "3"], state='readonly')
        version_combo.pack(side=tk.LEFT, padx=(5, 10))

        # Community for v1/v2c
        self.v1v2_frame = ttk.Frame(row1)
        self.v1v2_frame.pack(side=tk.LEFT, padx=(10, 0))

        ttk.Label(self.v1v2_frame, text=self._("community") + ":").pack(side=tk.LEFT)
        ttk.Entry(self.v1v2_frame, textvariable=self.community_var, width=10).pack(side=tk.LEFT, padx=(5, 10))

        # Third row
        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(row2, text=self._("timeout") + ":").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.timeout_var, width=6).pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(row2, text=self._("retries") + ":").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.retries_var, width=6).pack(side=tk.LEFT, padx=(5, 10))

        ttk.Checkbutton(row2, text=self._("extended_scan"),
                        variable=self.extended_scan_var).pack(side=tk.LEFT, padx=(20, 10))

        # Buttons
        btn_frame = ttk.Frame(row2)
        btn_frame.pack(side=tk.RIGHT, padx=5)

        self.scan_btn = ttk.Button(btn_frame, text=self._("start_scan"), command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=2)

        self.stop_btn = ttk.Button(btn_frame, text=self._("stop"), command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(btn_frame, text=self._("test"), command=self.test_connection).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text=self._("batch"), command=self.show_batch_operations).pack(side=tk.LEFT, padx=2)

        # SNMPv3 Frame
        self.v3_frame = ttk.LabelFrame(config_frame, text=self._("snmpv3_configuration"))

        # First v3 row
        v3_row1 = ttk.Frame(self.v3_frame)
        v3_row1.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(v3_row1, text=self._("username") + ":").pack(side=tk.LEFT)
        ttk.Entry(v3_row1, textvariable=self.v3_user_var, width=15).pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(v3_row1, text=self._("auth") + ":").pack(side=tk.LEFT)
        auth_combo = ttk.Combobox(v3_row1, textvariable=self.v3_auth_protocol_var, width=10,
                                  values=["noAuth", "MD5", "SHA", "SHA256", "SHA384", "SHA512"])
        auth_combo.pack(side=tk.LEFT, padx=(5, 10))
        auth_combo.state(['readonly'])

        ttk.Label(v3_row1, text=self._("auth_pass") + ":").pack(side=tk.LEFT)
        self.auth_pass_entry = ttk.Entry(v3_row1, textvariable=self.v3_auth_password_var,
                                         width=15, show="*")
        self.auth_pass_entry.pack(side=tk.LEFT, padx=(5, 10))

        # Second v3 row
        v3_row2 = ttk.Frame(self.v3_frame)
        v3_row2.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(v3_row2, text=self._("priv") + ":").pack(side=tk.LEFT)
        priv_combo = ttk.Combobox(v3_row2, textvariable=self.v3_priv_protocol_var, width=10,
                                  values=["noPriv", "DES", "AES128", "AES192", "AES256"])
        priv_combo.pack(side=tk.LEFT, padx=(5, 10))
        priv_combo.state(['readonly'])

        ttk.Label(v3_row2, text=self._("priv_pass") + ":").pack(side=tk.LEFT)
        self.priv_pass_entry = ttk.Entry(v3_row2, textvariable=self.v3_priv_password_var,
                                         width=15, show="*")
        self.priv_pass_entry.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Checkbutton(v3_row2, text=self._("show"),
                        variable=self.v3_show_passwords,
                        command=self.toggle_password_visibility).pack(side=tk.LEFT, padx=(10, 5))

        ttk.Button(v3_row2, text=self._("engine_id"),
                   command=self.discover_engine_id).pack(side=tk.LEFT, padx=5)

        ttk.Button(v3_row2, text=self._("test_v3"),
                   command=self.test_snmpv3_connection).pack(side=tk.LEFT, padx=5)

    def create_trap_tab(self):
        """Tab for trap receiver AND SENDER"""
        trap_frame = ttk.Frame(self.notebook)
        self.notebook.add(trap_frame, text=self._("trap_manager"))
        
        # Internal notebook for Receiver and Sender
        trap_notebook = ttk.Notebook(trap_frame)
        trap_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # === RECEIVER TAB ===
        receiver_frame = ttk.Frame(trap_notebook)
        trap_notebook.add(receiver_frame, text="Trap Receiver")
        
        # Receiver controls (existing code)
        control_frame = ttk.LabelFrame(receiver_frame, text="Trap Receiver Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        controls = ttk.Frame(control_frame)
        controls.pack(padx=10, pady=10)
        
        self.trap_status_label = ttk.Label(controls, text="Status: Inactive")
        self.trap_status_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.trap_toggle_btn = ttk.Button(controls, text="Start Receiver",
                                        command=self.toggle_trap_receiver)
        self.trap_toggle_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls, text="Clear", command=self.clear_traps).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Export", command=self.export_traps).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls, text="Port:").pack(side=tk.LEFT, padx=(20, 5))
        self.trap_port_var = tk.StringVar(value="162")
        ttk.Entry(controls, textvariable=self.trap_port_var, width=6).pack(side=tk.LEFT)
        
        # TreeView for received traps
        tree_frame = ttk.Frame(receiver_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Timestamp", "Source", "Type", "Size", "Data")
        self.trap_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.trap_tree.heading(col, text=col)
            self.trap_tree.column(col, width=150)
            
        trap_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.trap_tree.yview)
        self.trap_tree.configure(yscrollcommand=trap_scroll.set)
        
        self.trap_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        trap_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.trap_tree.bind("<Double-1>", self.on_trap_double_click)
        
        # Info frame
        info_frame = ttk.LabelFrame(receiver_frame, text="Statistics")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.trap_stats_label = ttk.Label(info_frame, text="Traps received: 0")
        self.trap_stats_label.pack(padx=10, pady=5)
        
        # === SENDER TAB ===
        sender_frame = ttk.Frame(trap_notebook)
        trap_notebook.add(sender_frame, text="Trap Sender")
        
        # Destination configuration
        dest_frame = ttk.LabelFrame(sender_frame, text="Trap Destination")
        dest_frame.pack(fill=tk.X, padx=5, pady=5)
        
        dest_controls = ttk.Frame(dest_frame)
        dest_controls.pack(padx=10, pady=10)
        
        ttk.Label(dest_controls, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.trap_dest_host_var = tk.StringVar(value="localhost")
        ttk.Entry(dest_controls, textvariable=self.trap_dest_host_var, width=20).grid(row=0, column=1, padx=5)
        
        ttk.Label(dest_controls, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.trap_dest_port_var = tk.StringVar(value="162")
        ttk.Entry(dest_controls, textvariable=self.trap_dest_port_var, width=8).grid(row=0, column=3, padx=5)
        
        ttk.Label(dest_controls, text="Version:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.trap_version_var = tk.StringVar(value="2c")
        ttk.Combobox(dest_controls, textvariable=self.trap_version_var, 
                    values=["1", "2c", "3"], state='readonly', width=5).grid(row=1, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(dest_controls, text="Community:").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.trap_community_var = tk.StringVar(value="public")
        ttk.Entry(dest_controls, textvariable=self.trap_community_var, width=15).grid(row=1, column=3, padx=5)
        
        # Trap type
        trap_type_frame = ttk.LabelFrame(sender_frame, text="Trap Type")
        trap_type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        trap_type_controls = ttk.Frame(trap_type_frame)
        trap_type_controls.pack(padx=10, pady=10)
        
        # Radio buttons for trap type
        self.trap_type_var = tk.StringVar(value="test")
        
        trap_types = [
            ("Test Trap", "test"),
            ("Cold Start", "coldstart"),
            ("Warm Start", "warmstart"),
            ("Link Down", "linkdown"),
            ("Link Up", "linkup"),
            ("Authentication Failure", "authfail"),
            ("UPS on Battery", "ups_battery"),
            ("UPS Battery Low", "ups_low"),
            ("Custom", "custom")
        ]
        
        for i, (text, value) in enumerate(trap_types):
            ttk.Radiobutton(trap_type_controls, text=text, variable=self.trap_type_var, 
                        value=value).grid(row=i//3, column=i%3, sticky=tk.W, padx=10, pady=2)
        
        # Frame for specific parameters
        params_frame = ttk.LabelFrame(sender_frame, text="Trap Parameters")
        params_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Notebook for different parameter types
        self.params_notebook = ttk.Notebook(params_frame)
        self.params_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Test parameters tab
        test_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(test_params, text="Test/Generic")
        
        ttk.Label(test_params, text="Message:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_message_var = tk.StringVar(value="Test trap from SNMP Browser")
        ttk.Entry(test_params, textvariable=self.trap_message_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        
        # Interface parameters tab
        if_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(if_params, text="Interface")
        
        ttk.Label(if_params, text="Interface Index:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_if_index_var = tk.StringVar(value="1")
        ttk.Entry(if_params, textvariable=self.trap_if_index_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(if_params, text="Interface Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_if_name_var = tk.StringVar(value="eth0")
        ttk.Entry(if_params, textvariable=self.trap_if_name_var, width=30).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # UPS parameters tab
        ups_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(ups_params, text="UPS")
        
        ttk.Label(ups_params, text="Battery Charge (%):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_battery_var = tk.StringVar(value="75")
        ttk.Entry(ups_params, textvariable=self.trap_battery_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(ups_params, text="Runtime (min):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_runtime_var = tk.StringVar(value="45")
        ttk.Entry(ups_params, textvariable=self.trap_runtime_var, width=10).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(ups_params, text="Load (%):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_load_var = tk.StringVar(value="80")
        ttk.Entry(ups_params, textvariable=self.trap_load_var, width=10).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(ups_params, text="Temperature (°C):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_temp_var = tk.StringVar(value="25")
        ttk.Entry(ups_params, textvariable=self.trap_temp_var, width=10).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Custom OID tab
        custom_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(custom_params, text="Custom")
        
        ttk.Label(custom_params, text="Trap OID:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_custom_oid_var = tk.StringVar(value="1.3.6.1.4.1.99999.1.1")
        ttk.Entry(custom_params, textvariable=self.trap_custom_oid_var, width=40).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(custom_params, text="Varbinds (OID=Value):").grid(row=1, column=0, sticky=tk.NW, padx=5, pady=5)
        self.trap_varbinds_text = tk.Text(custom_params, height=6, width=50)
        self.trap_varbinds_text.grid(row=1, column=1, padx=5, pady=5)
        self.trap_varbinds_text.insert(tk.END, "1.3.6.1.4.1.99999.1.2=Test Value\n1.3.6.1.4.1.99999.1.3=123")
        
        # Send buttons
        send_frame = ttk.Frame(sender_frame)
        send_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(send_frame, text="Send Trap", command=self.send_trap,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(send_frame, text="Test Loop (5x)", command=self.send_trap_loop).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(send_frame, text="Templates", command=self.show_trap_templates).pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.trap_send_status = ttk.Label(send_frame, text="")
        self.trap_send_status.pack(side=tk.LEFT, padx=20)

    def create_performance_tab(self):
        """Tab for performance metrics"""
        perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(perf_frame, text=self._("performance"))

        # Controls
        control_frame = ttk.LabelFrame(perf_frame, text=self._("performance_controls"))
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        controls = ttk.Frame(control_frame)
        controls.pack(padx=10, pady=10)
        
        ttk.Button(controls, text="Refresh", command=self.update_performance_display).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Reset", command=self.reset_performance_metrics).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Export", command=self.export_performance_data).pack(side=tk.LEFT, padx=5)
        
        # Metrics frame
        metrics_frame = ttk.LabelFrame(perf_frame, text="Current Metrics")
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.metrics_text = tk.Text(metrics_frame, height=8, width=80)
        self.metrics_text.pack(padx=10, pady=10)
        
        # Graph frame (if matplotlib available)
        if HAS_MATPLOTLIB:
            graph_frame = ttk.LabelFrame(perf_frame, text="Performance Graphs")
            graph_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Create matplotlib figure
            self.perf_figure = Figure(figsize=(12, 6), dpi=80)
            self.perf_canvas = FigureCanvasTkAgg(self.perf_figure, master=graph_frame)
            self.perf_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Bind tab change
            self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    def toggle_trap_receiver(self):
        """Enable/disable trap receiver"""
        if self.trap_receiver and self.trap_receiver.running:
            # Stop receiver
            self.trap_receiver.stop()
            self.trap_receiver = None
            self.trap_status_label.config(text="Status: Inactive")
            self.trap_toggle_btn.config(text="Start Receiver")
            self.logger.info("Trap receiver stopped")
        else:
            # Start receiver
            try:
                port = int(self.trap_port_var.get())
                
                # Check port permissions
                if port < 1024 and not self.check_admin_privileges():
                    messagebox.showwarning("Permissions",
                                         "Port < 1024 requires administrator privileges.\n"
                                         "Use a port >= 1024 or run as admin.")
                    return
                    
                self.trap_receiver = TrapReceiver(
                    port=port,
                    callback=self.on_trap_received,
                    logger=self.logger
                )
                self.trap_receiver.start()
                
                self.trap_status_label.config(text=f"Status: Active (port {port})")
                self.trap_toggle_btn.config(text="Stop Receiver")
                self.logger.info(f"Trap receiver started on port {port}")
                
                # Start periodic update
                self.update_trap_display()
                
            except Exception as e:
                messagebox.showerror("Error", f"Unable to start trap receiver:\n{str(e)}")
                self.logger.error(f"Error starting trap receiver: {e}")

    def check_admin_privileges(self):
        """Check administrator privileges"""
        try:
            if sys.platform.startswith('win'):
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def on_trap_received(self, trap_info):
        """Callback when trap is received"""
        self.received_traps.append(trap_info)
        # Update counter
        self.root.after(0, lambda: self.trap_stats_label.config(
            text=f"Traps received: {len(self.received_traps)}"))

    def update_trap_display(self):
        """Update trap display"""
        if self.trap_receiver and self.trap_receiver.running:
            # Get new traps
            new_traps = self.trap_receiver.get_traps()
            
            for trap in new_traps:
                # Add to tree
                self.trap_tree.insert("", 0, values=(
                    trap['timestamp'],
                    trap['source'],
                    trap['type'],
                    f"{trap['size']} bytes",
                    trap['raw_data'][:50] + "..." if len(trap['raw_data']) > 50 else trap['raw_data']
                ))
                
            # Limit number of displayed traps
            children = self.trap_tree.get_children()
            if len(children) > 1000:
                for item in children[1000:]:
                    self.trap_tree.delete(item)
                    
            # Call again after 1 second
            self.root.after(1000, self.update_trap_display)

    def on_trap_double_click(self, event):
        """Double click on trap for IMPROVED details"""
        selection = self.trap_tree.selection()
        if selection:
            item = selection[0]
            values = self.trap_tree.item(item)['values']
            
            # Find trap in received data
            trap_data = None
            for trap in self.received_traps:
                if trap['timestamp'] == values[0] and trap['source'] == values[1]:
                    trap_data = trap
                    break
            
            if not trap_data:
                # Fallback to tree values
                trap_data = {
                    'timestamp': values[0],
                    'source': values[1],
                    'type': values[2],
                    'size': values[3],
                    'raw_data': values[4] if len(values) > 4 else ""
                }
            
            # Show trap details
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Trap Details - Decoded")
            detail_window.geometry("800x600")
            detail_window.transient(self.root)
            
            # Notebook for different views
            notebook = ttk.Notebook(detail_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Basic Info Tab
            info_frame = ttk.Frame(notebook)
            notebook.add(info_frame, text="Basic Info")
            
            info_text = ttk.Frame(info_frame)
            info_text.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(info_text, text=f"Timestamp: {trap_data.get('timestamp', 'N/A')}").pack(anchor=tk.W, pady=2)
            ttk.Label(info_text, text=f"Source: {trap_data.get('source', 'N/A')}").pack(anchor=tk.W, pady=2)
            ttk.Label(info_text, text=f"Type: {trap_data.get('type', 'N/A')}").pack(anchor=tk.W, pady=2)
            ttk.Label(info_text, text=f"Size: {trap_data.get('size', 0)} bytes").pack(anchor=tk.W, pady=2)
            
            if 'community' in trap_data:
                ttk.Label(info_text, text=f"Community: {trap_data['community']}").pack(anchor=tk.W, pady=2)
            if 'trap_type' in trap_data:
                ttk.Label(info_text, text=f"Trap Type: {trap_data['trap_type']}",
                        font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, pady=5)
            
            # Decoded Varbinds Tab
            if trap_data.get('decoded') and trap_data['decoded'].get('varbinds'):
                varbind_frame = ttk.Frame(notebook)
                notebook.add(varbind_frame, text="Varbinds")
                
                # TreeView for varbinds
                columns = ("OID", "Name", "Type", "Value")
                vb_tree = ttk.Treeview(varbind_frame, columns=columns, show="headings", height=10)
                
                for col in columns:
                    vb_tree.heading(col, text=col)
                    vb_tree.column(col, width=150)
                
                # Populate varbinds
                for vb in trap_data['decoded']['varbinds']:
                    vb_tree.insert("", tk.END, values=(
                        vb['oid'],
                        vb.get('name', ''),
                        vb['type'],
                        vb['value']
                    ))
                
                vb_scroll = ttk.Scrollbar(varbind_frame, orient=tk.VERTICAL, command=vb_tree.yview)
                vb_tree.configure(yscrollcommand=vb_scroll.set)
                
                vb_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
                vb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Raw Hex Tab
            hex_frame = ttk.Frame(notebook)
            notebook.add(hex_frame, text="Raw Hex")
            
            hex_text = tk.Text(hex_frame, wrap=tk.WORD, font=('Courier', 10))
            hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Format hex in rows
            raw_hex = trap_data.get('raw_data', '')
            formatted_hex = ""
            for i in range(0, len(raw_hex), 32):
                line = raw_hex[i:i+32]
                # Add spaces every 2 characters
                spaced = ' '.join(line[j:j+2] for j in range(0, len(line), 2))
                formatted_hex += f"{i//2:04x}: {spaced}\n"
            
            hex_text.insert(tk.END, formatted_hex)
            hex_text.config(state=tk.DISABLED)
            
            # Full Decode Tab
            decode_frame = ttk.Frame(notebook)
            notebook.add(decode_frame, text="Decoding")
            
            decode_text = tk.Text(decode_frame, wrap=tk.WORD, font=('Courier', 10))
            decode_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # On-demand decoding
            def decode_full():
                from snmpy import decode_snmp_hex
                import io
                import sys
                
                # Capture output
                old_stdout = sys.stdout
                sys.stdout = buffer = io.StringIO()
                
                decode_snmp_hex(raw_hex)
                
                output = buffer.getvalue()
                sys.stdout = old_stdout
                
                decode_text.config(state=tk.NORMAL)
                decode_text.delete(1.0, tk.END)
                decode_text.insert(tk.END, output)
                decode_text.config(state=tk.DISABLED)
            
            ttk.Button(decode_frame, text="Detailed Decode", 
                    command=decode_full).pack(pady=5)
            
            # Buttons
            btn_frame = ttk.Frame(detail_window)
            btn_frame.pack(pady=10)
            
            def copy_hex():
                self.root.clipboard_clear()
                self.root.clipboard_append(raw_hex)
                messagebox.showinfo("Copied", "Hex copied to clipboard!")
            
            def save_trap():
                filename = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON", "*.json"), ("Text", "*.txt")],
                    initialfile=f"trap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )
                if filename:
                    with open(filename, 'w') as f:
                        json.dump(trap_data, f, indent=2, default=str)
                    messagebox.showinfo("Saved", f"Trap saved to {filename}")
            
            ttk.Button(btn_frame, text="Copy Hex", command=copy_hex).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Save", command=save_trap).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Close", command=detail_window.destroy).pack(side=tk.LEFT, padx=5)

    def clear_traps(self):
        """Clear received traps"""
        if messagebox.askyesno("Confirm", "Clear all received traps?"):
            self.received_traps.clear()
            for item in self.trap_tree.get_children():
                self.trap_tree.delete(item)
            self.trap_stats_label.config(text="Traps received: 0")

    def export_traps(self):
        """Export received traps"""
        if not self.received_traps:
            messagebox.showwarning("Warning", "No traps to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv")],
            initialfile=f"traps_{time.strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.received_traps, f, indent=2)
                else:
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Timestamp', 'Source', 'Type', 'Size', 'Data'])
                        for trap in self.received_traps:
                            writer.writerow([
                                trap['timestamp'],
                                trap['source'],
                                trap['type'],
                                trap['size'],
                                trap['raw_data']
                            ])
                            
                messagebox.showinfo("Export", f"Traps exported: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export error: {str(e)}")

    def on_tab_changed(self, event):
        """Handle tab change"""
        selected = self.notebook.select()
        tab_text = self.notebook.tab(selected, "text")
        
        # Enable/disable performance update
        self.performance_tab_active = (tab_text == "Performance")
        
        if self.performance_tab_active:
            self.update_performance_display()

    def update_performance_display(self):
        """Update performance display"""
        try:
            # Get metrics
            summary = self.performance_monitor.get_summary()
            
            # Update text
            self.metrics_text.delete(1.0, tk.END)
            
            text = f"""
Total Queries: {summary['total_queries']}
Success Rate: {summary['success_rate']}
Queries/Second: {summary['current_qps']}

Average Response Time: {summary['avg_response_time']}
Min Response Time: {summary['min_response_time']}
Max Response Time: {summary['max_response_time']}

Memory Used: {summary['memory_mb']} MB
CPU Usage: {summary['cpu_percent']}%
"""
            self.metrics_text.insert(tk.END, text)
            
            # Update graphs if available
            if HAS_MATPLOTLIB and hasattr(self, 'perf_figure'):
                self.update_performance_graphs()
                
        except Exception as e:
            self.logger.error(f"Error updating performance: {e}")

    def update_performance_graphs(self):
        """Update performance graphs"""
        try:
            self.perf_figure.clear()
            
            # Create subplots
            ax1 = self.perf_figure.add_subplot(2, 2, 1)
            ax2 = self.perf_figure.add_subplot(2, 2, 2)
            ax3 = self.perf_figure.add_subplot(2, 2, 3)
            ax4 = self.perf_figure.add_subplot(2, 2, 4)
            
            # Response time graph
            if self.performance_monitor.metrics['response_times']:
                ax1.plot(list(self.performance_monitor.metrics['response_times']))
                ax1.set_title('Response Time (s)')
                ax1.set_xlabel('Query')
                ax1.grid(True)
                
            # Success rate graph
            if self.performance_monitor.metrics['success_rate']:
                ax2.plot(list(self.performance_monitor.metrics['success_rate']))
                ax2.set_title('Success Rate (%)')
                ax2.set_xlabel('Query')
                ax2.set_ylim([0, 105])
                ax2.grid(True)
                
            # Memory graph
            if self.performance_monitor.metrics['memory_usage']:
                ax3.plot(list(self.performance_monitor.metrics['memory_usage']))
                ax3.set_title('Memory (MB)')
                ax3.set_xlabel('Time')
                ax3.grid(True)
                
            # QPS graph
            if self.performance_monitor.metrics['queries_per_second']:
                ax4.plot(list(self.performance_monitor.metrics['queries_per_second']))
                ax4.set_title('Queries/Second')
                ax4.set_xlabel('Time')
                ax4.grid(True)
                
            self.perf_figure.tight_layout()
            self.perf_canvas.draw()
            
        except Exception as e:
            self.logger.error(f"Error updating graphs: {e}")

    def reset_performance_metrics(self):
        """Reset performance metrics"""
        if messagebox.askyesno("Confirm", "Reset all metrics?"):
            self.performance_monitor = PerformanceMonitor()
            self.update_performance_display()

    def export_performance_data(self):
        """Export performance data"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv")],
            initialfile=f"performance_{time.strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                data = {
                    'summary': self.performance_monitor.get_summary(),
                    'current_stats': self.performance_monitor.current_stats,
                    'metrics': {
                        'response_times': list(self.performance_monitor.metrics['response_times']),
                        'success_rate': list(self.performance_monitor.metrics['success_rate']),
                        'queries_per_second': list(self.performance_monitor.metrics['queries_per_second']),
                        'memory_usage': list(self.performance_monitor.metrics['memory_usage']),
                        'cpu_usage': list(self.performance_monitor.metrics['cpu_usage'])
                    }
                }
                
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2, default=str)
                else:
                    # CSV export
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Metric', 'Value'])
                        for key, value in data['summary'].items():
                            writer.writerow([key, value])
                            
                messagebox.showinfo("Export", f"Performance data exported: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export error: {str(e)}")

    def show_batch_operations(self):
        """Show batch operations dialog"""
        batch_window = tk.Toplevel(self.root)
        batch_window.title("Batch Operations")
        batch_window.geometry("700x500")
        batch_window.transient(self.root)
        
        # Hosts frame
        hosts_frame = ttk.LabelFrame(batch_window, text="Host List (one per line)")
        hosts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        hosts_text = tk.Text(hosts_frame, height=10)
        hosts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Example
        hosts_text.insert(tk.END, "192.168.1.1\n192.168.1.2\n192.168.1.3")
        
        # OID frame
        oid_frame = ttk.LabelFrame(batch_window, text="OID to Query")
        oid_frame.pack(fill=tk.X, padx=10, pady=5)
        
        oid_var = tk.StringVar(value="1.3.6.1.2.1.1.1.0")
        ttk.Entry(oid_frame, textvariable=oid_var, width=50).pack(padx=5, pady=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(batch_window, text="Options")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        opts = ttk.Frame(options_frame)
        opts.pack(padx=5, pady=5)
        
        ttk.Label(opts, text="Max Workers:").grid(row=0, column=0, sticky=tk.W)
        workers_var = tk.StringVar(value="5")
        ttk.Spinbox(opts, from_=1, to=20, textvariable=workers_var, width=10).grid(row=0, column=1, padx=5)
        
        walk_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="WALK (use * at the end of OID)",
                       variable=walk_var).grid(row=1, column=0, columnspan=2, pady=5)
        
        # Progress
        self.batch_progress = ttk.Progressbar(batch_window, mode='determinate')
        self.batch_progress.pack(fill=tk.X, padx=10, pady=5)
        
        self.batch_status = tk.StringVar(value="Ready")
        ttk.Label(batch_window, textvariable=self.batch_status).pack()
        
        # Buttons
        btn_frame = ttk.Frame(batch_window)
        btn_frame.pack(pady=10)
        
        def run_batch():
            # Get hosts
            hosts = [h.strip() for h in hosts_text.get(1.0, tk.END).split('\n') if h.strip()]
            
            if not hosts:
                messagebox.showwarning("Warning", "Enter at least one host")
                return
                
            # Prepare OID
            oid = oid_var.get()
            if walk_var.get() and not oid.endswith('*'):
                oid += '*'
                
            # Prepare SNMP config
            snmp_config = {
                'version': self.version_var.get(),
                'community': self.community_var.get(),
                'port': int(self.port_var.get()),
                'timeout': float(self.timeout_var.get()),
                'retries': int(self.retries_var.get())
            }
            
            if self.version_var.get() == '3':
                snmp_config.update({
                    'username': self.v3_user_var.get(),
                    'auth_protocol': self.v3_auth_protocol_var.get(),
                    'auth_password': self.v3_auth_password_var.get(),
                    'priv_protocol': self.v3_priv_protocol_var.get(),
                    'priv_password': self.v3_priv_password_var.get()
                })
                
            # Progress callback
            def progress_callback(completed, total):
                self.batch_progress['value'] = (completed / total) * 100
                self.batch_status.set(f"Completed {completed}/{total} hosts")
                batch_window.update()
                
            # Execute batch
            self.batch_status.set("Running batch...")
            self.batch_operations.max_workers = int(workers_var.get())
            
            results = self.batch_operations.scan_multiple_hosts(
                hosts, oid, snmp_config, progress_callback)
                
            # Show results
            self.show_batch_results(results)
            batch_window.destroy()
            
        ttk.Button(btn_frame, text="Run", command=run_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=batch_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_batch_results(self, results):
        """Show batch results"""
        results_window = tk.Toplevel(self.root)
        results_window.title("Batch Results")
        results_window.geometry("800x600")
        results_window.transient(self.root)
        
        # TreeView
        tree_frame = ttk.Frame(results_window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Host", "Status", "Value/Error", "Response Time")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
            
        # Populate results
        for host, data in results.items():
            if data.get('success'):
                if 'results' in data:
                    # Multi results (walk)
                    for oid, value in data['results'].items():
                        tree.insert("", tk.END, values=(
                            host, "OK", f"{oid}: {value}",
                            f"{data.get('response_time', 0):.3f}s"
                        ))
                else:
                    tree.insert("", tk.END, values=(
                        host, "OK", data.get('value', ''),
                        f"{data.get('response_time', 0):.3f}s"
                    ))
            else:
                tree.insert("", tk.END, values=(
                    host, "ERROR", data.get('error', 'Unknown'), "-"
                ))
                
        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        btn_frame = ttk.Frame(results_window)
        btn_frame.pack(pady=10)
        
        def export_batch():
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json")],
                initialfile=f"batch_results_{time.strftime('%Y%m%d_%H%M%S')}"
            )
            
            if filename:
                self.batch_operations.export_results(
                    filename, 'csv' if filename.endswith('.csv') else 'json')
                messagebox.showinfo("Export", f"Results exported: {filename}")
                
        ttk.Button(btn_frame, text="Export", command=export_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="OK", command=results_window.destroy).pack(side=tk.LEFT, padx=5)

    def load_mib_file(self):
        """Load MIB file"""
        filename = filedialog.askopenfilename(
            title="Load MIB File",
            filetypes=[
                ("MIB Files", "*.mib"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            if self.mib_parser.load_mib_file(filename):
                # Update OID dictionary
                self.oid_names.update(self.mib_parser.mib_definitions)
                messagebox.showinfo("MIB Loaded",
                                   f"MIB file loaded successfully!\n"
                                   f"Total definitions: {len(self.mib_parser.mib_definitions)}")
            else:
                messagebox.showerror("Error", "Error loading MIB file")

    def search_mib_definitions(self):
        """Search MIB definitions"""
        search_term = simpledialog.askstring("Search MIB", "Enter search term:")
        if search_term:
            results = self.mib_parser.search_name(search_term)
            
            if results:
                # Show results
                result_window = tk.Toplevel(self.root)
                result_window.title(f"Search results: {search_term}")
                result_window.geometry("600x400")
                result_window.transient(self.root)
                
                # TreeView
                tree_frame = ttk.Frame(result_window)
                tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                columns = ("OID", "Name")
                tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
                
                tree.heading("OID", text="OID")
                tree.heading("Name", text="Name")
                tree.column("OID", width=300)
                tree.column("Name", width=250)
                
                for oid, name in results.items():
                    tree.insert("", tk.END, values=(oid, name))
                    
                scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
                tree.configure(yscrollcommand=scroll.set)
                
                tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scroll.pack(side=tk.RIGHT, fill=tk.Y)
                
                ttk.Button(result_window, text="OK",
                          command=result_window.destroy).pack(pady=10)
            else:
                messagebox.showinfo("Search", "No results found")

    def show_profile_manager(self):
        """Show profile manager"""
        profile_window = tk.Toplevel(self.root)
        profile_window.title("Profile Manager")
        profile_window.geometry("500x400")
        profile_window.transient(self.root)
        
        # Profile list
        list_frame = ttk.LabelFrame(profile_window, text="Saved Profiles")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        listbox = tk.Listbox(list_frame)
        listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Populate list
        for profile_name in self.profile_manager.list_profiles():
            listbox.insert(tk.END, profile_name)
            
        # Buttons
        btn_frame = ttk.Frame(profile_window)
        btn_frame.pack(pady=10)
        
        def load_profile():
            selection = listbox.curselection()
            if selection:
                profile_name = listbox.get(selection[0])
                self.load_profile(profile_name)
                profile_window.destroy()
                
        def delete_profile():
            selection = listbox.curselection()
            if selection:
                profile_name = listbox.get(selection[0])
                if messagebox.askyesno("Confirm", f"Delete profile '{profile_name}'?"):
                    self.profile_manager.delete_profile(profile_name)
                    listbox.delete(selection[0])
                    self.update_profile_list()
                    
        def rename_profile():
            selection = listbox.curselection()
            if selection:
                old_name = listbox.get(selection[0])
                new_name = simpledialog.askstring("Rename", "New name:",
                                                 initialvalue=old_name)
                if new_name and new_name != old_name:
                    config = self.profile_manager.get_profile(old_name)
                    self.profile_manager.add_profile(new_name, config)
                    self.profile_manager.delete_profile(old_name)
                    listbox.delete(selection[0])
                    listbox.insert(selection[0], new_name)
                    self.update_profile_list()
                    
        ttk.Button(btn_frame, text="Load", command=load_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=delete_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Rename", command=rename_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=profile_window.destroy).pack(side=tk.LEFT, padx=5)

    def save_current_profile(self):
        """Save current configuration as profile"""
        profile_name = simpledialog.askstring("Save Profile", "Profile name:")
        
        if profile_name:
            config = {
                'host': self.host_var.get(),
                'port': self.port_var.get(),
                'version': self.version_var.get(),
                'timeout': self.timeout_var.get(),
                'retries': self.retries_var.get(),
                'extended_scan': self.extended_scan_var.get()
            }
            
            if self.version_var.get() == '3':
                config.update({
                    'v3_user': self.v3_user_var.get(),
                    'v3_auth_protocol': self.v3_auth_protocol_var.get(),
                    'v3_auth_password': self.v3_auth_password_var.get(),
                    'v3_priv_protocol': self.v3_priv_protocol_var.get(),
                    'v3_priv_password': self.v3_priv_password_var.get()
                })
            else:
                config['community'] = self.community_var.get()
                
            self.profile_manager.add_profile(profile_name, config)
            self.update_profile_list()
            self.current_profile_var.set(profile_name)
            
            messagebox.showinfo("Profile Saved", f"Profile '{profile_name}' saved successfully")

    def load_profile(self, profile_name):
        """Load profile"""
        config = self.profile_manager.get_profile(profile_name)
        
        if config:
            self.host_var.set(config.get('host', ''))
            self.port_var.set(config.get('port', '161'))
            self.version_var.set(config.get('version', '2c'))
            self.timeout_var.set(config.get('timeout', '5.0'))
            self.retries_var.set(config.get('retries', '3'))
            self.extended_scan_var.set(config.get('extended_scan', False))
            
            if config.get('version') == '3':
                self.v3_user_var.set(config.get('v3_user', ''))
                self.v3_auth_protocol_var.set(config.get('v3_auth_protocol', 'noAuth'))
                self.v3_auth_password_var.set(config.get('v3_auth_password', ''))
                self.v3_priv_protocol_var.set(config.get('v3_priv_protocol', 'noPriv'))
                self.v3_priv_password_var.set(config.get('v3_priv_password', ''))
            else:
                self.community_var.set(config.get('community', 'public'))
                
            self.current_profile_var.set(profile_name)
            self.logger.info(f"Profile '{profile_name}' loaded")

    def on_profile_selected(self, event):
        """Handle profile selection from combo"""
        profile_name = self.current_profile_var.get()
        if profile_name and profile_name != "Default":
            self.load_profile(profile_name)

    def update_profile_list(self):
        """Update profile list in combo"""
        profiles = ["Default"] + self.profile_manager.list_profiles()
        self.profile_combo['values'] = profiles

    def show_performance_window(self):
        """Show dedicated performance window"""
        perf_window = tk.Toplevel(self.root)
        perf_window.title("Performance Monitor")
        perf_window.geometry("900x600")
        perf_window.transient(self.root)
        
        # Select performance tab
        for i in range(self.notebook.index("end")):
            if self.notebook.tab(i, "text") == "Performance":
                self.notebook.select(i)
                break
    
    def create_browser_tab(self):
        """Main Browser tab"""
        browser_frame = ttk.Frame(self.notebook)
        self.notebook.add(browser_frame, text=self._("browser"))

        # Filters
        filter_frame = ttk.LabelFrame(browser_frame, text="Filters")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.filter_var.trace('w', self.apply_filter)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(filter_frame, text="Clear", command=self.clear_filter).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(filter_frame, text="Errors Only",
                        variable=self.show_errors_var,
                        command=self.apply_filter).pack(side=tk.LEFT, padx=(20, 5))

        # Results
        results_frame = ttk.Frame(browser_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("OID", "Name", "Type", "Value", "Status", "Timestamp")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)

        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)

        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Actions
        action_frame = ttk.Frame(browser_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Dashboard", command=self.add_to_dashboard).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="GET", command=self.get_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="SET", command=self.set_value).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="WALK", command=self.walk_from_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Export", command=self.export_results).pack(side=tk.LEFT, padx=2)

        # Bind events
        self.results_tree.bind("<Double-1>", self.on_result_double_click)
        self.results_tree.bind("<Button-3>", self.show_context_menu)

    def create_dashboard_tab(self):
        """Dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text=self._("dashboard"))

        # Controls
        control_frame = ttk.LabelFrame(dashboard_frame, text="Dashboard Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(control_frame, text="Refresh", command=self.refresh_dashboard).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Remove", command=self.remove_from_dashboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear", command=self.clear_dashboard).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(control_frame, text="Auto-Refresh (30s)",
                        variable=self.auto_refresh_var,
                        command=self.toggle_auto_refresh).pack(side=tk.LEFT, padx=(20, 5))

        # TreeView
        dash_frame = ttk.Frame(dashboard_frame)
        dash_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        dash_columns = ("Host", "OID", "Name", "Value", "Timestamp", "Status")
        self.dashboard_tree = ttk.Treeview(dash_frame, columns=dash_columns, show="headings", height=15)

        for col in dash_columns:
            self.dashboard_tree.heading(col, text=col)
            self.dashboard_tree.column(col, width=120)

        dash_scroll = ttk.Scrollbar(dash_frame, orient=tk.VERTICAL, command=self.dashboard_tree.yview)
        self.dashboard_tree.configure(yscrollcommand=dash_scroll.set)

        self.dashboard_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dash_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def create_mib_tree_tab(self):
        """MIB tree tab with value column"""
        mib_frame = ttk.Frame(self.notebook)
        self.notebook.add(mib_frame, text=self._("mib_tree"))

        # Controls
        control_frame = ttk.LabelFrame(mib_frame, text="MIB Tree Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(control_frame, text="Build", command=self.build_mib_tree).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Expand", command=self.expand_all_mib).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Collapse", command=self.collapse_all_mib).pack(side=tk.LEFT, padx=5)

        # TreeView with added value column
        tree_frame = ttk.Frame(mib_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.mib_tree = ttk.Treeview(tree_frame, columns=("oid", "value", "type", "status"), height=20)
        self.mib_tree.heading("#0", text="MIB Name")
        self.mib_tree.heading("oid", text="OID")
        self.mib_tree.heading("value", text="Value")
        self.mib_tree.heading("type", text="Type")
        self.mib_tree.heading("status", text="Status")

        self.mib_tree.column("#0", width=300)
        self.mib_tree.column("oid", width=200)
        self.mib_tree.column("value", width=250)
        self.mib_tree.column("type", width=100)
        self.mib_tree.column("status", width=80)

        mib_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.mib_tree.yview)
        self.mib_tree.configure(yscrollcommand=mib_scroll.set)

        self.mib_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        mib_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.mib_tree.bind("<Double-1>", self.on_mib_double_click)

    def create_status_frame(self, parent):
        """Status frame with memory info"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(5, 0))

        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=(0, 10))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

        # Memory info
        self.memory_var = tk.StringVar(value="")
        ttk.Label(status_frame, textvariable=self.memory_var).pack(side=tk.LEFT, padx=(20, 0))

        self.info_var = tk.StringVar(value="")
        ttk.Label(status_frame, textvariable=self.info_var).pack(side=tk.RIGHT, padx=(0, 10))

        self.time_var = tk.StringVar()
        ttk.Label(status_frame, textvariable=self.time_var).pack(side=tk.RIGHT)
        self.update_time()

    def update_time(self):
        """Update time and memory"""
        self.time_var.set(time.strftime("%H:%M:%S"))

        # Update memory info
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        self.memory_var.set(f"{memory_mb:.1f}MB")

        self.root.after(1000, self.update_time)

    def on_version_change(self, *args):
        """Handle SNMP version change"""
        version = self.version_var.get()

        if version == "3":
            self.v1v2_frame.pack_forget()
            self.v3_frame.pack(fill=tk.X, padx=5, pady=5)
            self.logger.info("Switched to SNMPv3")
        else:
            if not self.v1v2_frame.winfo_viewable():
                self.v1v2_frame.pack(side=tk.LEFT, padx=(10, 0))
            self.v3_frame.pack_forget()
            self.logger.info(f"Switched to SNMPv{version}")

    def toggle_password_visibility(self):
        """Show/hide v3 passwords"""
        show = "" if self.v3_show_passwords.get() else "*"
        self.auth_pass_entry.config(show=show)
        self.priv_pass_entry.config(show=show)

    def validate_input(self) -> Tuple[bool, str]:
        """Complete input validation"""
        try:
            # Host
            host = self.host_var.get().strip()
            if not host:
                return False, "Host cannot be empty!"

            # Port
            port = int(self.port_var.get())
            if port < 1 or port > 65535:
                return False, "Port must be between 1 and 65535!"

            # Timeout
            timeout = float(self.timeout_var.get())
            if timeout < 0.1 or timeout > 60:
                return False, "Timeout must be between 0.1 and 60 seconds!"

            # Retries
            retries = int(self.retries_var.get())
            if retries < 0 or retries > 10:
                return False, "Retries must be between 0 and 10!"

            # SNMPv3
            if self.version_var.get() == "3":
                if not self.v3_user_var.get().strip():
                    return False, "SNMPv3 username required!"

                if self.v3_auth_protocol_var.get() != "noAuth":
                    if len(self.v3_auth_password_var.get()) < 8:
                        return False, "Auth password must be at least 8 characters!"

                if self.v3_priv_protocol_var.get() != "noPriv":
                    if len(self.v3_priv_password_var.get()) < 8:
                        return False, "Priv password must be at least 8 characters!"
            else:
                if not self.community_var.get().strip():
                    return False, "Community string required!"

            # Test host resolution
            try:
                ipaddress.ip_address(host)
            except:
                try:
                    resolved = socket.gethostbyname(host)
                    self.logger.info(f"Host resolved: {host} -> {resolved}")
                except:
                    return False, f"Unable to resolve host: {host}"

            # Memory limits
            max_results = int(self.max_results_var.get())
            if max_results < 100 or max_results > 100000:
                return False, "Max results must be between 100 and 100000!"

            max_memory = int(self.max_memory_var.get())
            if max_memory < 50 or max_memory > 2000:
                return False, "Max memory must be between 50 and 2000 MB!"

            return True, ""

        except ValueError as e:
            return False, f"Validation error: {str(e)}"

    def create_snmpv3_client(self):
        """Create SNMPv3 client with secure handling"""
        try:
            auth_map = {
                "noAuth": SnmpV3AuthProtocol.NO_AUTH,
                "MD5": SnmpV3AuthProtocol.MD5,
                "SHA": SnmpV3AuthProtocol.SHA,
                "SHA256": SnmpV3AuthProtocol.SHA256,
                "SHA384": SnmpV3AuthProtocol.SHA384,
                "SHA512": SnmpV3AuthProtocol.SHA512
            }

            priv_map = {
                "noPriv": SnmpV3PrivProtocol.NO_PRIV,
                "DES": SnmpV3PrivProtocol.DES,
                "AES128": SnmpV3PrivProtocol.AES128,
                "AES192": SnmpV3PrivProtocol.AES192,
                "AES256": SnmpV3PrivProtocol.AES256
            }

            user = SnmpV3User(
                username=self.v3_user_var.get(),
                auth_protocol=auth_map.get(self.v3_auth_protocol_var.get()),
                auth_password=self.v3_auth_password_var.get(),
                priv_protocol=priv_map.get(self.v3_priv_protocol_var.get()),
                priv_password=self.v3_priv_password_var.get()
            )

            client = SnmpClient(
                host=self.host_var.get(),
                port=int(self.port_var.get()),
                version=SnmpVersion.V3,
                v3_user=user,
                timeout=float(self.timeout_var.get()),
                retries=int(self.retries_var.get())
            )

            self.logger.info(f"SNMPv3 client created for {self.host_var.get()}")
            return client

        except Exception as e:
            self.logger.error(f"Error creating v3 client: {str(e)}")
            raise

    def test_connection(self):
        """Non-blocking connection test"""
        # Validate input
        valid, error = self.validate_input()
        if not valid:
            messagebox.showerror("Error", error)
            return

        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Testing connection...")
        self.progress.start()
        self.logger.info(f"Testing connection to {self.host_var.get()}")

        thread = threading.Thread(target=self._test_connection_worker, daemon=True)
        thread.start()

    def _test_connection_worker(self):
        """Connection test worker with performance tracking"""
        start_time = time.time()
        try:
            if self.version_var.get() == "3":
                client = self.create_snmpv3_client()
                version_info = f"SNMPv3 ({self.v3_user_var.get()})"
            else:
                version = SnmpVersion.V1 if self.version_var.get() == "1" else SnmpVersion.V2C
                client = SnmpClient(
                    self.host_var.get(),
                    int(self.port_var.get()),
                    self.community_var.get(),
                    version,
                    float(self.timeout_var.get()),
                    int(self.retries_var.get())
                )
                version_info = f"SNMPv{self.version_var.get()}"

            # Test sysDescr
            result = client.get("1.3.6.1.2.1.1.1.0")
            response_time = time.time() - start_time

            # Record performance
            self.performance_monitor.record_query(response_time, result is not None)

            if result:
                if isinstance(result, SnmpOctetString):
                    sys_desc = result.value.decode('utf-8', errors='replace')
                else:
                    sys_desc = str(result)

                self.logger.info("Connection test successful")
                self.root.after(0, lambda: self._show_test_success(sys_desc, version_info))
            else:
                self.logger.warning("Connection test: no response")
                self.root.after(0, lambda: self._show_test_warning())

        except Exception as e:
            self.performance_monitor.record_query(time.time() - start_time, False)
            self.logger.error(f"Connection test failed: {str(e)}")
            self.root.after(0, lambda: self._show_test_error(str(e)))
        finally:
            self.root.after(0, self._test_completed)

    def _show_test_success(self, sys_desc, version_info):
        """Show test success"""
        messagebox.showinfo("Test OK",
                            f"SNMP connection established!\n\n"
                            f"Protocol: {version_info}\n"
                            f"System: {sys_desc[:100]}...")
        self.status_var.set("Test successful")

    def _show_test_warning(self):
        """Show test warning"""
        messagebox.showwarning("Test",
                               "Connectivity OK but SNMP not responding.\n"
                               "Check community/credentials.")
        self.status_var.set("SNMP not responding")

    def _show_test_error(self, error_msg):
        """Show test error"""
        messagebox.showerror("Test Failed",
                             f"Test failed:\n\n{error_msg}")
        self.status_var.set("Test failed")

    def _test_completed(self):
        """Complete test"""
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)

    def test_snmpv3_connection(self):
        """SNMPv3 specific test"""
        self.test_connection()

    def discover_engine_id(self):
        """Discover working Engine ID"""
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Discovering Engine ID...")
        self.progress.start()
        self.logger.info("Starting Engine ID discovery")

        thread = threading.Thread(target=self._discover_engine_worker, daemon=True)
        thread.start()

    def _discover_engine_worker(self):
        """Engine ID discovery worker"""
        try:
            host = self.host_var.get()
            port = int(self.port_var.get())
            timeout = float(self.timeout_var.get())

            # Create temporary user for discovery
            temp_user = SnmpV3User(
                username="",
                auth_protocol=SnmpV3AuthProtocol.NO_AUTH,
                priv_protocol=SnmpV3PrivProtocol.NO_PRIV
            )

            processor = SnmpV3MessageProcessor(temp_user)
            success = processor.discover_engine(host, port, timeout)

            if success and processor.engine_id:
                engine_id_hex = processor.engine_id.hex()
                engine_id_formatted = ':'.join(engine_id_hex[i:i + 2] for i in range(0, len(engine_id_hex), 2))

                results = {
                    'engine_id': engine_id_formatted,
                    'engine_boots': processor.engine_boots,
                    'engine_time': processor.engine_time
                }

                self.logger.info(f"Engine ID discovered: {engine_id_formatted}")
                self.root.after(0, lambda: self._show_engine_discovery_results(results))
            else:
                self.logger.warning("Engine ID discovery failed")
                self.root.after(0, lambda: self._show_engine_discovery_error("No response"))

        except Exception as e:
            self.logger.error(f"Discovery error: {str(e)}")
            self.root.after(0, lambda: self._show_engine_discovery_error(str(e)))
        finally:
            self.root.after(0, self._discovery_completed)

    def _show_engine_discovery_results(self, results):
        """Show discovery results"""
        self.v3_engine_id_var.set(results['engine_id'])

        result_window = tk.Toplevel(self.root)
        result_window.title("Engine ID Discovery")
        result_window.geometry("500x300")
        result_window.transient(self.root)

        ttk.Label(result_window, text="Engine ID Discovered!",
                  font=('TkDefaultFont', 12, 'bold')).pack(pady=10)

        frame = ttk.Frame(result_window)
        frame.pack(padx=20, pady=10)

        ttk.Label(frame, text=f"Engine ID: {results['engine_id']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text=f"Engine Boots: {results['engine_boots']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text=f"Engine Time: {results['engine_time']} sec").pack(anchor=tk.W, pady=2)

        def copy_engine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(results['engine_id'])
            messagebox.showinfo("Copied", "Engine ID copied!")

        ttk.Button(result_window, text="Copy", command=copy_engine_id).pack(pady=10)
        ttk.Button(result_window, text="OK", command=result_window.destroy).pack()

    def _show_engine_discovery_error(self, error_msg):
        """Show discovery error"""
        messagebox.showerror("Discovery Failed", f"Unable to discover Engine ID:\n{error_msg}")
        self.status_var.set("Discovery failed")

    def _discovery_completed(self):
        """Complete discovery"""
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)

    def start_scan(self):
        """Start scan with complete validation"""
        if self.scanning:
            return

        # Validation
        valid, error = self.validate_input()
        if not valid:
            messagebox.showerror("Error", error)
            return

        # Start scan
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Scanning...")

        # Clear results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results = {}

        # Initialize scanner with limits
        self.memory_scanner = MemoryLimitedScanner(
            int(self.max_results_var.get()),
            int(self.max_memory_var.get())
        )

        self.logger.info(f"Starting scan {self.host_var.get()} with SNMPv{self.version_var.get()}")

        # Scan thread
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()

    def _scan_worker(self):
        """Scan worker with robust error handling and performance tracking"""
        start_time = time.time()
        errors = []
        successful_oids = 0

        try:
            # Create client
            if self.version_var.get() == "3":
                self.client = self.create_snmpv3_client()
            else:
                version = SnmpVersion.V1 if self.version_var.get() == "1" else SnmpVersion.V2C
                self.client = SnmpClient(
                    self.host_var.get(),
                    int(self.port_var.get()),
                    self.community_var.get(),
                    version,
                    float(self.timeout_var.get()),
                    int(self.retries_var.get())
                )

            # OIDs to scan
            oids = [
                "1.3.6.1.2.1.1",  # System
                "1.3.6.1.2.1.2",  # Interfaces
                "1.3.6.1.2.1.25",  # Host
            ]

            if self.extended_scan_var.get():
                oids.extend([
                    "1.3.6.1.2.1.4",  # IP
                    "1.3.6.1.2.1.6",  # TCP
                    "1.3.6.1.2.1.7",  # UDP
                    "1.3.6.1.2.1.33",  # UPS
                    "1.3.6.1.4.1",  # Enterprises
                ])

            total_oids = len(oids)
            processed = 0

            for base_oid in oids:
                if not self.scanning:
                    self.logger.info("Scan interrupted by user")
                    break

                # Check memory limits
                ok, msg = self.memory_scanner.check_limits()
                if not ok:
                    self.logger.warning(f"Limit reached: {msg}")
                    self.root.after(0, lambda m=msg: messagebox.showwarning("Limit", m))
                    break

                try:
                    self.root.after(0, lambda o=base_oid, p=processed, t=total_oids:
                    self.status_var.set(f"Scanning {o}... ({p}/{t})"))

                    # Timer for performance
                    oid_start = time.time()

                    # Execute walk
                    if self.version_var.get() == "2c" or self.version_var.get() == "3":
                        results = self.client.bulk_walk(base_oid, max_repetitions=20)
                    else:
                        results = self.client.walk(base_oid)

                    oid_time = time.time() - oid_start

                    # Record performance
                    self.performance_monitor.record_query(oid_time, len(results) > 0)

                    # Process results
                    for oid, value in results.items():
                        if not self.scanning:
                            break

                        # Check limits
                        ok, msg = self.memory_scanner.check_limits()
                        if not ok:
                            self.logger.warning(f"Limit during processing: {msg}")
                            break

                        self.scan_results[oid] = {
                            'value': value,
                            'type': type(value).__name__,
                            'status': 'OK',
                            'timestamp': time.time()
                        }

                        self.memory_scanner.increment()
                        self.root.after(0, self._add_result_to_tree, oid, value)

                    if results:
                        successful_oids += 1
                        self.logger.info(f"OID {base_oid}: {len(results)} results")

                except socket.timeout:
                    error = f"Timeout on {base_oid}"
                    errors.append(error)
                    self.logger.warning(error)
                    self.performance_monitor.record_query(self.timeout_var.get(), False)
                except Exception as e:
                    error = f"Error {base_oid}: {str(e)}"
                    errors.append(error)
                    self.logger.error(error)
                    self.performance_monitor.record_query(0, False)

                processed += 1

                # Check global timeout
                if time.time() - start_time > 300:  # 5 minutes
                    self.logger.warning("Global scan timeout (5 minutes)")
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Timeout", "Scan interrupted after 5 minutes"))
                    break

            # Final report
            scan_time = time.time() - start_time
            total_results = len(self.scan_results)

            self.logger.info(f"Scan completed: {total_results} results in {scan_time:.1f}s")

            if errors:
                self.logger.warning(f"Completed with {len(errors)} errors")
                error_summary = "\n".join(errors[:5])
                self.root.after(0, lambda: self.status_var.set(
                    f"Completed with {len(errors)} errors in {scan_time:.1f}s"))
            else:
                self.root.after(0, lambda: self.status_var.set(
                    f"Scan OK: {total_results} results in {scan_time:.1f}s"))

            self.root.after(0, self._scan_completed)

        except Exception as e:
            self.logger.error(f"Critical scan error: {str(e)}\n{traceback.format_exc()}")
            self.root.after(0, lambda: self._scan_error(f"Critical error: {str(e)}"))

    def _add_result_to_tree(self, oid, value):
        """Add result to tree with improved MIB name"""
        try:
            # Use MIB parser for name
            name = self.mib_parser.get_name(oid)
            if not name:
                name = self._get_oid_description(oid)
                
            value_type = type(value).__name__

            # Format value
            if isinstance(value, SnmpOctetString):
                try:
                    display_value = value.value.decode('utf-8')
                except:
                    display_value = value.value.hex()
                status = "OK"
            elif hasattr(value, 'value'):
                display_value = str(value.value)
                status = "OK"
            else:
                display_value = str(value)
                status = "OK" if value else "Error"

            timestamp = time.strftime("%H:%M:%S")

            self.results_tree.insert("", tk.END, values=(
                oid, name, value_type, display_value, status, timestamp
            ))

            total = len(self.results_tree.get_children())
            self.info_var.set(f"Results: {total}")

        except Exception as e:
            self.logger.error(f"Error adding result: {e}")

    def _get_oid_description(self, oid):
        """Get improved OID description with MIB parser support"""
        # First check MIB parser
        mib_name = self.mib_parser.get_name(oid)
        if mib_name:
            return mib_name
            
        # Then check exact dictionary
        if oid in self.oid_names:
            return self.oid_names[oid]
        
        # Then look for partial matches
        oid_parts = oid.split('.')
        for i in range(len(oid_parts), 0, -1):
            partial = '.'.join(oid_parts[:i])
            if partial in self.oid_names:
                # If found, add index if present
                if i < len(oid_parts):
                    suffix = '.'.join(oid_parts[i:])
                    return f"{self.oid_names[partial]}.{suffix}"
                return self.oid_names[partial]
        
        # If not found, try to identify main category
        if oid.startswith("1.3.6.1.2.1.1"):
            return "system"
        elif oid.startswith("1.3.6.1.2.1.2"):
            return "interfaces"
        elif oid.startswith("1.3.6.1.2.1.4"):
            return "ip"
        elif oid.startswith("1.3.6.1.2.1.6"):
            return "tcp"
        elif oid.startswith("1.3.6.1.2.1.7"):
            return "udp"
        elif oid.startswith("1.3.6.1.2.1.11"):
            return "snmp"
        elif oid.startswith("1.3.6.1.2.1.25"):
            return "host"
        elif oid.startswith("1.3.6.1.2.1.31"):
            return "ifMIB"
        elif oid.startswith("1.3.6.1.2.1.33"):
            return "upsMIB"
        elif oid.startswith("1.3.6.1.4.1"):
            return "enterprises"
        
        return ""

    def _scan_completed(self):
        """Complete scan"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()

        total = len(self.results_tree.get_children())
        self.status_var.set(f"Scan completed - {total} results")
        self.save_config()

    def _scan_error(self, error_msg):
        """Handle scan error"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set(f"Error: {error_msg}")
        messagebox.showerror("Scan Error", error_msg)

    def stop_scan(self):
        """Stop scan"""
        self.scanning = False
        self.status_var.set("Stopping...")
        self.logger.info("Scan interrupted by user")

    def walk_from_selected(self):
        """WALK from selected element with performance tracking"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select an element")
            return

        if not self.client:
            messagebox.showerror("Error", "Perform a scan first")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if not values:
            return

        oid = values[0]

        # Confirm for potentially large walks
        if not messagebox.askyesno("WALK", f"Execute WALK from:\n{oid}\n\nThis may generate many results."):
            return

        # Clear results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        self.status_var.set(f"WALK from {oid}...")
        self.progress.start()
        self.logger.info(f"WALK from OID: {oid}")

        # Thread for WALK
        def walk_worker():
            start_time = time.time()
            try:
                if self.version_var.get() == "2c" or self.version_var.get() == "3":
                    results = self.client.bulk_walk(oid, max_repetitions=20)
                else:
                    results = self.client.walk(oid)

                response_time = time.time() - start_time
                self.performance_monitor.record_query(response_time, len(results) > 0)

                count = 0
                for walk_oid, value in results.items():
                    if count >= int(self.max_results_var.get()):
                        self.root.after(0, lambda: messagebox.showwarning(
                            "Limit", f"Reached limit of {self.max_results_var.get()} results"))
                        break

                    self.root.after(0, self._add_result_to_tree, walk_oid, value)
                    count += 1

                self.logger.info(f"WALK completed: {count} results in {response_time:.2f}s")
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: self.status_var.set(f"✅ WALK completed - {count} results"))

            except Exception as e:
                self.performance_monitor.record_query(time.time() - start_time, False)
                self.logger.error(f"WALK error: {str(e)}")
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("WALK Error", str(e)))

        threading.Thread(target=walk_worker, daemon=True).start()

    def set_value(self):
        """SET SNMP value with tracking"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select an element")
            return

        if not self.client:
            messagebox.showerror("Error", "Perform a scan first")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if not values:
            return

        oid = values[0]
        current_value = values[3]
        current_type = values[2]

        # Dialog for new value
        dialog = tk.Toplevel(self.root)
        dialog.title("SET SNMP Value")
        dialog.geometry("450x350")
        dialog.transient(self.root)
        dialog.grab_set()

        # OID info
        info_frame = ttk.LabelFrame(dialog, text="OID Information")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(info_frame, text=f"OID: {oid}", font=('TkDefaultFont', 9)).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Current Type: {current_type}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Current Value: {current_value}").pack(anchor=tk.W, padx=5, pady=2)

        # New value frame
        value_frame = ttk.LabelFrame(dialog, text="New Value")
        value_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(value_frame, text="Value:").pack(anchor=tk.W, padx=5, pady=5)
        new_value_var = tk.StringVar(value=current_value)
        value_entry = ttk.Entry(value_frame, textvariable=new_value_var, width=40)
        value_entry.pack(padx=5, pady=5)

        ttk.Label(value_frame, text="Data Type:").pack(anchor=tk.W, padx=5, pady=5)
        type_var = tk.StringVar(value="String")
        type_combo = ttk.Combobox(value_frame, textvariable=type_var, state='readonly',
                                  values=["String", "Integer", "IPAddress", "OID", "Gauge", "Counter"])
        type_combo.pack(padx=5, pady=5)

        # Warning
        warning_label = ttk.Label(dialog, text="WARNING: SET modifies values on the device!",
                                  foreground="red")
        warning_label.pack(pady=10)

        def do_set():
            start_time = time.time()
            try:
                new_val = new_value_var.get()
                val_type = type_var.get()

                # Create appropriate SNMP value
                if val_type == "Integer":
                    snmp_value = SnmpInteger(int(new_val))
                elif val_type == "IPAddress":
                    import ipaddress
                    ip = ipaddress.ip_address(new_val)
                    snmp_value = SnmpIpAddress(int(ip))
                elif val_type == "OID":
                    parts = [int(x) for x in new_val.split('.') if x]
                    snmp_value = SnmpObjectIdentifier(parts)
                elif val_type == "Gauge":
                    snmp_value = SnmpGauge32(int(new_val))
                elif val_type == "Counter":
                    snmp_value = SnmpCounter32(int(new_val))
                else:
                    snmp_value = SnmpOctetString(new_val.encode())

                # Log operation
                self.logger.info(f"SET {oid} = {new_val} ({val_type})")

                # Execute SET
                if self.client.set(oid, snmp_value):
                    response_time = time.time() - start_time
                    self.performance_monitor.record_query(response_time, True)
                    
                    messagebox.showinfo("SET OK", "Value set successfully!")
                    dialog.destroy()

                    # Update value in tree
                    self.get_single_oid(oid)
                    self.logger.info(f"SET completed successfully in {response_time:.3f}s")
                else:
                    self.performance_monitor.record_query(time.time() - start_time, False)
                    messagebox.showerror("SET Failed", "Unable to set value")
                    self.logger.error("SET failed")

            except Exception as e:
                self.performance_monitor.record_query(time.time() - start_time, False)
                error_msg = f"SET error: {str(e)}"
                self.logger.error(error_msg)
                messagebox.showerror("Error", error_msg)

        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Apply", command=do_set).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def get_selected(self):
        """GET on selected element"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select element")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if values:
            self.get_single_oid(values[0])

    def get_single_oid(self, oid):
        """GET single OID with performance tracking"""
        if not self.client:
            messagebox.showerror("Error", "Perform a scan first")
            return

        start_time = time.time()
        try:
            self.logger.info(f"GET OID: {oid}")
            result = self.client.get(oid)
            response_time = time.time() - start_time
            
            self.performance_monitor.record_query(response_time, result is not None)

            if result:
                if isinstance(result, SnmpOctetString):
                    value = result.value.decode('utf-8', errors='replace')
                else:
                    value = str(result.value) if hasattr(result, 'value') else str(result)

                messagebox.showinfo("GET Result",
                                    f"OID: {oid}\n"
                                    f"Value: {value}\n"
                                    f"Type: {type(result).__name__}\n"
                                    f"Response time: {response_time:.3f}s")

                # Update in tree if present
                for item in self.results_tree.get_children():
                    item_values = self.results_tree.item(item)['values']
                    if item_values and item_values[0] == oid:
                        self.results_tree.item(item, values=(
                            oid, item_values[1], type(result).__name__,
                            value, "OK", time.strftime("%H:%M:%S")
                        ))
                        break
            else:
                self.performance_monitor.record_query(response_time, False)
                messagebox.showwarning("GET Result", f"No value for: {oid}")

        except Exception as e:
            self.performance_monitor.record_query(time.time() - start_time, False)
            self.logger.error(f"GET error: {str(e)}")
            messagebox.showerror("GET Error", str(e))

    def full_walk(self):
        """Complete walk with performance tracking"""
        if not messagebox.askyesno("Full Walk",
                                   "Full walk can take A LONG time and memory.\n\n"
                                   "Continue?"):
            return

        # Clear results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results.clear()

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Full walk in progress...")

        # Initialize scanner with limits
        self.memory_scanner = MemoryLimitedScanner(
            int(self.max_results_var.get()),
            int(self.max_memory_var.get())
        )

        self.logger.info("Starting full walk")

        def walk_worker():
            start_time = time.time()
            try:
                # Create client
                if self.version_var.get() == "3":
                    client = self.create_snmpv3_client()
                else:
                    version = SnmpVersion.V1 if self.version_var.get() == "1" else SnmpVersion.V2C
                    client = SnmpClient(
                        self.host_var.get(),
                        int(self.port_var.get()),
                        self.community_var.get(),
                        version,
                        float(self.timeout_var.get()),
                        int(self.retries_var.get())
                    )

                # Walk from root
                self.logger.info("Walk from root OID: 1")

                if self.version_var.get() == "2c" or self.version_var.get() == "3":
                    results = client.bulk_walk("1", max_repetitions=50)
                else:
                    results = client.walk("1")

                response_time = time.time() - start_time
                self.performance_monitor.record_query(response_time, len(results) > 0)

                # Add results with limit checking
                count = 0
                for oid, value in results.items():
                    if not self.scanning:
                        self.logger.info("Walk interrupted by user")
                        break

                    # Check limits
                    ok, msg = self.memory_scanner.check_limits()
                    if not ok:
                        self.logger.warning(f"Walk interrupted due to limit: {msg}")
                        self.root.after(0, lambda m=msg: messagebox.showwarning("Limit", m))
                        break

                    self.scan_results[oid] = {
                        'value': value,
                        'type': type(value).__name__,
                        'status': 'OK',
                        'timestamp': time.time()
                    }

                    self.memory_scanner.increment()
                    self.root.after(0, self._add_result_to_tree, oid, value)

                    count += 1
                    if count % 100 == 0:
                        self.root.after(0, lambda c=count: self.status_var.set(f"Walk: {c} OIDs found..."))

                self.logger.info(f"Walk completed: {count} OIDs in {response_time:.1f}s")
                self.root.after(0, lambda c=count: self.status_var.set(f"Walk completed: {c} OIDs"))

            except Exception as e:
                self.performance_monitor.record_query(time.time() - start_time, False)
                self.logger.error(f"Full walk error: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Walk Error", str(e)))
            finally:
                self.scanning = False
                self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.progress.stop())

        threading.Thread(target=walk_worker, daemon=True).start()

    def refresh_dashboard(self):
        """Refresh dashboard with performance tracking"""
        if not self.saved_values:
            self.status_var.set("Dashboard empty")
            return

        # Clear dashboard
        for item in self.dashboard_tree.get_children():
            self.dashboard_tree.delete(item)

        self.status_var.set("Refreshing dashboard...")
        self.progress.start()
        self.logger.info(f"Refreshing dashboard: {len(self.saved_values)} items")

        def refresh_worker():
            try:
                errors = []
                success = 0

                for key, config in self.saved_values.items():
                    start_time = time.time()
                    try:
                        # Create client for this host
                        if config.get('version') == '3':
                            # Use saved (decrypted) credentials
                            if 'v3_config' in config:
                                v3_config = config['v3_config']

                                # Decrypt passwords
                                auth_pass = self.credential_manager.decrypt_password(
                                    v3_config.get('auth_password_encrypted', ''))
                                priv_pass = self.credential_manager.decrypt_password(
                                    v3_config.get('priv_password_encrypted', ''))

                                # Create v3 user
                                user = SnmpV3User(
                                    username=v3_config.get('username', ''),
                                    auth_protocol=SnmpV3AuthProtocol[v3_config.get('auth_protocol', 'NO_AUTH')],
                                    auth_password=auth_pass,
                                    priv_protocol=SnmpV3PrivProtocol[v3_config.get('priv_protocol', 'NO_PRIV')],
                                    priv_password=priv_pass
                                )

                                client = SnmpClient(
                                    config['host'],
                                    int(config['port']),
                                    version=SnmpVersion.V3,
                                    v3_user=user,
                                    timeout=float(self.timeout_var.get()),
                                    retries=int(self.retries_var.get())
                                )
                            else:
                                continue
                        else:
                            version = SnmpVersion.V1 if config['version'] == "1" else SnmpVersion.V2C
                            client = SnmpClient(
                                config['host'],
                                int(config['port']),
                                config['community'],
                                version,
                                float(self.timeout_var.get()),
                                int(self.retries_var.get())
                            )

                        # Get value
                        result = client.get(config['oid'])
                        response_time = time.time() - start_time
                        
                        self.performance_monitor.record_query(response_time, result is not None)

                        if result:
                            if isinstance(result, SnmpOctetString):
                                value = result.value.decode('utf-8', errors='replace')
                            else:
                                value = str(result.value) if hasattr(result, 'value') else str(result)
                            status = "ok"
                            success += 1
                        else:
                            value = "N/A"
                            status = "error"
                            errors.append(f"{config['host']}:{config['oid']}")

                        timestamp = time.strftime("%H:%M:%S")

                        # Add to dashboard
                        self.root.after(0, lambda h=config['host'], o=config['oid'],
                                                  n=config['name'], v=value, t=timestamp, s=status:
                        self.dashboard_tree.insert("", tk.END, values=(h, o, n, v, t, s)))

                    except Exception as e:
                        self.performance_monitor.record_query(time.time() - start_time, False)
                        errors.append(f"{config['host']}:{config['oid']} - {str(e)}")
                        self.root.after(0, lambda h=config['host'], o=config['oid'],
                                                  n=config['name'], e=str(e):
                        self.dashboard_tree.insert("", tk.END,
                                                   values=(
                                                   h, o, n, f"Error: {e[:30]}...", time.strftime("%H:%M:%S"), "error")))

                # Final report
                total = len(self.saved_values)
                self.logger.info(f"Dashboard refreshed: {success}/{total} OK")

                if errors:
                    self.root.after(0, lambda: self.status_var.set(
                        f"Dashboard: {success}/{total} OK, {len(errors)} errors"))
                else:
                    self.root.after(0, lambda: self.status_var.set(
                        f"Dashboard refreshed: {total} items"))

            except Exception as e:
                self.logger.error(f"Dashboard refresh error: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Dashboard Error", str(e)))
            finally:
                self.root.after(0, lambda: self.progress.stop())

        threading.Thread(target=refresh_worker, daemon=True).start()

    def export_results(self):
        """Export results in ALL formats"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("JSON Files", "*.json"),
                ("Text Files", "*.txt"),
                ("HTML Files", "*.html"),
                ("XML Files", "*.xml"),
                ("All Files", "*.*")
            ],
            initialfile=f"snmp_export_{self.host_var.get().replace('.', '_')}_{time.strftime('%Y%m%d_%H%M%S')}"
        )

        if not filename:
            return

        try:
            self.logger.info(f"Exporting results to: {filename}")

            if filename.endswith('.json'):
                # Export JSON with performance metrics
                export_data = {
                    'metadata': {
                        'host': self.host_var.get(),
                        'version': self.version_var.get(),
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'total_results': len(self.scan_results),
                        'performance_summary': self.performance_monitor.get_summary()
                    },
                    'results': {}
                }

                for oid, data in self.scan_results.items():
                    export_data['results'][oid] = {
                        'name': self._get_oid_description(oid),
                        'value': str(data['value']),
                        'type': data['type'],
                        'status': data['status'],
                        'timestamp': data['timestamp']
                    }

                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)

            elif filename.endswith('.csv'):
                # Export CSV
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['OID', 'Name', 'Type', 'Value', 'Status', 'Timestamp'])

                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        if values:
                            writer.writerow(values)

            elif filename.endswith('.html'):
                # Advanced HTML export
                with open(filename, 'w', encoding='utf-8') as f:
                    perf_summary = self.performance_monitor.get_summary()
                    f.write("""<!DOCTYPE html>
<html>
<head>
    <title>SNMP Export - """ + self.host_var.get() + """</title>
    <meta charset="utf-8">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .metric-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        .metric-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        table { 
            border-collapse: collapse; 
            width: 100%;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left; 
        }
        th { 
            background: #667eea; 
            color: white;
            position: sticky;
            top: 0;
        }
        tr:nth-child(even) { background: #f2f2f2; }
        tr:hover { background-color: #e0e0e0; }
        .status-ok { color: green; }
        .status-error { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SNMP Scan Results</h1>
        <p><strong>Host:</strong> """ + self.host_var.get() + """</p>
        <p><strong>Version:</strong> SNMPv""" + self.version_var.get() + """</p>
        <p><strong>Date:</strong> """ + time.strftime('%Y-%m-%d %H:%M:%S') + """</p>
        <p><strong>Total Results:</strong> """ + str(len(self.scan_results)) + """</p>
    </div>
    
    <div class="metrics">
        <div class="metric-card">
            <div class="metric-label">Total Queries</div>
            <div class="metric-value">""" + str(perf_summary['total_queries']) + """</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Success Rate</div>
            <div class="metric-value">""" + perf_summary['success_rate'] + """</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Avg Response Time</div>
            <div class="metric-value">""" + perf_summary['avg_response_time'] + """</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Memory Used</div>
            <div class="metric-value">""" + perf_summary['memory_mb'] + """ MB</div>
        </div>
    </div>
    
    <table>
        <tr>
            <th>OID</th>
            <th>Name</th>
            <th>Type</th>
            <th>Value</th>
            <th>Status</th>
            <th>Timestamp</th>
        </tr>
""")
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        if values:
                            status_class = 'status-ok' if values[4] == 'OK' else 'status-error'
                            f.write(f"""        <tr>
            <td>{values[0]}</td>
            <td>{values[1]}</td>
            <td>{values[2]}</td>
            <td>{values[3]}</td>
            <td class="{status_class}">{values[4]}</td>
            <td>{values[5]}</td>
        </tr>
""")

                    f.write("""    </table>
</body>
</html>""")

            elif filename.endswith('.xml'):
                # Export XML
                import xml.etree.ElementTree as ET

                root = ET.Element('snmp_export')

                # Metadata
                metadata = ET.SubElement(root, 'metadata')
                ET.SubElement(metadata, 'host').text = self.host_var.get()
                ET.SubElement(metadata, 'version').text = self.version_var.get()
                ET.SubElement(metadata, 'timestamp').text = time.strftime('%Y-%m-%d %H:%M:%S')
                ET.SubElement(metadata, 'total_results').text = str(len(self.scan_results))

                # Results
                results = ET.SubElement(root, 'results')

                for item in self.results_tree.get_children():
                    values = self.results_tree.item(item)['values']
                    if values:
                        result = ET.SubElement(results, 'result')
                        ET.SubElement(result, 'oid').text = str(values[0])
                        ET.SubElement(result, 'name').text = str(values[1])
                        ET.SubElement(result, 'type').text = str(values[2])
                        ET.SubElement(result, 'value').text = str(values[3])
                        ET.SubElement(result, 'status').text = str(values[4])
                        ET.SubElement(result, 'timestamp').text = str(values[5])

                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)

            else:
                # Export TXT
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write("SNMP SCAN RESULTS\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"Host: {self.host_var.get()}\n")
                    f.write(f"Version: SNMPv{self.version_var.get()}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Results: {len(self.scan_results)}\n")
                    f.write("=" * 80 + "\n\n")

                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        if values:
                            f.write(f"OID: {values[0]}\n")
                            f.write(f"Name: {values[1]}\n")
                            f.write(f"Type: {values[2]}\n")
                            f.write(f"Value: {values[3]}\n")
                            f.write(f"Status: {values[4]}\n")
                            f.write(f"Timestamp: {values[5]}\n")
                            f.write("-" * 40 + "\n\n")

            self.logger.info(f"Export completed: {os.path.basename(filename)}")
            messagebox.showinfo("Export Complete",
                                f"Results exported successfully!\n\n"
                                f"File: {os.path.basename(filename)}\n"
                                f"Total: {len(self.scan_results)} results")

            # Ask if open file
            if messagebox.askyesno("Open File", "Do you want to open the exported file?"):
                if sys.platform.startswith('win'):
                    os.startfile(filename)
                elif sys.platform.startswith('darwin'):
                    os.system(f'open "{filename}"')
                else:
                    os.system(f'xdg-open "{filename}"')

        except Exception as e:
            self.logger.error(f"Export error: {str(e)}")
            messagebox.showerror("Export Error", f"Export error:\n{str(e)}")

    def save_config(self):
        """Save configuration with encrypted credentials"""
        config = {
            'host': self.host_var.get(),
            'community': self.community_var.get(),
            'port': self.port_var.get(),
            'version': self.version_var.get(),
            'timeout': self.timeout_var.get(),
            'retries': self.retries_var.get(),
            'extended_scan': self.extended_scan_var.get(),
            'max_results': self.max_results_var.get(),
            'max_memory': self.max_memory_var.get(),
            'current_profile': self.current_profile_var.get(),
            'language': self.language_manager.get_current_language()
        }

        if self.version_var.get() == "3":
            # Encrypt v3 passwords
            config['v3_user'] = self.v3_user_var.get()
            config['v3_auth_protocol'] = self.v3_auth_protocol_var.get()
            config['v3_auth_password_encrypted'] = self.credential_manager.encrypt_password(
                self.v3_auth_password_var.get())
            config['v3_priv_protocol'] = self.v3_priv_protocol_var.get()
            config['v3_priv_password_encrypted'] = self.credential_manager.encrypt_password(
                self.v3_priv_password_var.get())
            config['v3_engine_id'] = self.v3_engine_id_var.get()

        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            self.logger.info("Configuration saved")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")

    def save_language_preference(self, language_code):
        """Save language preference to config"""
        try:
            # Load existing config if it exists
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)

            # Update language
            config['language'] = language_code

            # Save config
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)

            self.logger.info(f"Language preference saved: {language_code}")
        except Exception as e:
            self.logger.error(f"Error saving language preference: {e}")

    def load_config(self):
        """Load configuration with decryption"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)

                self.host_var.set(config.get('host', '192.168.1.1'))
                self.community_var.set(config.get('community', 'public'))
                self.port_var.set(config.get('port', '161'))
                self.version_var.set(config.get('version', '2c'))
                self.timeout_var.set(config.get('timeout', '5.0'))
                self.retries_var.set(config.get('retries', '3'))
                self.extended_scan_var.set(config.get('extended_scan', False))
                self.max_results_var.set(config.get('max_results', '10000'))
                self.max_memory_var.set(config.get('max_memory', '500'))
                self.current_profile_var.set(config.get('current_profile', 'Default'))

                # Load language preference
                if 'language' in config:
                    self.language_manager.set_language(config['language'])

                if 'v3_user' in config:
                    self.v3_user_var.set(config.get('v3_user', ''))
                    self.v3_auth_protocol_var.set(config.get('v3_auth_protocol', 'noAuth'))

                    # Decrypt passwords
                    if 'v3_auth_password_encrypted' in config:
                        auth_pass = self.credential_manager.decrypt_password(
                            config['v3_auth_password_encrypted'])
                        self.v3_auth_password_var.set(auth_pass)

                    self.v3_priv_protocol_var.set(config.get('v3_priv_protocol', 'noPriv'))

                    if 'v3_priv_password_encrypted' in config:
                        priv_pass = self.credential_manager.decrypt_password(
                            config['v3_priv_password_encrypted'])
                        self.v3_priv_password_var.set(priv_pass)

                    self.v3_engine_id_var.set(config.get('v3_engine_id', ''))

                self.logger.info("Configuration loaded")

        except Exception as e:
            self.logger.error(f"Error loading config: {e}")

    def show_settings(self):
        """Show advanced settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("450x550")
        settings_window.transient(self.root)
        settings_window.grab_set()

        # Notebook for categories
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Limits Tab
        limits_frame = ttk.Frame(notebook)
        notebook.add(limits_frame, text="Limits")

        ttk.Label(limits_frame, text="Scan Limits:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        limits_info = ttk.Frame(limits_frame)
        limits_info.pack(padx=20, pady=10)

        ttk.Label(limits_info, text="Max Results:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(limits_info, textvariable=self.max_results_var, width=10).grid(row=0, column=1, padx=10)

        ttk.Label(limits_info, text="Max Memory (MB):").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(limits_info, textvariable=self.max_memory_var, width=10).grid(row=1, column=1, padx=10)

        # Logging Tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Logging")

        ttk.Label(log_frame, text="Log Configuration:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        log_level_var = tk.StringVar(value="INFO")
        ttk.Label(log_frame, text="Log Level:").pack()
        ttk.Combobox(log_frame, textvariable=log_level_var,
                     values=["DEBUG", "INFO", "WARNING", "ERROR"],
                     state='readonly').pack(pady=5)

        def apply_log_level():
            level = getattr(logging, log_level_var.get())
            self.logger.setLevel(level)
            messagebox.showinfo("OK", f"Log level set to {log_level_var.get()}")

        ttk.Button(log_frame, text="Apply", command=apply_log_level).pack(pady=10)

        # Security Tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security")

        ttk.Label(security_frame, text="Security Options:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        def clear_passwords():
            """Clear passwords from memory"""
            self.v3_auth_password_var.set("")
            self.v3_priv_password_var.set("")

            # Force garbage collection
            self.credential_manager.secure_delete(self.v3_auth_password_var.get())
            self.credential_manager.secure_delete(self.v3_priv_password_var.get())

            gc.collect()
            messagebox.showinfo("OK", "Passwords cleared from memory")

        ttk.Button(security_frame, text="Clear Passwords from Memory",
                   command=clear_passwords).pack(pady=10)

        # Performance Tab
        perf_frame = ttk.Frame(notebook)
        notebook.add(perf_frame, text="Performance")
        
        ttk.Label(perf_frame, text="Performance Options:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)
        
        perf_info = ttk.Frame(perf_frame)
        perf_info.pack(padx=20, pady=10)
        
        ttk.Label(perf_info, text="Max Batch Workers:").grid(row=0, column=0, sticky=tk.W, pady=5)
        batch_workers_var = tk.StringVar(value=str(self.batch_operations.max_workers))
        ttk.Entry(perf_info, textvariable=batch_workers_var, width=10).grid(row=0, column=1, padx=10)
        
        def apply_performance():
            try:
                self.batch_operations.max_workers = int(batch_workers_var.get())
                messagebox.showinfo("OK", "Performance settings applied")
            except:
                messagebox.showerror("Error", "Invalid value")
                
        ttk.Button(perf_frame, text="Apply", command=apply_performance).pack(pady=10)

        # Buttons
        btn_frame = ttk.Frame(settings_window)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="OK", command=settings_window.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=settings_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_log_viewer(self):
        """View log file"""
        log_window = tk.Toplevel(self.root)
        log_window.title("Log Viewer")
        log_window.geometry("800x600")
        log_window.transient(self.root)

        # Text widget with scrollbar
        frame = ttk.Frame(log_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        text = tk.Text(frame, wrap=tk.NONE)
        v_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        h_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        text.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Load latest log
        try:
            log_file = os.path.join("logs", f"snmp_browser_{datetime.now().strftime('%Y%m%d')}.log")
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    text.insert(tk.END, f.read())
                text.see(tk.END)
            else:
                text.insert(tk.END, "No log file found for today.")
        except Exception as e:
            text.insert(tk.END, f"Error loading log: {str(e)}")

        text.config(state=tk.DISABLED)

        # Buttons
        btn_frame = ttk.Frame(log_window)
        btn_frame.pack(pady=5)

        def refresh_log():
            text.config(state=tk.NORMAL)
            text.delete(1.0, tk.END)
            try:
                with open(log_file, 'r') as f:
                    text.insert(tk.END, f.read())
                text.see(tk.END)
            except:
                pass
            text.config(state=tk.DISABLED)

        ttk.Button(btn_frame, text="Refresh", command=refresh_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=log_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_debug_info(self):
        """Show debug information"""
        info = f"""
DEBUG INFO

System: {sys.platform}
Python: {sys.version}
Memory: {psutil.Process().memory_info().rss / 1024 / 1024:.1f}MB
CPU: {psutil.cpu_percent()}%

Results loaded: {len(self.scan_results)}
Dashboard items: {len(self.saved_values)}
Traps received: {len(self.received_traps)}
Saved profiles: {len(self.profile_manager.list_profiles())}

Performance Summary:
{json.dumps(self.performance_monitor.get_summary(), indent=2)}

Log directory: {os.path.abspath('logs')}
Config file: {os.path.abspath(self.config_file)}

SNMP Client active: {'Yes' if self.client else 'No'}
SNMP Version: {self.version_var.get()}
Trap Receiver: {'Active' if self.trap_receiver and self.trap_receiver.running else 'Inactive'}
"""

        messagebox.showinfo("Debug Info", info)

    def show_shortcuts(self):
        """Show keyboard shortcuts"""
        shortcuts = """
KEYBOARD SHORTCUTS

Ctrl+S    - Save configuration
Ctrl+O    - Load configuration  
Ctrl+E    - Export results
Ctrl+T    - Test connection
Ctrl+Q    - Exit

F1        - Help
F5        - Refresh dashboard
ESC       - Stop scan

Double Click - GET on OID
Right Click  - Context menu
"""
        messagebox.showinfo("Shortcuts", shortcuts)

    def on_closing(self):
        """Application closing with cleanup"""
        if self.scanning:
            if not messagebox.askyesno("Scan in progress",
                                       "Scan in progress. Do you really want to exit?"):
                return
            self.stop_scan()

        # Stop trap receiver
        if self.trap_receiver and self.trap_receiver.running:
            self.trap_receiver.stop()

        # Stop timer
        if self.auto_refresh_timer:
            self.root.after_cancel(self.auto_refresh_timer)

        # Save configuration
        self.save_config()
        self.save_saved_values()

        # Clear passwords from memory
        self.credential_manager.secure_delete(self.v3_auth_password_var.get())
        self.credential_manager.secure_delete(self.v3_priv_password_var.get())

        # Cleanup
        gc.collect()

        self.logger.info("Application closing")
        self.logger.info("=" * 60)

        self.root.quit()
        self.root.destroy()

    # Existing helper methods from original code

    def apply_filter(self, *args):
        """Apply filters to results"""
        filter_text = self.filter_var.get().lower()
        show_errors = self.show_errors_var.get()

        for item in self.results_tree.get_children():
            values = self.results_tree.item(item)['values']
            if not values:
                continue

            text_match = (not filter_text or
                          any(filter_text in str(v).lower() for v in values))

            error_match = (not show_errors or values[4] != "OK")

            if text_match and error_match:
                self.results_tree.reattach(item, "", tk.END)
            else:
                self.results_tree.detach(item)

    def clear_filter(self):
        """Clear filters"""
        self.filter_var.set("")
        self.show_errors_var.set(False)

    def on_result_double_click(self, event):
        """Double click on result"""
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            values = self.results_tree.item(item)['values']
            if values:
                self.get_single_oid(values[0])

    def on_mib_double_click(self, event):
        """Double click on MIB tree - Show complete details"""
        selection = self.mib_tree.selection()
        if selection:
            item = selection[0]
            values = self.mib_tree.item(item)['values']
            if values and values[0]:  # If it has an OID
                oid = values[0]
                value = values[1] if len(values) > 1 else ""
                type_str = values[2] if len(values) > 2 else ""
                status = values[3] if len(values) > 3 else ""
                
                # If there's a value, show details
                if value:
                    # Retrieve full value if truncated
                    if oid in self.scan_results:
                        data = self.scan_results[oid]
                        raw_value = data.get('value')
                        
                        if isinstance(raw_value, SnmpOctetString):
                            try:
                                full_value = raw_value.value.decode('utf-8', errors='replace')
                            except:
                                full_value = raw_value.value.hex()
                        elif hasattr(raw_value, 'value'):
                            full_value = str(raw_value.value)
                        else:
                            full_value = str(raw_value)
                    else:
                        full_value = value
                    
                    # Show dialog with full value
                    detail_window = tk.Toplevel(self.root)
                    detail_window.title("OID Details")
                    detail_window.geometry("600x400")
                    detail_window.transient(self.root)
                    
                    # Info frame
                    info_frame = ttk.LabelFrame(detail_window, text="OID Information")
                    info_frame.pack(fill=tk.X, padx=10, pady=10)
                    
                    ttk.Label(info_frame, text=f"OID: {oid}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(info_frame, text=f"Name: {self._get_oid_description(oid)}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(info_frame, text=f"Type: {type_str}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(info_frame, text=f"Status: {status}").pack(anchor=tk.W, padx=5, pady=2)
                    
                    # Value frame
                    value_frame = ttk.LabelFrame(detail_window, text="Value")
                    value_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
                    
                    text_widget = tk.Text(value_frame, wrap=tk.WORD)
                    text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                    text_widget.insert(tk.END, full_value)
                    text_widget.config(state=tk.DISABLED)
                    
                    # Buttons
                    btn_frame = ttk.Frame(detail_window)
                    btn_frame.pack(pady=5)
                    
                    def copy_value():
                        self.root.clipboard_clear()
                        self.root.clipboard_append(full_value)
                        messagebox.showinfo("Copied", "Value copied to clipboard!")
                    
                    ttk.Button(btn_frame, text="Copy Value", command=copy_value).pack(side=tk.LEFT, padx=5)
                    ttk.Button(btn_frame, text="GET", command=lambda: self.get_single_oid(oid)).pack(side=tk.LEFT, padx=5)
                    ttk.Button(btn_frame, text="OK", command=detail_window.destroy).pack(side=tk.LEFT, padx=5)
                else:
                    # If no value, try to GET
                    self.get_single_oid(oid)

    def show_context_menu(self, event):
        """Context menu"""
        selection = self.results_tree.selection()
        if not selection:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="GET", command=self.get_selected)
        menu.add_command(label="SET", command=self.set_value)
        menu.add_command(label="WALK", command=self.walk_from_selected)
        menu.add_separator()
        menu.add_command(label="Add to Dashboard", command=self.add_to_dashboard)
        menu.add_command(label="Copy OID", command=self.copy_oid)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def add_to_dashboard(self):
        """Add to dashboard with v3 support"""
        selection = self.results_tree.selection()
        if not selection:
            return

        count = 0
        for item in selection:
            values = self.results_tree.item(item)['values']
            if values:
                key = f"{self.host_var.get()}_{values[0]}"

                config = {
                    'host': self.host_var.get(),
                    'oid': values[0],
                    'name': values[1],
                    'community': self.community_var.get(),
                    'version': self.version_var.get(),
                    'port': self.port_var.get()
                }

                # If v3, save encrypted configuration
                if self.version_var.get() == "3":
                    config['v3_config'] = {
                        'username': self.v3_user_var.get(),
                        'auth_protocol': self.v3_auth_protocol_var.get(),
                        'auth_password_encrypted': self.credential_manager.encrypt_password(
                            self.v3_auth_password_var.get()),
                        'priv_protocol': self.v3_priv_protocol_var.get(),
                        'priv_password_encrypted': self.credential_manager.encrypt_password(
                            self.v3_priv_password_var.get())
                    }

                self.saved_values[key] = config
                count += 1

        self.save_saved_values()
        self.logger.info(f"Added {count} items to dashboard")
        messagebox.showinfo("Dashboard", f"Added {count} items to dashboard")

    def copy_oid(self):
        """Copy OID to clipboard"""
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            values = self.results_tree.item(item)['values']
            if values:
                self.root.clipboard_clear()
                self.root.clipboard_append(values[0])
                self.status_var.set(f"OID copied: {values[0]}")

    def remove_from_dashboard(self):
        """Remove from dashboard"""
        selection = self.dashboard_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select items to remove")
            return

        for item in selection:
            values = self.dashboard_tree.item(item)['values']
            if values:
                key = f"{values[0]}_{values[1]}"
                if key in self.saved_values:
                    del self.saved_values[key]
            self.dashboard_tree.delete(item)

        self.save_saved_values()

    def clear_dashboard(self):
        """Clear dashboard"""
        if self.saved_values and messagebox.askyesno("Confirm", "Remove all items?"):
            self.saved_values.clear()
            for item in self.dashboard_tree.get_children():
                self.dashboard_tree.delete(item)
            self.save_saved_values()

    def toggle_auto_refresh(self):
        """Toggle dashboard auto-refresh"""
        if self.auto_refresh_var.get():
            self.refresh_dashboard()
            self.auto_refresh_timer = self.root.after(30000, self.toggle_auto_refresh)
            self.logger.info("Dashboard auto-refresh enabled")
        else:
            if self.auto_refresh_timer:
                self.root.after_cancel(self.auto_refresh_timer)
                self.auto_refresh_timer = None
            self.logger.info("Dashboard auto-refresh disabled")

    def build_mib_tree(self):
        """Build MIB tree with descriptive names"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "Perform a scan first")
            return

        # Clear existing tree
        for item in self.mib_tree.get_children():
            self.mib_tree.delete(item)

        self.status_var.set("Building MIB tree...")
        self.progress.start()
        
        # Structure to organize OIDs hierarchically
        tree_structure = {}
        
        # Process each OID from results
        for oid, data in self.scan_results.items():
            parts = oid.split('.')
            current = tree_structure
            
            # Build full path
            path = []
            for i, part in enumerate(parts):
                if part:  # Ignore empty parts
                    path.append(part)
                    full_oid = '.'.join(path)
                    
                    if part not in current:
                        current[part] = {
                            '_oid': full_oid,
                            '_name': self._get_oid_description(full_oid),
                            '_data': None,
                            '_children': {}
                        }
                    
                    # If this is the complete OID, save the data
                    if full_oid == oid:
                        current[part]['_data'] = data
                        
                    current = current[part]['_children']
        
        # Populate the tree
        self._populate_mib_tree_enhanced("", tree_structure)
        
        self.progress.stop()
        self.status_var.set("MIB tree built")
        
        # Expand first levels
        for item in self.mib_tree.get_children():
            self.mib_tree.item(item, open=True)
            for child in self.mib_tree.get_children(item):
                self.mib_tree.item(child, open=True)

    def _populate_mib_tree_enhanced(self, parent, tree_dict):
        """Populate MIB tree with values visible directly"""
        for key, value in sorted(tree_dict.items(), key=lambda x: (x[0].isdigit(), int(x[0]) if x[0].isdigit() else x[0])):
            if isinstance(value, dict):
                oid = value.get('_oid', key)
                name = value.get('_name', '')
                data = value.get('_data', None)
                children = value.get('_children', {})
                
                # Determine text to show
                if name:
                    display_text = f"{key} - {name}"
                else:
                    display_text = key
                
                # Prepare value to show
                value_str = ""
                type_str = ""
                status_str = ""
                
                if data:
                    # If we have data for this OID
                    raw_value = data.get('value')
                    
                    # Format value for display
                    if isinstance(raw_value, SnmpOctetString):
                        try:
                            value_str = raw_value.value.decode('utf-8', errors='replace')
                            # Truncate if too long
                            if len(value_str) > 100:
                                value_str = value_str[:100] + "..."
                        except:
                            value_str = raw_value.value.hex()
                            if len(value_str) > 50:
                                value_str = value_str[:50] + "..."
                    elif hasattr(raw_value, 'value'):
                        value_str = str(raw_value.value)
                        if len(value_str) > 100:
                            value_str = value_str[:100] + "..."
                    else:
                        value_str = str(raw_value) if raw_value else ""
                        if len(value_str) > 100:
                            value_str = value_str[:100] + "..."
                    
                    type_str = data.get('type', '')
                    status_str = data.get('status', 'OK')
                    
                    # Tag for nodes with data (different color if we want)
                    tag = 'hasdata'
                else:
                    # Nodes without data
                    tag = 'nodata'
                
                # Insert node with all info including value
                node = self.mib_tree.insert(parent, tk.END, 
                                        text=display_text,
                                        values=(oid, value_str, type_str, status_str),
                                        tags=(tag,))
                
                # Color configuration (black for all)
                self.mib_tree.tag_configure('hasdata', foreground='black', font=('TkDefaultFont', 9, 'normal'))
                self.mib_tree.tag_configure('nodata', foreground='black', font=('TkDefaultFont', 9, 'normal'))
                
                # Recursively process children
                if children:
                    self._populate_mib_tree_enhanced(node, children)

    def expand_all_mib(self):
        """Expand all MIB tree"""
        for item in self.mib_tree.get_children():
            self._expand_tree_recursive(item)

    def collapse_all_mib(self):
        """Collapse all MIB tree"""
        for item in self.mib_tree.get_children():
            self._collapse_tree_recursive(item)

    def _expand_tree_recursive(self, item):
        """Expand recursively"""
        self.mib_tree.item(item, open=True)
        for child in self.mib_tree.get_children(item):
            self._expand_tree_recursive(child)

    def _collapse_tree_recursive(self, item):
        """Collapse recursively"""
        self.mib_tree.item(item, open=False)
        for child in self.mib_tree.get_children(item):
            self._collapse_tree_recursive(child)

    def clear_cache(self):
        """Clear cache and results"""
        if messagebox.askyesno("Clear Cache", "Clear all results and cache?"):
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            for item in self.mib_tree.get_children():
                self.mib_tree.delete(item)

            self.scan_results.clear()
            self.mib_tree_data.clear()

            gc.collect()

            self.status_var.set("Cache cleared")
            self.info_var.set("")
            self.logger.info("Cache cleared")

    def load_config_dialog(self):
        """Load configuration dialog"""
        filename = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'r') as f:
                    config = json.load(f)

                # Apply configuration
                self.host_var.set(config.get('host', '192.168.1.1'))
                self.community_var.set(config.get('community', 'public'))
                self.port_var.set(config.get('port', '161'))
                self.version_var.set(config.get('version', '2c'))
                self.timeout_var.set(config.get('timeout', '5.0'))
                self.retries_var.set(config.get('retries', '3'))

                messagebox.showinfo("Configuration", "Configuration loaded successfully!")
                self.logger.info(f"Configuration loaded from: {filename}")

            except Exception as e:
                messagebox.showerror("Error", f"Loading error:\n{str(e)}")
                self.logger.error(f"Error loading config: {str(e)}")

    def save_saved_values(self):
        """Save dashboard values"""
        try:
            with open(self.saved_values_file, 'w') as f:
                json.dump(self.saved_values, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving dashboard: {e}")

    def load_saved_values(self):
        """Load dashboard values"""
        try:
            if os.path.exists(self.saved_values_file):
                with open(self.saved_values_file, 'r') as f:
                    self.saved_values = json.load(f)
                self.logger.info(f"Dashboard loaded: {len(self.saved_values)} items")
        except Exception as e:
            self.logger.error(f"Error loading dashboard: {e}")

    def show_snmpv3_wizard(self):
        """SNMPv3 configuration wizard"""
        wizard = tk.Toplevel(self.root)
        wizard.title("SNMPv3 Wizard")
        wizard.geometry("500x400")
        wizard.transient(self.root)

        text = """
SNMPv3 CONFIGURATION

1. USERNAME: Identifies the SNMPv3 user

2. AUTHENTICATION:
   • noAuth: No authentication
   • MD5/SHA: Requires password (min 8 characters)

3. PRIVACY (Encryption):
   • noPriv: No encryption
   • DES/AES: Requires privacy password

4. SECURITY LEVELS:
   • noAuthNoPriv: Username only
   • authNoPriv: Username + authentication
   • authPriv: Username + auth + encryption

5. ENGINE ID: Uniquely identifies the device
   (use "Discover Engine ID" to get it)

Passwords must match those configured
on the SNMP device!
"""

        text_widget = tk.Text(wizard, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)

        ttk.Button(wizard, text="OK", command=wizard.destroy).pack(pady=10)

    def show_help(self):
        """Show help"""
        help_text = """
SNMP BROWSER HELP

BASIC OPERATIONS:
• Configure host and parameters
• Choose SNMP version (1, 2c, 3)
• Click "Start Scan"
• View results in browser

SNMPv3:
• Requires username and password
• Supports authentication and encryption
• Use "Discover Engine ID" for discovery

ADVANCED FEATURES:
• GET: Double click on OID
• SET: Right click > SET
• WALK: Right click > WALK
• Dashboard: Monitor specific values
• Export: Save in various formats

NEW FEATURES:
• Trap Receiver: Receive SNMP traps
• Performance Monitor: Track metrics
• Batch Operations: Query multiple hosts
• MIB Loading: Load custom MIB files
• Profile Manager: Save configurations

SECURITY LIMITS:
• Max 10000 results per scan
• Max 500MB memory
• 5 minutes timeout per scan
• Encrypted passwords in configuration

SHORTCUTS:
• F5: Refresh dashboard
• Ctrl+T: Test connection
• Ctrl+S: Save configuration
• ESC: Stop scan
"""

        help_window = tk.Toplevel(self.root)
        help_window.title("Help")
        help_window.geometry("600x500")
        help_window.transient(self.root)

        text = tk.Text(help_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)

        ttk.Button(help_window, text="OK", command=help_window.destroy).pack(pady=10)

    def change_language(self):
        """Show language selection dialog"""
        lang_window = tk.Toplevel(self.root)
        lang_window.title(self._("select_language"))
        lang_window.geometry("350x400")
        lang_window.resizable(False, False)
        lang_window.transient(self.root)

        # Center window
        lang_window.update_idletasks()
        x = (lang_window.winfo_screenwidth() // 2) - (350 // 2)
        y = (lang_window.winfo_screenheight() // 2) - (400 // 2)
        lang_window.geometry(f'+{x}+{y}')

        # Main frame
        main_frame = ttk.Frame(lang_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        ttk.Label(main_frame, text=self._("select_language"),
                font=('TkDefaultFont', 14, 'bold')).pack(pady=(0, 15))

        # Language list
        listbox_frame = ttk.Frame(main_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Listbox
        lang_listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set,
                                  font=('TkDefaultFont', 11), height=12)
        lang_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=lang_listbox.yview)

        # Populate languages
        languages = self.language_manager.get_available_languages()
        current_lang = self.language_manager.get_current_language()
        current_index = 0

        for i, (code, name) in enumerate(languages):
            if code == current_lang:
                lang_listbox.insert(tk.END, f"✓ {name}")
                current_index = i
            else:
                lang_listbox.insert(tk.END, f"  {name}")

        lang_listbox.selection_set(current_index)
        lang_listbox.see(current_index)

        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(15, 0))

        def apply_language():
            selection = lang_listbox.curselection()
            if selection:
                index = selection[0]
                code, name = languages[index]
                if self.language_manager.set_language(code):
                    self.save_language_preference(code)
                    messagebox.showinfo(
                        self._("success"),
                        f"{self._('language')} {self._('info').lower()}: {name}\n\n"
                        f"Please restart the application for all changes to take effect."
                    )
                    lang_window.destroy()

        ttk.Button(btn_frame, text=self._("apply"), command=apply_language,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text=self._("cancel"),
                command=lang_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_about(self):
        """Show about window with logo"""
        # Create custom window
        about_window = tk.Toplevel(self.root)
        about_window.title(self._("about") + " - SNMP Browser")
        about_window.geometry("450x490")
        about_window.resizable(False, False)
        about_window.transient(self.root)
        
        # Center window
        about_window.update_idletasks()
        x = (about_window.winfo_screenwidth() // 2) - (450 // 2)
        y = (about_window.winfo_screenheight() // 2) - (480 // 2)
        about_window.geometry(f'+{x}+{y}')
        
        # Main frame
        main_frame = ttk.Frame(about_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Logo
        try:
            logo = self.get_about_logo()
            logo_label = ttk.Label(main_frame, image=logo)
            logo_label.image = logo
            logo_label.pack(pady=(5, 10))
        except Exception as e:
            self.logger.error(f"Unable to load icon: {e}")
            logo_label = ttk.Label(main_frame, text="SNMP Browser", font=('Arial', 48))
            logo_label.pack(pady=(5, 10))
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack()
        
        ttk.Label(title_frame, text="SNMP Browser",
                font=('TkDefaultFont', 16, 'bold')).pack()
        
        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Features in two columns
        features_frame = ttk.LabelFrame(main_frame, text="✨ Features")
        features_frame.pack(fill='x', pady=5)
        
        features_content = ttk.Frame(features_frame)
        features_content.pack(padx=10, pady=8)
        
        # First column
        col1_features = [
            "SNMPv1/v2c/v3 Support",
            "AES Encryption",
            "Rotating Logging",
            "Optimized Memory"
        ]
        
        # Second column  
        col2_features = [
            "Multi-format Export",
            "Real-time Dashboard",
            "Integrated MIB Browser",
            "Bulk Scanning"
        ]
        
        # Two column grid
        for i, (feat1, feat2) in enumerate(zip(col1_features, col2_features)):
            ttk.Label(features_content, text=feat1, font=('TkDefaultFont', 8)).grid(
                row=i, column=0, sticky='w', padx=(0, 20))
            ttk.Label(features_content, text=feat2, font=('TkDefaultFont', 8)).grid(
                row=i, column=1, sticky='w')
        
        # Compact system info
        info_frame = ttk.LabelFrame(main_frame, text="System")
        info_frame.pack(fill='x', pady=5)
        
        info_content = ttk.Frame(info_frame)
        info_content.pack(padx=10, pady=8)
        
        # Compact grid info
        memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        cpu_percent = psutil.Process().cpu_percent()
        
        info_data = [
            ("OS:", sys.platform.title(), "Python:", sys.version.split()[0]),
            ("Memory:", f"{memory_mb:.1f} MB", "CPU:", f"{cpu_percent:.1f}%"),
            ("Results:", str(len(self.scan_results)), "Threads:", str(threading.active_count()))
        ]
        
        for i, (label1, value1, label2, value2) in enumerate(info_data):
            ttk.Label(info_content, text=label1, font=('TkDefaultFont', 8, 'bold')).grid(
                row=i, column=0, sticky='w', padx=(0, 5))
            ttk.Label(info_content, text=value1, font=('TkDefaultFont', 8)).grid(
                row=i, column=1, sticky='w', padx=(0, 20))
            ttk.Label(info_content, text=label2, font=('TkDefaultFont', 8, 'bold')).grid(
                row=i, column=2, sticky='w', padx=(0, 5))
            ttk.Label(info_content, text=value2, font=('TkDefaultFont', 8)).grid(
                row=i, column=3, sticky='w')
        
        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=8)
        
        # Copyright and credits
        credits_frame = ttk.Frame(main_frame)
        credits_frame.pack()
        
        ttk.Label(credits_frame, text="© 2024 - Powered by JustVugg",
                font=('TkDefaultFont', 9)).pack()
        
        # Link to SNMPY
        snmpy_label = ttk.Label(credits_frame, text="Based on SNMPY library", 
                            foreground='blue', cursor='hand2',
                            font=('TkDefaultFont', 9, 'underline'))
        snmpy_label.pack(pady=3)
        snmpy_label.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/JustVugg/snmpy"))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(8, 5))
        
        ttk.Button(button_frame, text="OK", 
                command=about_window.destroy, width=10).pack()
        
        # Focus and bind
        about_window.focus_set()
        about_window.bind('<Escape>', lambda e: about_window.destroy())
        about_window.bind('<Return>', lambda e: about_window.destroy())

    def get_about_logo(self):
        """Load logo from icon.png using PIL"""
        from PIL import Image, ImageTk
        
        try:
            # Icon.png file path
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
            
            if os.path.exists(icon_path):
                # Use PIL to load and resize image
                image = Image.open(icon_path)
                # Resize to 100x100 pixels
                image = image.resize((100, 100), Image.Resampling.LANCZOS)
                # Convert to PhotoImage for Tkinter
                return ImageTk.PhotoImage(image)
            else:
                raise FileNotFoundError(f"File not found: {icon_path}")
                
        except Exception as e:
            self.logger.error(f"Unable to load icon: {e}")
            raise  # Important: raise exception to trigger fallback


def check_dependencies():
    """Check required dependencies"""
    missing = []

    try:
        import psutil
    except ImportError:
        missing.append("psutil")

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        missing.append("cryptography")

    if missing:
        print("Missing dependencies:")
        print(f"   Install with: pip install {' '.join(missing)}")
        return False

    # Check optional
    try:
        import matplotlib
        print("✓ Matplotlib found - Performance graphs enabled")
    except ImportError:
        print("⚠ Matplotlib not found - Performance graphs disabled")
        print("  Install with: pip install matplotlib")

    return True


def main():
    """Main function production ready"""
    try:
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)

        # Create necessary directories
        os.makedirs("logs", exist_ok=True)

        # Create main window
        root = tk.Tk()

        # Icon (if available)
        try:
            # For Windows and Linux
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
            if os.path.exists(icon_path):
                icon = tk.PhotoImage(file=icon_path)
                root.iconphoto(True, icon)
            else:
                # Try with .ico for Windows
                ico_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
                if os.path.exists(ico_path) and sys.platform.startswith('win'):
                    root.iconbitmap(ico_path)
        except Exception as e:
            print(f"Unable to load icon: {e}")

        # Create application
        app = SnmpBrowserGUI(root)

        # Bind global shortcuts
        root.bind('<F1>', lambda e: app.show_help())
        root.bind('<F5>', lambda e: app.refresh_dashboard())
        root.bind('<Control-s>', lambda e: app.save_config())
        root.bind('<Control-o>', lambda e: app.load_config_dialog())
        root.bind('<Control-e>', lambda e: app.export_results())
        root.bind('<Control-t>', lambda e: app.test_connection())
        root.bind('<Control-q>', lambda e: app.on_closing())
        root.bind('<Escape>', lambda e: app.stop_scan() if app.scanning else None)

        # Center window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')

        # Start GUI
        root.mainloop()

    except Exception as e:
        print(f"Critical error: {e}")
        traceback.print_exc()

        try:
            messagebox.showerror("Critical Error",
                                 f"Unable to start application:\n\n{str(e)}")
        except:
            pass

        sys.exit(1)


if __name__ == "__main__":
    main()

        

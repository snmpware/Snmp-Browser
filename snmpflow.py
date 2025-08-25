#!/usr/bin/env python3
"""
SNMP Browser - Production Ready Enhanced
Browser SNMP professionale con supporto completo v1/v2c/v3
Include logging, crittografia credenziali, gestione memoria, trap receiver,
performance metrics, batch operations, MIB compilation e profili multipli
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

# Importa la libreria SNMPY
from snmpy import *
import webbrowser

# Per i grafici delle performance
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

class MibParser:
    """Parser MIB per nomi descrittivi"""
    
    def __init__(self, logger):
        self.logger = logger
        self.mib_definitions = {}
        self.custom_mibs = {}
        self.load_builtin_mibs()
        
    def load_builtin_mibs(self):
        """Carica MIB builtin per UPS e altri dispositivi comuni"""
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
        """Carica un file MIB custom"""
        try:
            self.logger.info(f"Caricamento MIB da: {filepath}")
            
            # Parser semplice per file MIB in formato testo
            with open(filepath, 'r') as f:
                content = f.read()
                
            # Estrai definizioni OBJECT-TYPE
            pattern = r'(\w+)\s+OBJECT-TYPE[\s\S]*?::=\s*\{\s*([\w\s]+)\s+(\d+)\s*\}'
            matches = re.findall(pattern, content)
            
            for name, parent, index in matches:
                # Costruisci OID completo
                if parent in self.custom_mibs:
                    parent_oid = self.custom_mibs[parent]
                    full_oid = f"{parent_oid}.{index}"
                    self.custom_mibs[name] = full_oid
                    self.mib_definitions[full_oid] = name
                    
            self.logger.info(f"Caricate {len(matches)} definizioni dal MIB")
            return True
            
        except Exception as e:
            self.logger.error(f"Errore caricamento MIB: {e}")
            return False
            
    def get_name(self, oid):
        """Ottiene nome descrittivo per OID"""
        return self.mib_definitions.get(oid, "")
        
    def search_name(self, pattern):
        """Cerca nomi che matchano pattern"""
        results = {}
        pattern_lower = pattern.lower()
        for oid, name in self.mib_definitions.items():
            if pattern_lower in name.lower():
                results[oid] = name
        return results

class TrapReceiver(threading.Thread):
    """Ricevitore SNMP Trap thread-safe"""
    
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
        """Main loop del trap receiver"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind sulla porta trap
            self.socket.bind(('', self.port))
            self.socket.settimeout(1.0)  # Timeout per permettere stop pulito
            
            self.running = True
            self.logger.info(f"Trap receiver avviato su porta {self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(65535)
                    
                    # Processa trap
                    trap_info = self.parse_trap(data, addr)
                    self.traps_received += 1
                    
                    # Aggiungi a coda
                    self.trap_queue.put(trap_info)
                    
                    # Callback se definito
                    if self.callback:
                        self.callback(trap_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Errore ricezione trap: {e}")
                        
        except Exception as e:
            self.logger.error(f"Errore avvio trap receiver: {e}")
        finally:
            if self.socket:
                self.socket.close()
            self.logger.info("Trap receiver fermato")
            
    def parse_trap(self, data, addr):
        """Parser migliorato per trap SNMP usando decode_snmp_hex"""
        trap_info = {
            'timestamp': datetime.now().isoformat(),
            'source': f"{addr[0]}:{addr[1]}",
            'raw_data': data.hex(),
            'size': len(data),
            'type': 'Unknown',
            'decoded': None  # Nuovo campo per info decodificate
        }
        
        try:
            # Usa la funzione di decodifica dalla libreria
            from snmpy import decode_snmp_hex
            
            # Decodifica il trap
            decoded = decode_snmp_hex(data.hex(), return_dict=True)
            
            if decoded and not decoded.get('error'):
                trap_info['decoded'] = decoded
                trap_info['type'] = f"SNMPv{decoded['version']} - {decoded.get('pdu_type', 'Unknown')}"
                
                # Se è un trap, aggiungi info sul tipo
                if 'trap_type' in decoded:
                    trap_info['trap_type'] = decoded['trap_type']
                    trap_info['type'] = f"SNMPv{decoded['version']} - {decoded['trap_type']}"
                
                # Estrai community
                if decoded.get('community'):
                    trap_info['community'] = decoded['community']
                    
        except Exception as e:
            self.logger.debug(f"Errore parsing trap avanzato: {e}")
            
        return trap_info
        
    def stop(self):
        """Ferma il receiver"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
                
    def get_traps(self, max_count=100):
        """Ottiene trap dalla coda"""
        traps = []
        while not self.trap_queue.empty() and len(traps) < max_count:
            try:
                traps.append(self.trap_queue.get_nowait())
            except queue.Empty:
                break
        return traps

class PerformanceMonitor:
    """Monitor performance con metriche"""
    
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
        """Registra una query"""
        now = time.time()
        
        # Aggiorna contatori
        self.current_stats['total_queries'] += 1
        if success:
            self.current_stats['successful_queries'] += 1
        else:
            self.current_stats['failed_queries'] += 1
            
        # Aggiorna tempi risposta
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
            
        # Aggiungi a metriche
        self.metrics['response_times'].append(response_time if response_time else 0)
        self.metrics['success_rate'].append(100 if success else 0)
        self.metrics['timestamps'].append(now)
        
        # Calcola QPS
        if len(self.metrics['timestamps']) > 1:
            time_window = self.metrics['timestamps'][-1] - self.metrics['timestamps'][0]
            if time_window > 0:
                qps = len(self.metrics['timestamps']) / time_window
                self.metrics['queries_per_second'].append(qps)
                
    def update_system_metrics(self):
        """Aggiorna metriche di sistema"""
        try:
            process = psutil.Process()
            self.metrics['memory_usage'].append(process.memory_info().rss / 1024 / 1024)
            self.metrics['cpu_usage'].append(process.cpu_percent())
        except:
            pass
            
    def get_summary(self):
        """Ottiene summary delle performance"""
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
    """Gestione operazioni batch su host multipli"""
    
    def __init__(self, logger, max_workers=5):
        self.logger = logger
        self.max_workers = max_workers
        self.results = {}
        self.progress_callback = None
        
    def scan_multiple_hosts(self, hosts, oid, snmp_config, progress_callback=None):
        """Scansiona OID su host multipli"""
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
                    self.logger.error(f"Errore scan {host}: {e}")
                    
                completed += 1
                if self.progress_callback:
                    self.progress_callback(completed, total)
                    
        return self.results
        
    def _scan_single_host(self, host, oid, config):
        """Scansiona singolo host"""
        try:
            # Crea client SNMP
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
                
            # Esegui query
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
                # Singolo OID o walk
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
                    # Get singolo
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
        """Formatta valore SNMP"""
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
        """Esporta risultati batch"""
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
    """Gestione profili di configurazione"""
    
    def __init__(self, profiles_file="snmp_profiles.json", credential_manager=None):
        self.profiles_file = profiles_file
        self.credential_manager = credential_manager
        self.profiles = self.load_profiles()
        
    def load_profiles(self):
        """Carica profili salvati"""
        try:
            if os.path.exists(self.profiles_file):
                with open(self.profiles_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
        
    def save_profiles(self):
        """Salva profili su file"""
        try:
            with open(self.profiles_file, 'w') as f:
                json.dump(self.profiles, f, indent=2)
            return True
        except Exception:
            return False
            
    def add_profile(self, name, config):
        """Aggiunge nuovo profilo"""
        # Cripta password se presenti
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
        """Ottiene profilo decriptato"""
        if name not in self.profiles:
            return None
            
        config = self.profiles[name].copy()
        
        # Decripta password
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
        """Elimina profilo"""
        if name in self.profiles:
            del self.profiles[name]
            self.save_profiles()
            return True
        return False
        
    def list_profiles(self):
        """Lista nomi profili"""
        return list(self.profiles.keys())

class SecureCredentialManager:
    """Gestisce il salvataggio sicuro delle credenziali"""

    def __init__(self, app_name="SNMPBrowser"):
        self.app_name = app_name
        self.key_file = f".{app_name}_key"
        self.cipher = self._get_or_create_cipher()

    def _get_or_create_cipher(self):
        """Ottiene o crea chiave di crittografia"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Proteggi il file su sistemi Unix
            if hasattr(os, 'chmod'):
                os.chmod(self.key_file, 0o600)

        return Fernet(key)

    def encrypt_password(self, password: str) -> str:
        """Cripta una password"""
        if not password:
            return ""
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted: str) -> str:
        """Decripta una password"""
        if not encrypted:
            return ""
        try:
            return self.cipher.decrypt(encrypted.encode()).decode()
        except:
            return ""

    def secure_delete(self, data: str):
        """Cancellazione sicura dalla memoria"""
        if data:
            # Sovrascrive la stringa in memoria
            data_len = len(data)
            random_data = secrets.token_bytes(data_len)
            # Forza garbage collection
            del data
            gc.collect()


class MemoryLimitedScanner:
    """Scanner con limite di memoria"""

    def __init__(self, max_results=10000, max_memory_mb=500):
        self.max_results = max_results
        self.max_memory_mb = max_memory_mb
        self.results_count = 0
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024

    def check_limits(self) -> Tuple[bool, str]:
        """Controlla limiti memoria e risultati"""
        # Check numero risultati
        if self.results_count >= self.max_results:
            return False, f"Limite risultati raggiunto ({self.max_results})"

        # Check memoria
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_used = current_memory - self.start_memory

        if memory_used > self.max_memory_mb:
            return False, f"Limite memoria raggiunto ({self.max_memory_mb}MB)"

        return True, ""

    def increment(self):
        """Incrementa contatore risultati"""
        self.results_count += 1


class SnmpBrowserGUI:
    """Interfaccia grafica SNMP Browser Production Ready Enhanced"""

    def __init__(self, root):
        self.root = root
        self.root.title("SNMP Browser")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 750)

        # Setup logging
        self.setup_logging()
        self.logger.info("=" * 60)
        self.logger.info("Avvio SNMP Browser")
        self.logger.info(f"Sistema: {sys.platform}, Python: {sys.version}")

        # Manager componenti
        self.credential_manager = SecureCredentialManager()
        self.profile_manager = ProfileManager(credential_manager=self.credential_manager)
        self.mib_parser = MibParser(self.logger)
        self.performance_monitor = PerformanceMonitor()
        self.batch_operations = BatchOperations(self.logger)
        self.trap_receiver = None
        
        # Variabili configurazione base
        self.host_var = tk.StringVar(value="192.168.1.1")
        self.community_var = tk.StringVar(value="public")
        self.port_var = tk.StringVar(value="161")
        self.version_var = tk.StringVar(value="2c")
        self.timeout_var = tk.StringVar(value="5.0")
        self.retries_var = tk.StringVar(value="3")
        self.current_profile_var = tk.StringVar(value="Default")

        # Variabili SNMPv3
        self.v3_user_var = tk.StringVar(value="")
        self.v3_auth_protocol_var = tk.StringVar(value="noAuth")
        self.v3_auth_password_var = tk.StringVar(value="")
        self.v3_priv_protocol_var = tk.StringVar(value="noPriv")
        self.v3_priv_password_var = tk.StringVar(value="")
        self.v3_show_passwords = tk.BooleanVar(value=False)
        self.v3_engine_id_var = tk.StringVar(value="")

        # Variabili di stato
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

        # Limiti memoria
        self.max_results_var = tk.StringVar(value="10000")
        self.max_memory_var = tk.StringVar(value="500")
        self.memory_scanner = None

        # File configurazione
        self.config_file = "snmp_browser_config.json"
        self.saved_values_file = "snmp_browser_saved.json"

        # Dizionario OID
        self.oid_names = self._build_oid_names_dictionary()

        # Crea interfaccia
        self.create_widgets()
        self.create_menu()

        # Carica configurazione
        self.load_config()
        self.load_saved_values()

        # Bind eventi
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.version_var.trace('w', self.on_version_change)

        # Monitor memoria e performance
        self.start_memory_monitor()
        self.update_performance_metrics()

        self.logger.info("Inizializzazione completata")

    def setup_logging(self):
        """Configura logging su file con rotazione"""
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Nome file con data
        log_file = os.path.join(log_dir, f"snmp_browser_{datetime.now().strftime('%Y%m%d')}.log")

        # Configura logger
        self.logger = logging.getLogger('SNMPBrowser')
        self.logger.setLevel(logging.DEBUG)

        # File handler con rotazione
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

        # Formato
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Aggiungi handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def send_trap(self):
        """Invia un trap SNMP"""
        try:
            from snmpy import SnmpTrapSender, SnmpVersion, SnmpV3User, SnmpV3AuthProtocol
            from snmpy import SnmpOctetString, SnmpInteger, SnmpObjectIdentifier
            
            # Ottieni parametri
            host = self.trap_dest_host_var.get()
            port = int(self.trap_dest_port_var.get())
            version_str = self.trap_version_var.get()
            community = self.trap_community_var.get()
            
            # Determina versione
            if version_str == "1":
                version = SnmpVersion.V1
            elif version_str == "3":
                version = SnmpVersion.V3
                messagebox.showwarning("SNMPv3", "SNMPv3 trap non ancora implementato in GUI")
                return
            else:
                version = SnmpVersion.V2C
            
            # Crea sender
            sender = SnmpTrapSender(
                trap_host=host,
                trap_port=port,
                community=community,
                version=version
            )
            
            # Invia in base al tipo
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
                        
                        # Determina tipo valore
                        if value.isdigit():
                            varbinds.append((oid, SnmpInteger(int(value))))
                        else:
                            varbinds.append((oid, SnmpOctetString(value)))
                
                custom_oid = self.trap_custom_oid_var.get()
                success = sender.send_v2c_trap(custom_oid, varbinds=varbinds)
            
            # Mostra risultato
            if success:
                self.trap_send_status.config(text=f"Trap inviato a {host}:{port}", foreground="green")
                self.logger.info(f"Trap {trap_type} inviato con successo a {host}:{port}")
                
                # Se il receiver è attivo sulla stessa porta, dovremmo vederlo
                if self.trap_receiver and self.trap_receiver.running and host == "localhost":
                    self.status_var.set(f"Trap {trap_type} inviato (controlla receiver)")
            else:
                self.trap_send_status.config(text="Errore invio trap", foreground="red")
                self.logger.error(f"Errore invio trap {trap_type}")
                
        except Exception as e:
            messagebox.showerror("Errore", f"Errore invio trap:\n{str(e)}")
            self.logger.error(f"Errore invio trap: {e}")

    def send_trap_loop(self):
        """Invia 5 trap di test con delay"""
        def send_loop():
            for i in range(5):
                self.trap_message_var.set(f"Test trap #{i+1} - {time.strftime('%H:%M:%S')}")
                self.send_trap()
                if i < 4:
                    time.sleep(2)
        
        # Esegui in thread separato
        threading.Thread(target=send_loop, daemon=True).start()

    def show_trap_templates(self):
        """Mostra template di trap predefiniti"""
        template_window = tk.Toplevel(self.root)
        template_window.title("Trap Templates")
        template_window.geometry("600x400")
        template_window.transient(self.root)
        
        # Lista template
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
                'params': {'message': 'Sistema operativo - Test periodico'}
            }
        ]
        
        # Lista
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
                
                # Applica template
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
        
        # Pulsanti
        btn_frame = ttk.Frame(template_window)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Applica", command=apply_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Chiudi", command=template_window.destroy).pack(side=tk.LEFT, padx=5)

    def start_memory_monitor(self):
        """Monitora l'uso della memoria"""

        def monitor():
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024

            # Avvisa se supera soglia
            if memory_mb > 800:
                self.logger.warning(f"Uso memoria elevato: {memory_mb:.1f}MB")
                self.root.after(0, lambda: self.status_var.set(
                    f"Memoria elevata: {memory_mb:.1f}MB"))

            # Ricontrolla ogni 30 secondi
            self.root.after(30000, monitor)

        # Avvia monitor
        self.root.after(5000, monitor)

    def update_performance_metrics(self):
        """Aggiorna metriche performance periodicamente"""
        self.performance_monitor.update_system_metrics()
        
        # Aggiorna display se tab performance è visibile
        if hasattr(self, 'performance_tab_active') and self.performance_tab_active:
            self.update_performance_display()
            
        # Richiama ogni 2 secondi
        self.root.after(2000, self.update_performance_metrics)

    def _build_oid_names_dictionary(self):
        """Costruisce dizionario OID esteso con SNMPv3 e UPS"""
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
        
        # Aggiungi definizioni MIB parser
        base_dict.update(self.mib_parser.mib_definitions)
        
        return base_dict

    def create_menu(self):
        """Crea menu principale con nuove opzioni"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Menu File
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Salva Configurazione", command=self.save_config, accelerator="Ctrl+S")
        file_menu.add_command(label="Carica Configurazione", command=self.load_config_dialog, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Gestione Profili", command=self.show_profile_manager)
        file_menu.add_separator()
        file_menu.add_command(label="Esporta Risultati", command=self.export_results, accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label="Visualizza Log", command=self.show_log_viewer)
        file_menu.add_separator()
        file_menu.add_command(label="Esci", command=self.on_closing, accelerator="Ctrl+Q")

        # Menu Tools
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Test Connessione", command=self.test_connection, accelerator="Ctrl+T")
        tools_menu.add_command(label="SNMP Walk Completo", command=self.full_walk)
        tools_menu.add_command(label="Operazioni Batch", command=self.show_batch_operations)
        tools_menu.add_separator()
        tools_menu.add_command(label="Trap Receiver", command=self.toggle_trap_receiver)
        tools_menu.add_command(label="Performance Monitor", command=self.show_performance_window)
        tools_menu.add_separator()
        tools_menu.add_command(label="Carica MIB", command=self.load_mib_file)
        tools_menu.add_command(label="Cerca in MIB", command=self.search_mib_definitions)
        tools_menu.add_separator()
        tools_menu.add_command(label="Decodifica Hex SNMP", command=self.show_hex_decoder)
        tools_menu.add_separator()
        tools_menu.add_command(label="Wizard SNMPv3", command=self.show_snmpv3_wizard)
        tools_menu.add_command(label="Scopri Engine ID", command=self.discover_engine_id)
        tools_menu.add_separator()
        tools_menu.add_command(label="Pulisci Cache", command=self.clear_cache)
        tools_menu.add_command(label="Impostazioni", command=self.show_settings)

        # Menu Help
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Guida", command=self.show_help, accelerator="F1")
        help_menu.add_command(label="Shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="Debug Info", command=self.show_debug_info)
        help_menu.add_separator()
        help_menu.add_command(label="Info", command=self.show_about)


    def show_hex_decoder(self):
        """Mostra dialog per decodifica hex manuale"""
        decoder_window = tk.Toplevel(self.root)
        decoder_window.title("SNMP Hex Decoder")
        decoder_window.geometry("900x700")
        decoder_window.transient(self.root)
        
        # Input
        input_frame = ttk.LabelFrame(decoder_window, text="Hex Input (incolla qui)")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        input_text = tk.Text(input_frame, height=8, font=('Courier', 10))
        input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Esempio
        input_text.insert(tk.END, "# Incolla qui l'hex del pacchetto SNMP\n")
        input_text.insert(tk.END, "# Esempio: 3081a202010104067075626c6963a78194...")
        
        # Output
        output_frame = ttk.LabelFrame(decoder_window, text="Risultato Decodifica")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        output_text = tk.Text(output_frame, height=15, font=('Courier', 10))
        output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def decode():
            from snmpy import decode_snmp_hex
            import io
            import sys
            
            # Ottieni hex
            hex_data = input_text.get(1.0, tk.END).strip()
            # Rimuovi commenti
            hex_data = '\n'.join(line for line in hex_data.split('\n') 
                                if not line.strip().startswith('#'))
            
            if not hex_data:
                messagebox.showwarning("Avviso", "Inserisci dati hex!")
                return
            
            # Cattura output
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            
            try:
                decode_snmp_hex(hex_data)
                output = buffer.getvalue()
            except Exception as e:
                output = f"Errore decodifica:\n{str(e)}"
            finally:
                sys.stdout = old_stdout
            
            # Mostra risultato
            output_text.config(state=tk.NORMAL)
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, output)
            output_text.config(state=tk.DISABLED)
        
        # Pulsanti
        btn_frame = ttk.Frame(decoder_window)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Decodifica", command=decode,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Pulisci", 
                command=lambda: input_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Chiudi", 
                command=decoder_window.destroy).pack(side=tk.LEFT, padx=5)

    def create_widgets(self):
        """Crea tutti i widget"""
        # Frame principale
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Frame configurazione
        self.create_config_frame(main_frame)

        # Notebook per visualizzazioni
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        # Tabs
        self.create_browser_tab()
        self.create_dashboard_tab()
        self.create_mib_tree_tab()
        self.create_trap_tab()
        self.create_performance_tab()

        # Frame stato
        self.create_status_frame(main_frame)

    def create_config_frame(self, parent):
        """Frame configurazione con profili"""
        config_frame = ttk.LabelFrame(parent, text="Configurazione SNMP")
        config_frame.pack(fill=tk.X, pady=(0, 5))

        # Prima riga - Profili
        profile_row = ttk.Frame(config_frame)
        profile_row.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(profile_row, text="Profilo:").pack(side=tk.LEFT)
        self.profile_combo = ttk.Combobox(profile_row, textvariable=self.current_profile_var,
                                          width=15, state='readonly')
        self.profile_combo.pack(side=tk.LEFT, padx=(5, 10))
        self.profile_combo.bind('<<ComboboxSelected>>', self.on_profile_selected)
        
        ttk.Button(profile_row, text="Salva", command=self.save_current_profile).pack(side=tk.LEFT, padx=2)
        ttk.Button(profile_row, text="Gestisci", command=self.show_profile_manager).pack(side=tk.LEFT, padx=2)
        
        self.update_profile_list()

        # Seconda riga
        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(row1, text="Host:").pack(side=tk.LEFT)
        self.host_entry = ttk.Entry(row1, textvariable=self.host_var, width=15)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(row1, text="Porta:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(row1, textvariable=self.port_var, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(row1, text="Versione:").pack(side=tk.LEFT)
        version_combo = ttk.Combobox(row1, textvariable=self.version_var, width=5,
                                     values=["1", "2c", "3"], state='readonly')
        version_combo.pack(side=tk.LEFT, padx=(5, 10))

        # Community per v1/v2c
        self.v1v2_frame = ttk.Frame(row1)
        self.v1v2_frame.pack(side=tk.LEFT, padx=(10, 0))

        ttk.Label(self.v1v2_frame, text="Community:").pack(side=tk.LEFT)
        ttk.Entry(self.v1v2_frame, textvariable=self.community_var, width=10).pack(side=tk.LEFT, padx=(5, 10))

        # Terza riga
        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(row2, text="Timeout:").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.timeout_var, width=6).pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(row2, text="Retry:").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.retries_var, width=6).pack(side=tk.LEFT, padx=(5, 10))

        ttk.Checkbutton(row2, text="Scansione Estesa",
                        variable=self.extended_scan_var).pack(side=tk.LEFT, padx=(20, 10))

        # Pulsanti
        btn_frame = ttk.Frame(row2)
        btn_frame.pack(side=tk.RIGHT, padx=5)

        self.scan_btn = ttk.Button(btn_frame, text="Avvia Scansione", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=2)

        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(btn_frame, text="Test", command=self.test_connection).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Batch", command=self.show_batch_operations).pack(side=tk.LEFT, padx=2)

        # Frame SNMPv3
        self.v3_frame = ttk.LabelFrame(config_frame, text="Configurazione SNMPv3")

        # Prima riga v3
        v3_row1 = ttk.Frame(self.v3_frame)
        v3_row1.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(v3_row1, text="Username:").pack(side=tk.LEFT)
        ttk.Entry(v3_row1, textvariable=self.v3_user_var, width=15).pack(side=tk.LEFT, padx=(5, 10))

        ttk.Label(v3_row1, text="Auth:").pack(side=tk.LEFT)
        auth_combo = ttk.Combobox(v3_row1, textvariable=self.v3_auth_protocol_var, width=10,
                                  values=["noAuth", "MD5", "SHA", "SHA256", "SHA384", "SHA512"])
        auth_combo.pack(side=tk.LEFT, padx=(5, 10))
        auth_combo.state(['readonly'])

        ttk.Label(v3_row1, text="Auth Pass:").pack(side=tk.LEFT)
        self.auth_pass_entry = ttk.Entry(v3_row1, textvariable=self.v3_auth_password_var,
                                         width=15, show="*")
        self.auth_pass_entry.pack(side=tk.LEFT, padx=(5, 10))

        # Seconda riga v3
        v3_row2 = ttk.Frame(self.v3_frame)
        v3_row2.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(v3_row2, text="Priv:").pack(side=tk.LEFT)
        priv_combo = ttk.Combobox(v3_row2, textvariable=self.v3_priv_protocol_var, width=10,
                                  values=["noPriv", "DES", "AES128", "AES192", "AES256"])
        priv_combo.pack(side=tk.LEFT, padx=(5, 10))
        priv_combo.state(['readonly'])

        ttk.Label(v3_row2, text="Priv Pass:").pack(side=tk.LEFT)
        self.priv_pass_entry = ttk.Entry(v3_row2, textvariable=self.v3_priv_password_var,
                                         width=15, show="*")
        self.priv_pass_entry.pack(side=tk.LEFT, padx=(5, 10))

        ttk.Checkbutton(v3_row2, text="Mostra",
                        variable=self.v3_show_passwords,
                        command=self.toggle_password_visibility).pack(side=tk.LEFT, padx=(10, 5))

        ttk.Button(v3_row2, text="Engine ID",
                   command=self.discover_engine_id).pack(side=tk.LEFT, padx=5)

        ttk.Button(v3_row2, text="Test v3",
                   command=self.test_snmpv3_connection).pack(side=tk.LEFT, padx=5)

    def create_trap_tab(self):
        """Tab per trap receiver E SENDER"""
        trap_frame = ttk.Frame(self.notebook)
        self.notebook.add(trap_frame, text="Trap Manager")
        
        # Notebook interno per Receiver e Sender
        trap_notebook = ttk.Notebook(trap_frame)
        trap_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # === TAB RECEIVER ===
        receiver_frame = ttk.Frame(trap_notebook)
        trap_notebook.add(receiver_frame, text="Trap Receiver")
        
        # Controlli Receiver (codice esistente)
        control_frame = ttk.LabelFrame(receiver_frame, text="Controlli Trap Receiver")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        controls = ttk.Frame(control_frame)
        controls.pack(padx=10, pady=10)
        
        self.trap_status_label = ttk.Label(controls, text="Status: Inattivo")
        self.trap_status_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.trap_toggle_btn = ttk.Button(controls, text="Avvia Receiver",
                                        command=self.toggle_trap_receiver)
        self.trap_toggle_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls, text="Pulisci", command=self.clear_traps).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Esporta", command=self.export_traps).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls, text="Porta:").pack(side=tk.LEFT, padx=(20, 5))
        self.trap_port_var = tk.StringVar(value="162")
        ttk.Entry(controls, textvariable=self.trap_port_var, width=6).pack(side=tk.LEFT)
        
        # TreeView per trap ricevuti
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
        info_frame = ttk.LabelFrame(receiver_frame, text="Statistiche")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.trap_stats_label = ttk.Label(info_frame, text="Trap ricevuti: 0")
        self.trap_stats_label.pack(padx=10, pady=5)
        
        # === TAB SENDER ===
        sender_frame = ttk.Frame(trap_notebook)
        trap_notebook.add(sender_frame, text="Trap Sender")
        
        # Configurazione destinazione
        dest_frame = ttk.LabelFrame(sender_frame, text="Destinazione Trap")
        dest_frame.pack(fill=tk.X, padx=5, pady=5)
        
        dest_controls = ttk.Frame(dest_frame)
        dest_controls.pack(padx=10, pady=10)
        
        ttk.Label(dest_controls, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.trap_dest_host_var = tk.StringVar(value="localhost")
        ttk.Entry(dest_controls, textvariable=self.trap_dest_host_var, width=20).grid(row=0, column=1, padx=5)
        
        ttk.Label(dest_controls, text="Porta:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.trap_dest_port_var = tk.StringVar(value="162")
        ttk.Entry(dest_controls, textvariable=self.trap_dest_port_var, width=8).grid(row=0, column=3, padx=5)
        
        ttk.Label(dest_controls, text="Versione:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.trap_version_var = tk.StringVar(value="2c")
        ttk.Combobox(dest_controls, textvariable=self.trap_version_var, 
                    values=["1", "2c", "3"], state='readonly', width=5).grid(row=1, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(dest_controls, text="Community:").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.trap_community_var = tk.StringVar(value="public")
        ttk.Entry(dest_controls, textvariable=self.trap_community_var, width=15).grid(row=1, column=3, padx=5)
        
        # Tipo di trap
        trap_type_frame = ttk.LabelFrame(sender_frame, text="Tipo di Trap")
        trap_type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        trap_type_controls = ttk.Frame(trap_type_frame)
        trap_type_controls.pack(padx=10, pady=10)
        
        # Radio buttons per tipo trap
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
        
        # Frame per parametri specifici
        params_frame = ttk.LabelFrame(sender_frame, text="Parametri Trap")
        params_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Notebook per diversi tipi di parametri
        self.params_notebook = ttk.Notebook(params_frame)
        self.params_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab parametri test
        test_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(test_params, text="Test/Generic")
        
        ttk.Label(test_params, text="Messaggio:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_message_var = tk.StringVar(value="Test trap from SNMP Browser")
        ttk.Entry(test_params, textvariable=self.trap_message_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        
        # Tab parametri interfaccia
        if_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(if_params, text="Interface")
        
        ttk.Label(if_params, text="Interface Index:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_if_index_var = tk.StringVar(value="1")
        ttk.Entry(if_params, textvariable=self.trap_if_index_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(if_params, text="Interface Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_if_name_var = tk.StringVar(value="eth0")
        ttk.Entry(if_params, textvariable=self.trap_if_name_var, width=30).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Tab parametri UPS
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
        
        # Tab custom OID
        custom_params = ttk.Frame(self.params_notebook)
        self.params_notebook.add(custom_params, text="Custom")
        
        ttk.Label(custom_params, text="Trap OID:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.trap_custom_oid_var = tk.StringVar(value="1.3.6.1.4.1.99999.1.1")
        ttk.Entry(custom_params, textvariable=self.trap_custom_oid_var, width=40).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(custom_params, text="Varbinds (OID=Value):").grid(row=1, column=0, sticky=tk.NW, padx=5, pady=5)
        self.trap_varbinds_text = tk.Text(custom_params, height=6, width=50)
        self.trap_varbinds_text.grid(row=1, column=1, padx=5, pady=5)
        self.trap_varbinds_text.insert(tk.END, "1.3.6.1.4.1.99999.1.2=Test Value\n1.3.6.1.4.1.99999.1.3=123")
        
        # Pulsanti invio
        send_frame = ttk.Frame(sender_frame)
        send_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(send_frame, text="Invia Trap", command=self.send_trap,
                style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(send_frame, text="Test Loop (5x)", command=self.send_trap_loop).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(send_frame, text="Templates", command=self.show_trap_templates).pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.trap_send_status = ttk.Label(send_frame, text="")
        self.trap_send_status.pack(side=tk.LEFT, padx=20)

    def create_performance_tab(self):
        """Tab per performance metrics"""
        perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(perf_frame, text="Performance")
        
        # Controlli
        control_frame = ttk.LabelFrame(perf_frame, text="Controlli Performance")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        controls = ttk.Frame(control_frame)
        controls.pack(padx=10, pady=10)
        
        ttk.Button(controls, text="Aggiorna", command=self.update_performance_display).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Reset", command=self.reset_performance_metrics).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Esporta", command=self.export_performance_data).pack(side=tk.LEFT, padx=5)
        
        # Frame metriche
        metrics_frame = ttk.LabelFrame(perf_frame, text="Metriche Correnti")
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.metrics_text = tk.Text(metrics_frame, height=8, width=80)
        self.metrics_text.pack(padx=10, pady=10)
        
        # Frame grafico (se matplotlib disponibile)
        if HAS_MATPLOTLIB:
            graph_frame = ttk.LabelFrame(perf_frame, text="Grafici Performance")
            graph_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Crea figura matplotlib
            self.perf_figure = Figure(figsize=(12, 6), dpi=80)
            self.perf_canvas = FigureCanvasTkAgg(self.perf_figure, master=graph_frame)
            self.perf_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Bind tab change
            self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    def toggle_trap_receiver(self):
        """Attiva/disattiva trap receiver"""
        if self.trap_receiver and self.trap_receiver.running:
            # Ferma receiver
            self.trap_receiver.stop()
            self.trap_receiver = None
            self.trap_status_label.config(text="Status: Inattivo")
            self.trap_toggle_btn.config(text="Avvia Receiver")
            self.logger.info("Trap receiver fermato")
        else:
            # Avvia receiver
            try:
                port = int(self.trap_port_var.get())
                
                # Check permessi porta
                if port < 1024 and not self.check_admin_privileges():
                    messagebox.showwarning("Permessi",
                                         "Porta < 1024 richiede privilegi amministratore.\n"
                                         "Usa una porta >= 1024 o avvia come admin.")
                    return
                    
                self.trap_receiver = TrapReceiver(
                    port=port,
                    callback=self.on_trap_received,
                    logger=self.logger
                )
                self.trap_receiver.start()
                
                self.trap_status_label.config(text=f"Status: Attivo (porta {port})")
                self.trap_toggle_btn.config(text="Ferma Receiver")
                self.logger.info(f"Trap receiver avviato su porta {port}")
                
                # Avvia update periodico
                self.update_trap_display()
                
            except Exception as e:
                messagebox.showerror("Errore", f"Impossibile avviare trap receiver:\n{str(e)}")
                self.logger.error(f"Errore avvio trap receiver: {e}")

    def check_admin_privileges(self):
        """Verifica privilegi amministratore"""
        try:
            if sys.platform.startswith('win'):
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def on_trap_received(self, trap_info):
        """Callback quando trap ricevuto"""
        self.received_traps.append(trap_info)
        # Aggiorna contatore
        self.root.after(0, lambda: self.trap_stats_label.config(
            text=f"Trap ricevuti: {len(self.received_traps)}"))

    def update_trap_display(self):
        """Aggiorna display trap"""
        if self.trap_receiver and self.trap_receiver.running:
            # Ottieni nuovi trap
            new_traps = self.trap_receiver.get_traps()
            
            for trap in new_traps:
                # Aggiungi al tree
                self.trap_tree.insert("", 0, values=(
                    trap['timestamp'],
                    trap['source'],
                    trap['type'],
                    f"{trap['size']} bytes",
                    trap['raw_data'][:50] + "..." if len(trap['raw_data']) > 50 else trap['raw_data']
                ))
                
            # Limita numero di trap visualizzati
            children = self.trap_tree.get_children()
            if len(children) > 1000:
                for item in children[1000:]:
                    self.trap_tree.delete(item)
                    
            # Richiama dopo 1 secondo
            self.root.after(1000, self.update_trap_display)

    def on_trap_double_click(self, event):
        """Doppio click su trap per dettagli MIGLIORATO"""
        selection = self.trap_tree.selection()
        if selection:
            item = selection[0]
            values = self.trap_tree.item(item)['values']
            
            # Trova il trap nei dati ricevuti
            trap_data = None
            for trap in self.received_traps:
                if trap['timestamp'] == values[0] and trap['source'] == values[1]:
                    trap_data = trap
                    break
            
            if not trap_data:
                # Fallback ai valori del tree
                trap_data = {
                    'timestamp': values[0],
                    'source': values[1],
                    'type': values[2],
                    'size': values[3],
                    'raw_data': values[4] if len(values) > 4 else ""
                }
            
            # Mostra dettagli trap
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Dettagli Trap - Decodificato")
            detail_window.geometry("800x600")
            detail_window.transient(self.root)
            
            # Notebook per diverse viste
            notebook = ttk.Notebook(detail_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Tab Info Base
            info_frame = ttk.Frame(notebook)
            notebook.add(info_frame, text="Info Base")
            
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
            
            # Tab Varbinds Decodificati
            if trap_data.get('decoded') and trap_data['decoded'].get('varbinds'):
                varbind_frame = ttk.Frame(notebook)
                notebook.add(varbind_frame, text="Varbinds")
                
                # TreeView per varbinds
                columns = ("OID", "Name", "Type", "Value")
                vb_tree = ttk.Treeview(varbind_frame, columns=columns, show="headings", height=10)
                
                for col in columns:
                    vb_tree.heading(col, text=col)
                    vb_tree.column(col, width=150)
                
                # Popola varbinds
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
            
            # Tab Raw Hex
            hex_frame = ttk.Frame(notebook)
            notebook.add(hex_frame, text="Raw Hex")
            
            hex_text = tk.Text(hex_frame, wrap=tk.WORD, font=('Courier', 10))
            hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Formatta hex in righe
            raw_hex = trap_data.get('raw_data', '')
            formatted_hex = ""
            for i in range(0, len(raw_hex), 32):
                line = raw_hex[i:i+32]
                # Aggiungi spazi ogni 2 caratteri
                spaced = ' '.join(line[j:j+2] for j in range(0, len(line), 2))
                formatted_hex += f"{i//2:04x}: {spaced}\n"
            
            hex_text.insert(tk.END, formatted_hex)
            hex_text.config(state=tk.DISABLED)
            
            # Tab Decodifica Completa
            decode_frame = ttk.Frame(notebook)
            notebook.add(decode_frame, text="Decodifica")
            
            decode_text = tk.Text(decode_frame, wrap=tk.WORD, font=('Courier', 10))
            decode_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Decodifica on-demand
            def decode_full():
                from snmpy import decode_snmp_hex
                import io
                import sys
                
                # Cattura output
                old_stdout = sys.stdout
                sys.stdout = buffer = io.StringIO()
                
                decode_snmp_hex(raw_hex)
                
                output = buffer.getvalue()
                sys.stdout = old_stdout
                
                decode_text.config(state=tk.NORMAL)
                decode_text.delete(1.0, tk.END)
                decode_text.insert(tk.END, output)
                decode_text.config(state=tk.DISABLED)
            
            ttk.Button(decode_frame, text="Decodifica Dettagliata", 
                    command=decode_full).pack(pady=5)
            
            # Pulsanti
            btn_frame = ttk.Frame(detail_window)
            btn_frame.pack(pady=10)
            
            def copy_hex():
                self.root.clipboard_clear()
                self.root.clipboard_append(raw_hex)
                messagebox.showinfo("Copiato", "Hex copiato negli appunti!")
            
            def save_trap():
                filename = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON", "*.json"), ("Text", "*.txt")],
                    initialfile=f"trap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )
                if filename:
                    with open(filename, 'w') as f:
                        json.dump(trap_data, f, indent=2, default=str)
                    messagebox.showinfo("Salvato", f"Trap salvato in {filename}")
            
            ttk.Button(btn_frame, text="Copia Hex", command=copy_hex).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Salva", command=save_trap).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Chiudi", command=detail_window.destroy).pack(side=tk.LEFT, padx=5)

    def clear_traps(self):
        """Pulisce trap ricevuti"""
        if messagebox.askyesno("Conferma", "Pulire tutti i trap ricevuti?"):
            self.received_traps.clear()
            for item in self.trap_tree.get_children():
                self.trap_tree.delete(item)
            self.trap_stats_label.config(text="Trap ricevuti: 0")

    def export_traps(self):
        """Esporta trap ricevuti"""
        if not self.received_traps:
            messagebox.showwarning("Avviso", "Nessun trap da esportare")
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
                            
                messagebox.showinfo("Export", f"Trap esportati: {filename}")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore export: {str(e)}")

    def on_tab_changed(self, event):
        """Gestisce cambio tab"""
        selected = self.notebook.select()
        tab_text = self.notebook.tab(selected, "text")
        
        # Attiva/disattiva aggiornamento performance
        self.performance_tab_active = (tab_text == "Performance")
        
        if self.performance_tab_active:
            self.update_performance_display()

    def update_performance_display(self):
        """Aggiorna display performance"""
        try:
            # Ottieni metriche
            summary = self.performance_monitor.get_summary()
            
            # Aggiorna testo
            self.metrics_text.delete(1.0, tk.END)
            
            text = f"""
Query Totali: {summary['total_queries']}
Success Rate: {summary['success_rate']}
Query/Secondo: {summary['current_qps']}

Tempo Risposta Medio: {summary['avg_response_time']}
Tempo Risposta Min: {summary['min_response_time']}
Tempo Risposta Max: {summary['max_response_time']}

Memoria Usata: {summary['memory_mb']} MB
CPU Usage: {summary['cpu_percent']}%
"""
            self.metrics_text.insert(tk.END, text)
            
            # Aggiorna grafici se disponibili
            if HAS_MATPLOTLIB and hasattr(self, 'perf_figure'):
                self.update_performance_graphs()
                
        except Exception as e:
            self.logger.error(f"Errore aggiornamento performance: {e}")

    def update_performance_graphs(self):
        """Aggiorna grafici performance"""
        try:
            self.perf_figure.clear()
            
            # Crea subplot
            ax1 = self.perf_figure.add_subplot(2, 2, 1)
            ax2 = self.perf_figure.add_subplot(2, 2, 2)
            ax3 = self.perf_figure.add_subplot(2, 2, 3)
            ax4 = self.perf_figure.add_subplot(2, 2, 4)
            
            # Grafico response time
            if self.performance_monitor.metrics['response_times']:
                ax1.plot(list(self.performance_monitor.metrics['response_times']))
                ax1.set_title('Tempo Risposta (s)')
                ax1.set_xlabel('Query')
                ax1.grid(True)
                
            # Grafico success rate
            if self.performance_monitor.metrics['success_rate']:
                ax2.plot(list(self.performance_monitor.metrics['success_rate']))
                ax2.set_title('Success Rate (%)')
                ax2.set_xlabel('Query')
                ax2.set_ylim([0, 105])
                ax2.grid(True)
                
            # Grafico memoria
            if self.performance_monitor.metrics['memory_usage']:
                ax3.plot(list(self.performance_monitor.metrics['memory_usage']))
                ax3.set_title('Memoria (MB)')
                ax3.set_xlabel('Tempo')
                ax3.grid(True)
                
            # Grafico QPS
            if self.performance_monitor.metrics['queries_per_second']:
                ax4.plot(list(self.performance_monitor.metrics['queries_per_second']))
                ax4.set_title('Query/Secondo')
                ax4.set_xlabel('Tempo')
                ax4.grid(True)
                
            self.perf_figure.tight_layout()
            self.perf_canvas.draw()
            
        except Exception as e:
            self.logger.error(f"Errore aggiornamento grafici: {e}")

    def reset_performance_metrics(self):
        """Reset metriche performance"""
        if messagebox.askyesno("Conferma", "Resettare tutte le metriche?"):
            self.performance_monitor = PerformanceMonitor()
            self.update_performance_display()

    def export_performance_data(self):
        """Esporta dati performance"""
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
                            
                messagebox.showinfo("Export", f"Performance data esportato: {filename}")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore export: {str(e)}")

    def show_batch_operations(self):
        """Mostra dialog operazioni batch"""
        batch_window = tk.Toplevel(self.root)
        batch_window.title("Operazioni Batch")
        batch_window.geometry("700x500")
        batch_window.transient(self.root)
        
        # Frame hosts
        hosts_frame = ttk.LabelFrame(batch_window, text="Lista Host (uno per riga)")
        hosts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        hosts_text = tk.Text(hosts_frame, height=10)
        hosts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Esempio
        hosts_text.insert(tk.END, "192.168.1.1\n192.168.1.2\n192.168.1.3")
        
        # Frame OID
        oid_frame = ttk.LabelFrame(batch_window, text="OID da Interrogare")
        oid_frame.pack(fill=tk.X, padx=10, pady=5)
        
        oid_var = tk.StringVar(value="1.3.6.1.2.1.1.1.0")
        ttk.Entry(oid_frame, textvariable=oid_var, width=50).pack(padx=5, pady=5)
        
        # Frame opzioni
        options_frame = ttk.LabelFrame(batch_window, text="Opzioni")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        opts = ttk.Frame(options_frame)
        opts.pack(padx=5, pady=5)
        
        ttk.Label(opts, text="Max Workers:").grid(row=0, column=0, sticky=tk.W)
        workers_var = tk.StringVar(value="5")
        ttk.Spinbox(opts, from_=1, to=20, textvariable=workers_var, width=10).grid(row=0, column=1, padx=5)
        
        walk_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="WALK (usa * alla fine dell'OID)",
                       variable=walk_var).grid(row=1, column=0, columnspan=2, pady=5)
        
        # Progress
        self.batch_progress = ttk.Progressbar(batch_window, mode='determinate')
        self.batch_progress.pack(fill=tk.X, padx=10, pady=5)
        
        self.batch_status = tk.StringVar(value="Pronto")
        ttk.Label(batch_window, textvariable=self.batch_status).pack()
        
        # Pulsanti
        btn_frame = ttk.Frame(batch_window)
        btn_frame.pack(pady=10)
        
        def run_batch():
            # Ottieni hosts
            hosts = [h.strip() for h in hosts_text.get(1.0, tk.END).split('\n') if h.strip()]
            
            if not hosts:
                messagebox.showwarning("Avviso", "Inserisci almeno un host")
                return
                
            # Prepara OID
            oid = oid_var.get()
            if walk_var.get() and not oid.endswith('*'):
                oid += '*'
                
            # Prepara config SNMP
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
                self.batch_status.set(f"Completati {completed}/{total} hosts")
                batch_window.update()
                
            # Esegui batch
            self.batch_status.set("Esecuzione batch...")
            self.batch_operations.max_workers = int(workers_var.get())
            
            results = self.batch_operations.scan_multiple_hosts(
                hosts, oid, snmp_config, progress_callback)
                
            # Mostra risultati
            self.show_batch_results(results)
            batch_window.destroy()
            
        ttk.Button(btn_frame, text="Esegui", command=run_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Annulla", command=batch_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_batch_results(self, results):
        """Mostra risultati operazioni batch"""
        results_window = tk.Toplevel(self.root)
        results_window.title("Risultati Batch")
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
            
        # Popola risultati
        for host, data in results.items():
            if data.get('success'):
                if 'results' in data:
                    # Multi risultati (walk)
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
        
        # Pulsanti
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
                messagebox.showinfo("Export", f"Risultati esportati: {filename}")
                
        ttk.Button(btn_frame, text="Esporta", command=export_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="OK", command=results_window.destroy).pack(side=tk.LEFT, padx=5)

    def load_mib_file(self):
        """Carica file MIB"""
        filename = filedialog.askopenfilename(
            title="Carica File MIB",
            filetypes=[
                ("MIB Files", "*.mib"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            if self.mib_parser.load_mib_file(filename):
                # Aggiorna dizionario OID
                self.oid_names.update(self.mib_parser.mib_definitions)
                messagebox.showinfo("MIB Caricato",
                                   f"File MIB caricato con successo!\n"
                                   f"Definizioni totali: {len(self.mib_parser.mib_definitions)}")
            else:
                messagebox.showerror("Errore", "Errore caricamento file MIB")

    def search_mib_definitions(self):
        """Cerca nelle definizioni MIB"""
        search_term = simpledialog.askstring("Cerca MIB", "Inserisci termine di ricerca:")
        
        if search_term:
            results = self.mib_parser.search_name(search_term)
            
            if results:
                # Mostra risultati
                result_window = tk.Toplevel(self.root)
                result_window.title(f"Risultati ricerca: {search_term}")
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
                messagebox.showinfo("Ricerca", "Nessun risultato trovato")

    def show_profile_manager(self):
        """Mostra gestore profili"""
        profile_window = tk.Toplevel(self.root)
        profile_window.title("Gestione Profili")
        profile_window.geometry("500x400")
        profile_window.transient(self.root)
        
        # Lista profili
        list_frame = ttk.LabelFrame(profile_window, text="Profili Salvati")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        listbox = tk.Listbox(list_frame)
        listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Popola lista
        for profile_name in self.profile_manager.list_profiles():
            listbox.insert(tk.END, profile_name)
            
        # Pulsanti
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
                if messagebox.askyesno("Conferma", f"Eliminare profilo '{profile_name}'?"):
                    self.profile_manager.delete_profile(profile_name)
                    listbox.delete(selection[0])
                    self.update_profile_list()
                    
        def rename_profile():
            selection = listbox.curselection()
            if selection:
                old_name = listbox.get(selection[0])
                new_name = simpledialog.askstring("Rinomina", "Nuovo nome:",
                                                 initialvalue=old_name)
                if new_name and new_name != old_name:
                    config = self.profile_manager.get_profile(old_name)
                    self.profile_manager.add_profile(new_name, config)
                    self.profile_manager.delete_profile(old_name)
                    listbox.delete(selection[0])
                    listbox.insert(selection[0], new_name)
                    self.update_profile_list()
                    
        ttk.Button(btn_frame, text="Carica", command=load_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Elimina", command=delete_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Rinomina", command=rename_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Chiudi", command=profile_window.destroy).pack(side=tk.LEFT, padx=5)

    def save_current_profile(self):
        """Salva configurazione corrente come profilo"""
        profile_name = simpledialog.askstring("Salva Profilo", "Nome profilo:")
        
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
            
            messagebox.showinfo("Profilo Salvato", f"Profilo '{profile_name}' salvato con successo")

    def load_profile(self, profile_name):
        """Carica profilo"""
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
            self.logger.info(f"Profilo '{profile_name}' caricato")

    def on_profile_selected(self, event):
        """Gestisce selezione profilo dal combo"""
        profile_name = self.current_profile_var.get()
        if profile_name and profile_name != "Default":
            self.load_profile(profile_name)

    def update_profile_list(self):
        """Aggiorna lista profili nel combo"""
        profiles = ["Default"] + self.profile_manager.list_profiles()
        self.profile_combo['values'] = profiles

    def show_performance_window(self):
        """Mostra finestra performance dedicata"""
        perf_window = tk.Toplevel(self.root)
        perf_window.title("Performance Monitor")
        perf_window.geometry("900x600")
        perf_window.transient(self.root)
        
        # Seleziona tab performance
        for i in range(self.notebook.index("end")):
            if self.notebook.tab(i, "text") == "Performance":
                self.notebook.select(i)
                break
    
    def create_browser_tab(self):
        """Tab Browser principale"""
        browser_frame = ttk.Frame(self.notebook)
        self.notebook.add(browser_frame, text="Browser SNMP")

        # Filtri
        filter_frame = ttk.LabelFrame(browser_frame, text="Filtri")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(filter_frame, text="Cerca:").pack(side=tk.LEFT, padx=5)
        self.filter_var.trace('w', self.apply_filter)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(filter_frame, text="Pulisci", command=self.clear_filter).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(filter_frame, text="Solo Errori",
                        variable=self.show_errors_var,
                        command=self.apply_filter).pack(side=tk.LEFT, padx=(20, 5))

        # Risultati
        results_frame = ttk.Frame(browser_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("OID", "Nome", "Tipo", "Valore", "Stato", "Timestamp")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)

        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)

        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Azioni
        action_frame = ttk.Frame(browser_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Dashboard", command=self.add_to_dashboard).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="GET", command=self.get_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="SET", command=self.set_value).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="WALK", command=self.walk_from_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Export", command=self.export_results).pack(side=tk.LEFT, padx=2)

        # Bind eventi
        self.results_tree.bind("<Double-1>", self.on_result_double_click)
        self.results_tree.bind("<Button-3>", self.show_context_menu)

    def create_dashboard_tab(self):
        """Tab Dashboard"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Controlli
        control_frame = ttk.LabelFrame(dashboard_frame, text="Controlli Dashboard")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(control_frame, text="Aggiorna", command=self.refresh_dashboard).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Rimuovi", command=self.remove_from_dashboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Pulisci", command=self.clear_dashboard).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(control_frame, text="Auto-Refresh (30s)",
                        variable=self.auto_refresh_var,
                        command=self.toggle_auto_refresh).pack(side=tk.LEFT, padx=(20, 5))

        # TreeView
        dash_frame = ttk.Frame(dashboard_frame)
        dash_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        dash_columns = ("Host", "OID", "Nome", "Valore", "Timestamp", "Stato")
        self.dashboard_tree = ttk.Treeview(dash_frame, columns=dash_columns, show="headings", height=15)

        for col in dash_columns:
            self.dashboard_tree.heading(col, text=col)
            self.dashboard_tree.column(col, width=120)

        dash_scroll = ttk.Scrollbar(dash_frame, orient=tk.VERTICAL, command=self.dashboard_tree.yview)
        self.dashboard_tree.configure(yscrollcommand=dash_scroll.set)

        self.dashboard_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dash_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def create_mib_tree_tab(self):
        """Tab Albero MIB con colonna valore"""
        mib_frame = ttk.Frame(self.notebook)
        self.notebook.add(mib_frame, text="Albero MIB")

        # Controlli
        control_frame = ttk.LabelFrame(mib_frame, text="Controlli Albero MIB")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(control_frame, text="Costruisci", command=self.build_mib_tree).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Espandi", command=self.expand_all_mib).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Comprimi", command=self.collapse_all_mib).pack(side=tk.LEFT, padx=5)

        # TreeView con colonna valore aggiunta
        tree_frame = ttk.Frame(mib_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.mib_tree = ttk.Treeview(tree_frame, columns=("oid", "value", "type", "status"), height=20)
        self.mib_tree.heading("#0", text="Nome MIB")
        self.mib_tree.heading("oid", text="OID")
        self.mib_tree.heading("value", text="Valore")
        self.mib_tree.heading("type", text="Tipo")
        self.mib_tree.heading("status", text="Stato")

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
        """Frame di stato con info memoria"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(5, 0))

        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=(0, 10))

        self.status_var = tk.StringVar(value="Pronto")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

        # Info memoria
        self.memory_var = tk.StringVar(value="")
        ttk.Label(status_frame, textvariable=self.memory_var).pack(side=tk.LEFT, padx=(20, 0))

        self.info_var = tk.StringVar(value="")
        ttk.Label(status_frame, textvariable=self.info_var).pack(side=tk.RIGHT, padx=(0, 10))

        self.time_var = tk.StringVar()
        ttk.Label(status_frame, textvariable=self.time_var).pack(side=tk.RIGHT)
        self.update_time()

    def update_time(self):
        """Aggiorna ora e memoria"""
        self.time_var.set(time.strftime("%H:%M:%S"))

        # Aggiorna info memoria
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        self.memory_var.set(f"{memory_mb:.1f}MB")

        self.root.after(1000, self.update_time)

    def on_version_change(self, *args):
        """Gestisce cambio versione SNMP"""
        version = self.version_var.get()

        if version == "3":
            self.v1v2_frame.pack_forget()
            self.v3_frame.pack(fill=tk.X, padx=5, pady=5)
            self.logger.info("Passaggio a SNMPv3")
        else:
            if not self.v1v2_frame.winfo_viewable():
                self.v1v2_frame.pack(side=tk.LEFT, padx=(10, 0))
            self.v3_frame.pack_forget()
            self.logger.info(f"Passaggio a SNMPv{version}")

    def toggle_password_visibility(self):
        """Mostra/nasconde password v3"""
        show = "" if self.v3_show_passwords.get() else "*"
        self.auth_pass_entry.config(show=show)
        self.priv_pass_entry.config(show=show)

    def validate_input(self) -> Tuple[bool, str]:
        """Validazione completa input"""
        try:
            # Host
            host = self.host_var.get().strip()
            if not host:
                return False, "Host non può essere vuoto!"

            # Porta
            port = int(self.port_var.get())
            if port < 1 or port > 65535:
                return False, "Porta deve essere tra 1 e 65535!"

            # Timeout
            timeout = float(self.timeout_var.get())
            if timeout < 0.1 or timeout > 60:
                return False, "Timeout deve essere tra 0.1 e 60 secondi!"

            # Retries
            retries = int(self.retries_var.get())
            if retries < 0 or retries > 10:
                return False, "Retries deve essere tra 0 e 10!"

            # SNMPv3
            if self.version_var.get() == "3":
                if not self.v3_user_var.get().strip():
                    return False, "Username SNMPv3 richiesto!"

                if self.v3_auth_protocol_var.get() != "noAuth":
                    if len(self.v3_auth_password_var.get()) < 8:
                        return False, "Password auth deve essere almeno 8 caratteri!"

                if self.v3_priv_protocol_var.get() != "noPriv":
                    if len(self.v3_priv_password_var.get()) < 8:
                        return False, "Password priv deve essere almeno 8 caratteri!"
            else:
                if not self.community_var.get().strip():
                    return False, "Community string richiesta!"

            # Test risoluzione host
            try:
                ipaddress.ip_address(host)
            except:
                try:
                    resolved = socket.gethostbyname(host)
                    self.logger.info(f"Host risolto: {host} -> {resolved}")
                except:
                    return False, f"Impossibile risolvere host: {host}"

            # Limiti memoria
            max_results = int(self.max_results_var.get())
            if max_results < 100 or max_results > 100000:
                return False, "Max risultati deve essere tra 100 e 100000!"

            max_memory = int(self.max_memory_var.get())
            if max_memory < 50 or max_memory > 2000:
                return False, "Max memoria deve essere tra 50 e 2000 MB!"

            return True, ""

        except ValueError as e:
            return False, f"Errore validazione: {str(e)}"

    def create_snmpv3_client(self):
        """Crea client SNMPv3 con gestione sicura"""
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

            self.logger.info(f"Client SNMPv3 creato per {self.host_var.get()}")
            return client

        except Exception as e:
            self.logger.error(f"Errore creazione client v3: {str(e)}")
            raise

    def test_connection(self):
        """Test connessione non bloccante"""
        # Valida input
        valid, error = self.validate_input()
        if not valid:
            messagebox.showerror("Errore", error)
            return

        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Test connessione...")
        self.progress.start()
        self.logger.info(f"Test connessione a {self.host_var.get()}")

        thread = threading.Thread(target=self._test_connection_worker, daemon=True)
        thread.start()

    def _test_connection_worker(self):
        """Worker test connessione con performance tracking"""
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

            # Registra performance
            self.performance_monitor.record_query(response_time, result is not None)

            if result:
                if isinstance(result, SnmpOctetString):
                    sys_desc = result.value.decode('utf-8', errors='replace')
                else:
                    sys_desc = str(result)

                self.logger.info("Test connessione riuscito")
                self.root.after(0, lambda: self._show_test_success(sys_desc, version_info))
            else:
                self.logger.warning("Test connessione: nessuna risposta")
                self.root.after(0, lambda: self._show_test_warning())

        except Exception as e:
            self.performance_monitor.record_query(time.time() - start_time, False)
            self.logger.error(f"Test connessione fallito: {str(e)}")
            self.root.after(0, lambda: self._show_test_error(str(e)))
        finally:
            self.root.after(0, self._test_completed)

    def _show_test_success(self, sys_desc, version_info):
        """Mostra successo test"""
        messagebox.showinfo("Test OK",
                            f"Connessione SNMP stabilita!\n\n"
                            f"Protocollo: {version_info}\n"
                            f"Sistema: {sys_desc[:100]}...")
        self.status_var.set("Test riuscito")

    def _show_test_warning(self):
        """Mostra warning test"""
        messagebox.showwarning("Test",
                               "Connettività OK ma SNMP non risponde.\n"
                               "Verificare community/credenziali.")
        self.status_var.set("SNMP non risponde")

    def _show_test_error(self, error_msg):
        """Mostra errore test"""
        messagebox.showerror("Test Fallito",
                             f"Test fallito:\n\n{error_msg}")
        self.status_var.set("Test fallito")

    def _test_completed(self):
        """Completa test"""
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)

    def test_snmpv3_connection(self):
        """Test specifico SNMPv3"""
        self.test_connection()

    def discover_engine_id(self):
        """Scopre Engine ID funzionante"""
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Discovery Engine ID...")
        self.progress.start()
        self.logger.info("Avvio discovery Engine ID")

        thread = threading.Thread(target=self._discover_engine_worker, daemon=True)
        thread.start()

    def _discover_engine_worker(self):
        """Worker discovery Engine ID"""
        try:
            host = self.host_var.get()
            port = int(self.port_var.get())
            timeout = float(self.timeout_var.get())

            # Crea utente temporaneo per discovery
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

                self.logger.info(f"Engine ID scoperto: {engine_id_formatted}")
                self.root.after(0, lambda: self._show_engine_discovery_results(results))
            else:
                self.logger.warning("Discovery Engine ID fallito")
                self.root.after(0, lambda: self._show_engine_discovery_error("Nessuna risposta"))

        except Exception as e:
            self.logger.error(f"Errore discovery: {str(e)}")
            self.root.after(0, lambda: self._show_engine_discovery_error(str(e)))
        finally:
            self.root.after(0, self._discovery_completed)

    def _show_engine_discovery_results(self, results):
        """Mostra risultati discovery"""
        self.v3_engine_id_var.set(results['engine_id'])

        result_window = tk.Toplevel(self.root)
        result_window.title("Engine ID Discovery")
        result_window.geometry("500x300")
        result_window.transient(self.root)

        ttk.Label(result_window, text="Engine ID Scoperto!",
                  font=('TkDefaultFont', 12, 'bold')).pack(pady=10)

        frame = ttk.Frame(result_window)
        frame.pack(padx=20, pady=10)

        ttk.Label(frame, text=f"Engine ID: {results['engine_id']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text=f"Engine Boots: {results['engine_boots']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text=f"Engine Time: {results['engine_time']} sec").pack(anchor=tk.W, pady=2)

        def copy_engine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(results['engine_id'])
            messagebox.showinfo("Copiato", "Engine ID copiato!")

        ttk.Button(result_window, text="Copia", command=copy_engine_id).pack(pady=10)
        ttk.Button(result_window, text="OK", command=result_window.destroy).pack()

    def _show_engine_discovery_error(self, error_msg):
        """Mostra errore discovery"""
        messagebox.showerror("Discovery Fallito", f"Impossibile scoprire Engine ID:\n{error_msg}")
        self.status_var.set("Discovery fallito")

    def _discovery_completed(self):
        """Completa discovery"""
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)

    def start_scan(self):
        """Avvia scansione con validazione completa"""
        if self.scanning:
            return

        # Validazione
        valid, error = self.validate_input()
        if not valid:
            messagebox.showerror("Errore", error)
            return

        # Avvia scansione
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Scansione in corso...")

        # Pulisci risultati
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results = {}

        # Inizializza scanner con limiti
        self.memory_scanner = MemoryLimitedScanner(
            int(self.max_results_var.get()),
            int(self.max_memory_var.get())
        )

        self.logger.info(f"Avvio scansione {self.host_var.get()} con SNMPv{self.version_var.get()}")

        # Thread scansione
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()

    def _scan_worker(self):
        """Worker scansione con gestione errori robusta e performance tracking"""
        start_time = time.time()
        errors = []
        successful_oids = 0

        try:
            # Crea client
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

            # OID da scansionare
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
                    self.logger.info("Scansione interrotta dall'utente")
                    break

                # Check limiti memoria
                ok, msg = self.memory_scanner.check_limits()
                if not ok:
                    self.logger.warning(f"Limite raggiunto: {msg}")
                    self.root.after(0, lambda m=msg: messagebox.showwarning("Limite", m))
                    break

                try:
                    self.root.after(0, lambda o=base_oid, p=processed, t=total_oids:
                    self.status_var.set(f"Scansione {o}... ({p}/{t})"))

                    # Timer per performance
                    oid_start = time.time()

                    # Esegui walk
                    if self.version_var.get() == "2c" or self.version_var.get() == "3":
                        results = self.client.bulk_walk(base_oid, max_repetitions=20)
                    else:
                        results = self.client.walk(base_oid)

                    oid_time = time.time() - oid_start

                    # Registra performance
                    self.performance_monitor.record_query(oid_time, len(results) > 0)

                    # Processa risultati
                    for oid, value in results.items():
                        if not self.scanning:
                            break

                        # Check limiti
                        ok, msg = self.memory_scanner.check_limits()
                        if not ok:
                            self.logger.warning(f"Limite durante processing: {msg}")
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
                        self.logger.info(f"OID {base_oid}: {len(results)} risultati")

                except socket.timeout:
                    error = f"Timeout su {base_oid}"
                    errors.append(error)
                    self.logger.warning(error)
                    self.performance_monitor.record_query(self.timeout_var.get(), False)
                except Exception as e:
                    error = f"Errore {base_oid}: {str(e)}"
                    errors.append(error)
                    self.logger.error(error)
                    self.performance_monitor.record_query(0, False)

                processed += 1

                # Check timeout globale
                if time.time() - start_time > 300:  # 5 minuti
                    self.logger.warning("Timeout globale scansione (5 minuti)")
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Timeout", "Scansione interrotta dopo 5 minuti"))
                    break

            # Report finale
            scan_time = time.time() - start_time
            total_results = len(self.scan_results)

            self.logger.info(f"Scansione completata: {total_results} risultati in {scan_time:.1f}s")

            if errors:
                self.logger.warning(f"Completata con {len(errors)} errori")
                error_summary = "\n".join(errors[:5])
                self.root.after(0, lambda: self.status_var.set(
                    f"Completato con {len(errors)} errori in {scan_time:.1f}s"))
            else:
                self.root.after(0, lambda: self.status_var.set(
                    f"Scansione OK: {total_results} risultati in {scan_time:.1f}s"))

            self.root.after(0, self._scan_completed)

        except Exception as e:
            self.logger.error(f"Errore critico scansione: {str(e)}\n{traceback.format_exc()}")
            self.root.after(0, lambda: self._scan_error(f"Errore critico: {str(e)}"))

    def _add_result_to_tree(self, oid, value):
        """Aggiunge risultato al tree con nome MIB migliorato"""
        try:
            # Usa MIB parser per nome
            name = self.mib_parser.get_name(oid)
            if not name:
                name = self._get_oid_description(oid)
                
            value_type = type(value).__name__

            # Formatta valore
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
            self.info_var.set(f"Risultati: {total}")

        except Exception as e:
            self.logger.error(f"Errore aggiunta risultato: {e}")

    def _get_oid_description(self, oid):
        """Ottiene descrizione OID migliorata con supporto MIB parser"""
        # Prima controlla MIB parser
        mib_name = self.mib_parser.get_name(oid)
        if mib_name:
            return mib_name
            
        # Poi controlla il dizionario esatto
        if oid in self.oid_names:
            return self.oid_names[oid]
        
        # Poi cerca corrispondenze parziali
        oid_parts = oid.split('.')
        for i in range(len(oid_parts), 0, -1):
            partial = '.'.join(oid_parts[:i])
            if partial in self.oid_names:
                # Se trovato, aggiungi l'indice se presente
                if i < len(oid_parts):
                    suffix = '.'.join(oid_parts[i:])
                    return f"{self.oid_names[partial]}.{suffix}"
                return self.oid_names[partial]
        
        # Se non trovato, cerca di identificare la categoria principale
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
        """Completa scansione"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()

        total = len(self.results_tree.get_children())
        self.status_var.set(f"Scansione completata - {total} risultati")
        self.save_config()

    def _scan_error(self, error_msg):
        """Gestisce errore scansione"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set(f"Errore: {error_msg}")
        messagebox.showerror("Errore Scansione", error_msg)

    def stop_scan(self):
        """Ferma scansione"""
        self.scanning = False
        self.status_var.set("Interruzione...")
        self.logger.info("Scansione interrotta dall'utente")

    def walk_from_selected(self):
        """WALK da elemento selezionato con performance tracking"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Seleziona un elemento")
            return

        if not self.client:
            messagebox.showerror("Errore", "Effettua prima una scansione")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if not values:
            return

        oid = values[0]

        # Conferma per walk potenzialmente grandi
        if not messagebox.askyesno("WALK", f"Eseguire WALK da:\n{oid}\n\nPotrebbe generare molti risultati."):
            return

        # Pulisci risultati
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        self.status_var.set(f"WALK da {oid}...")
        self.progress.start()
        self.logger.info(f"WALK da OID: {oid}")

        # Thread per WALK
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
                            "Limite", f"Raggiunto limite di {self.max_results_var.get()} risultati"))
                        break

                    self.root.after(0, self._add_result_to_tree, walk_oid, value)
                    count += 1

                self.logger.info(f"WALK completato: {count} risultati in {response_time:.2f}s")
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: self.status_var.set(f"✅ WALK completato - {count} risultati"))

            except Exception as e:
                self.performance_monitor.record_query(time.time() - start_time, False)
                self.logger.error(f"Errore WALK: {str(e)}")
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Errore WALK", str(e)))

        threading.Thread(target=walk_worker, daemon=True).start()

    def set_value(self):
        """SET valore SNMP con tracking"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Seleziona un elemento")
            return

        if not self.client:
            messagebox.showerror("Errore", "Effettua prima una scansione")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if not values:
            return

        oid = values[0]
        current_value = values[3]
        current_type = values[2]

        # Dialog per nuovo valore
        dialog = tk.Toplevel(self.root)
        dialog.title("SET Valore SNMP")
        dialog.geometry("450x350")
        dialog.transient(self.root)
        dialog.grab_set()

        # Info OID
        info_frame = ttk.LabelFrame(dialog, text="Informazioni OID")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(info_frame, text=f"OID: {oid}", font=('TkDefaultFont', 9)).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Tipo attuale: {current_type}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Valore attuale: {current_value}").pack(anchor=tk.W, padx=5, pady=2)

        # Frame nuovo valore
        value_frame = ttk.LabelFrame(dialog, text="Nuovo Valore")
        value_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(value_frame, text="Valore:").pack(anchor=tk.W, padx=5, pady=5)
        new_value_var = tk.StringVar(value=current_value)
        value_entry = ttk.Entry(value_frame, textvariable=new_value_var, width=40)
        value_entry.pack(padx=5, pady=5)

        ttk.Label(value_frame, text="Tipo dato:").pack(anchor=tk.W, padx=5, pady=5)
        type_var = tk.StringVar(value="String")
        type_combo = ttk.Combobox(value_frame, textvariable=type_var, state='readonly',
                                  values=["String", "Integer", "IPAddress", "OID", "Gauge", "Counter"])
        type_combo.pack(padx=5, pady=5)

        # Warning
        warning_label = ttk.Label(dialog, text="ATTENZIONE: SET modifica valori sul dispositivo!",
                                  foreground="red")
        warning_label.pack(pady=10)

        def do_set():
            start_time = time.time()
            try:
                new_val = new_value_var.get()
                val_type = type_var.get()

                # Crea valore SNMP appropriato
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

                # Log operazione
                self.logger.info(f"SET {oid} = {new_val} ({val_type})")

                # Esegui SET
                if self.client.set(oid, snmp_value):
                    response_time = time.time() - start_time
                    self.performance_monitor.record_query(response_time, True)
                    
                    messagebox.showinfo("SET OK", "Valore impostato con successo!")
                    dialog.destroy()

                    # Aggiorna valore nel tree
                    self.get_single_oid(oid)
                    self.logger.info(f"SET completato con successo in {response_time:.3f}s")
                else:
                    self.performance_monitor.record_query(time.time() - start_time, False)
                    messagebox.showerror("SET Fallito", "Impossibile impostare il valore")
                    self.logger.error("SET fallito")

            except Exception as e:
                self.performance_monitor.record_query(time.time() - start_time, False)
                error_msg = f"Errore SET: {str(e)}"
                self.logger.error(error_msg)
                messagebox.showerror("Errore", error_msg)

        # Pulsanti
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Applica", command=do_set).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Annulla", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def get_selected(self):
        """GET su elemento selezionato"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Seleziona elemento")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if values:
            self.get_single_oid(values[0])

    def get_single_oid(self, oid):
        """GET singolo OID con performance tracking"""
        if not self.client:
            messagebox.showerror("Errore", "Effettua prima una scansione")
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
                                    f"Valore: {value}\n"
                                    f"Tipo: {type(result).__name__}\n"
                                    f"Tempo risposta: {response_time:.3f}s")

                # Aggiorna nel tree se presente
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
                messagebox.showwarning("GET Result", f"Nessun valore per: {oid}")

        except Exception as e:
            self.performance_monitor.record_query(time.time() - start_time, False)
            self.logger.error(f"Errore GET: {str(e)}")
            messagebox.showerror("Errore GET", str(e))

    def full_walk(self):
        """Walk completo con performance tracking"""
        if not messagebox.askyesno("Walk Completo",
                                   "Il walk completo può richiedere MOLTO tempo e memoria.\n\n"
                                   "Continuare?"):
            return

        # Pulisci risultati
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results.clear()

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Walk completo in corso...")

        # Inizializza scanner con limiti
        self.memory_scanner = MemoryLimitedScanner(
            int(self.max_results_var.get()),
            int(self.max_memory_var.get())
        )

        self.logger.info("Avvio walk completo")

        def walk_worker():
            start_time = time.time()
            try:
                # Crea client
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

                # Walk dalla radice
                self.logger.info("Walk da OID radice: 1")

                if self.version_var.get() == "2c" or self.version_var.get() == "3":
                    results = client.bulk_walk("1", max_repetitions=50)
                else:
                    results = client.walk("1")

                response_time = time.time() - start_time
                self.performance_monitor.record_query(response_time, len(results) > 0)

                # Aggiungi risultati con controllo limiti
                count = 0
                for oid, value in results.items():
                    if not self.scanning:
                        self.logger.info("Walk interrotto dall'utente")
                        break

                    # Check limiti
                    ok, msg = self.memory_scanner.check_limits()
                    if not ok:
                        self.logger.warning(f"Walk interrotto per limite: {msg}")
                        self.root.after(0, lambda m=msg: messagebox.showwarning("Limite", m))
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
                        self.root.after(0, lambda c=count: self.status_var.set(f"Walk: {c} OID trovati..."))

                self.logger.info(f"Walk completato: {count} OID in {response_time:.1f}s")
                self.root.after(0, lambda c=count: self.status_var.set(f"Walk completato: {c} OID"))

            except Exception as e:
                self.performance_monitor.record_query(time.time() - start_time, False)
                self.logger.error(f"Errore walk completo: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Errore Walk", str(e)))
            finally:
                self.scanning = False
                self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.progress.stop())

        threading.Thread(target=walk_worker, daemon=True).start()

    def refresh_dashboard(self):
        """Aggiorna dashboard con performance tracking"""
        if not self.saved_values:
            self.status_var.set("Dashboard vuoto")
            return

        # Pulisci dashboard
        for item in self.dashboard_tree.get_children():
            self.dashboard_tree.delete(item)

        self.status_var.set("Aggiornamento dashboard...")
        self.progress.start()
        self.logger.info(f"Aggiornamento dashboard: {len(self.saved_values)} elementi")

        def refresh_worker():
            try:
                errors = []
                success = 0

                for key, config in self.saved_values.items():
                    start_time = time.time()
                    try:
                        # Crea client per questo host
                        if config.get('version') == '3':
                            # Usa credenziali salvate (decriptate)
                            if 'v3_config' in config:
                                v3_config = config['v3_config']

                                # Decripta password
                                auth_pass = self.credential_manager.decrypt_password(
                                    v3_config.get('auth_password_encrypted', ''))
                                priv_pass = self.credential_manager.decrypt_password(
                                    v3_config.get('priv_password_encrypted', ''))

                                # Crea user v3
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

                        # Get valore
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

                        # Aggiungi al dashboard
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

                # Report finale
                total = len(self.saved_values)
                self.logger.info(f"Dashboard aggiornato: {success}/{total} OK")

                if errors:
                    self.root.after(0, lambda: self.status_var.set(
                        f"Dashboard: {success}/{total} OK, {len(errors)} errori"))
                else:
                    self.root.after(0, lambda: self.status_var.set(
                        f"Dashboard aggiornato: {total} elementi"))

            except Exception as e:
                self.logger.error(f"Errore aggiornamento dashboard: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Errore Dashboard", str(e)))
            finally:
                self.root.after(0, lambda: self.progress.stop())

        threading.Thread(target=refresh_worker, daemon=True).start()

    def export_results(self):
        """Esporta risultati in TUTTI i formati"""
        if not self.scan_results:
            messagebox.showwarning("Avviso", "Nessun risultato da esportare")
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
            self.logger.info(f"Export risultati in: {filename}")

            if filename.endswith('.json'):
                # Export JSON con metriche performance
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
                    writer.writerow(['OID', 'Nome', 'Tipo', 'Valore', 'Stato', 'Timestamp'])

                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        if values:
                            writer.writerow(values)

            elif filename.endswith('.html'):
                # Export HTML avanzato
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

            self.logger.info(f"Export completato: {os.path.basename(filename)}")
            messagebox.showinfo("Export Completato",
                                f"Risultati esportati con successo!\n\n"
                                f"File: {os.path.basename(filename)}\n"
                                f"Totale: {len(self.scan_results)} risultati")

            # Chiedi se aprire
            if messagebox.askyesno("Apri File", "Vuoi aprire il file esportato?"):
                if sys.platform.startswith('win'):
                    os.startfile(filename)
                elif sys.platform.startswith('darwin'):
                    os.system(f'open "{filename}"')
                else:
                    os.system(f'xdg-open "{filename}"')

        except Exception as e:
            self.logger.error(f"Errore export: {str(e)}")
            messagebox.showerror("Errore Export", f"Errore durante export:\n{str(e)}")

    def save_config(self):
        """Salva configurazione con credenziali criptate"""
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
            'current_profile': self.current_profile_var.get()
        }

        if self.version_var.get() == "3":
            # Cripta password v3
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
            self.logger.info("Configurazione salvata")
        except Exception as e:
            self.logger.error(f"Errore salvataggio config: {e}")

    def load_config(self):
        """Carica configurazione con decriptazione"""
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

                if 'v3_user' in config:
                    self.v3_user_var.set(config.get('v3_user', ''))
                    self.v3_auth_protocol_var.set(config.get('v3_auth_protocol', 'noAuth'))

                    # Decripta password
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

                self.logger.info("Configurazione caricata")

        except Exception as e:
            self.logger.error(f"Errore caricamento config: {e}")

    def show_settings(self):
        """Mostra dialog impostazioni avanzate"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Impostazioni")
        settings_window.geometry("450x550")
        settings_window.transient(self.root)
        settings_window.grab_set()

        # Notebook per categorie
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tab Limiti
        limits_frame = ttk.Frame(notebook)
        notebook.add(limits_frame, text="Limiti")

        ttk.Label(limits_frame, text="Limiti Scansione:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        limits_info = ttk.Frame(limits_frame)
        limits_info.pack(padx=20, pady=10)

        ttk.Label(limits_info, text="Max Risultati:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(limits_info, textvariable=self.max_results_var, width=10).grid(row=0, column=1, padx=10)

        ttk.Label(limits_info, text="Max Memoria (MB):").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(limits_info, textvariable=self.max_memory_var, width=10).grid(row=1, column=1, padx=10)

        # Tab Logging
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Logging")

        ttk.Label(log_frame, text="Configurazione Log:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        log_level_var = tk.StringVar(value="INFO")
        ttk.Label(log_frame, text="Livello Log:").pack()
        ttk.Combobox(log_frame, textvariable=log_level_var,
                     values=["DEBUG", "INFO", "WARNING", "ERROR"],
                     state='readonly').pack(pady=5)

        def apply_log_level():
            level = getattr(logging, log_level_var.get())
            self.logger.setLevel(level)
            messagebox.showinfo("OK", f"Livello log impostato a {log_level_var.get()}")

        ttk.Button(log_frame, text="Applica", command=apply_log_level).pack(pady=10)

        # Tab Sicurezza
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Sicurezza")

        ttk.Label(security_frame, text="Opzioni Sicurezza:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        def clear_passwords():
            """Cancella password dalla memoria"""
            self.v3_auth_password_var.set("")
            self.v3_priv_password_var.set("")

            # Forza garbage collection
            self.credential_manager.secure_delete(self.v3_auth_password_var.get())
            self.credential_manager.secure_delete(self.v3_priv_password_var.get())

            gc.collect()
            messagebox.showinfo("OK", "Password cancellate dalla memoria")

        ttk.Button(security_frame, text="Cancella Password dalla Memoria",
                   command=clear_passwords).pack(pady=10)

        # Tab Performance
        perf_frame = ttk.Frame(notebook)
        notebook.add(perf_frame, text="Performance")
        
        ttk.Label(perf_frame, text="Opzioni Performance:",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)
        
        perf_info = ttk.Frame(perf_frame)
        perf_info.pack(padx=20, pady=10)
        
        ttk.Label(perf_info, text="Max Workers Batch:").grid(row=0, column=0, sticky=tk.W, pady=5)
        batch_workers_var = tk.StringVar(value=str(self.batch_operations.max_workers))
        ttk.Entry(perf_info, textvariable=batch_workers_var, width=10).grid(row=0, column=1, padx=10)
        
        def apply_performance():
            try:
                self.batch_operations.max_workers = int(batch_workers_var.get())
                messagebox.showinfo("OK", "Impostazioni performance applicate")
            except:
                messagebox.showerror("Errore", "Valore non valido")
                
        ttk.Button(perf_frame, text="Applica", command=apply_performance).pack(pady=10)

        # Pulsanti
        btn_frame = ttk.Frame(settings_window)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="OK", command=settings_window.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Annulla", command=settings_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_log_viewer(self):
        """Visualizza log file"""
        log_window = tk.Toplevel(self.root)
        log_window.title("Log Viewer")
        log_window.geometry("800x600")
        log_window.transient(self.root)

        # Text widget con scrollbar
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

        # Carica ultimo log
        try:
            log_file = os.path.join("logs", f"snmp_browser_{datetime.now().strftime('%Y%m%d')}.log")
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    text.insert(tk.END, f.read())
                text.see(tk.END)
            else:
                text.insert(tk.END, "Nessun file log trovato per oggi.")
        except Exception as e:
            text.insert(tk.END, f"Errore caricamento log: {str(e)}")

        text.config(state=tk.DISABLED)

        # Pulsanti
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

        ttk.Button(btn_frame, text="Aggiorna", command=refresh_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Chiudi", command=log_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_debug_info(self):
        """Mostra informazioni debug"""
        info = f"""
DEBUG INFO

Sistema: {sys.platform}
Python: {sys.version}
Memoria: {psutil.Process().memory_info().rss / 1024 / 1024:.1f}MB
CPU: {psutil.cpu_percent()}%

Risultati caricati: {len(self.scan_results)}
Dashboard elementi: {len(self.saved_values)}
Trap ricevuti: {len(self.received_traps)}
Profili salvati: {len(self.profile_manager.list_profiles())}

Performance Summary:
{json.dumps(self.performance_monitor.get_summary(), indent=2)}

Log directory: {os.path.abspath('logs')}
Config file: {os.path.abspath(self.config_file)}

SNMP Client attivo: {'Si' if self.client else 'No'}
Versione SNMP: {self.version_var.get()}
Trap Receiver: {'Attivo' if self.trap_receiver and self.trap_receiver.running else 'Inattivo'}
"""

        messagebox.showinfo("Debug Info", info)

    def show_shortcuts(self):
        """Mostra shortcuts tastiera"""
        shortcuts = """
SHORTCUTS TASTIERA

Ctrl+S    - Salva configurazione
Ctrl+O    - Carica configurazione  
Ctrl+E    - Esporta risultati
Ctrl+T    - Test connessione
Ctrl+Q    - Esci

F1        - Guida
F5        - Aggiorna dashboard
ESC       - Interrompi scansione

Doppio Click - GET su OID
Click Destro - Menu contestuale
"""
        messagebox.showinfo("Shortcuts", shortcuts)

    def on_closing(self):
        """Chiusura applicazione con cleanup"""
        if self.scanning:
            if not messagebox.askyesno("Scansione in corso",
                                       "Scansione in corso. Vuoi davvero uscire?"):
                return
            self.stop_scan()

        # Ferma trap receiver
        if self.trap_receiver and self.trap_receiver.running:
            self.trap_receiver.stop()

        # Ferma timer
        if self.auto_refresh_timer:
            self.root.after_cancel(self.auto_refresh_timer)

        # Salva configurazione
        self.save_config()
        self.save_saved_values()

        # Cancella password dalla memoria
        self.credential_manager.secure_delete(self.v3_auth_password_var.get())
        self.credential_manager.secure_delete(self.v3_priv_password_var.get())

        # Cleanup
        gc.collect()

        self.logger.info("Chiusura applicazione")
        self.logger.info("=" * 60)

        self.root.quit()
        self.root.destroy()

    # Metodi helper esistenti dal codice originale

    def apply_filter(self, *args):
        """Applica filtri ai risultati"""
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
        """Pulisce filtri"""
        self.filter_var.set("")
        self.show_errors_var.set(False)

    def on_result_double_click(self, event):
        """Doppio click su risultato"""
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            values = self.results_tree.item(item)['values']
            if values:
                self.get_single_oid(values[0])

    def on_mib_double_click(self, event):
        """Doppio click su MIB tree - Mostra dettagli completi"""
        selection = self.mib_tree.selection()
        if selection:
            item = selection[0]
            values = self.mib_tree.item(item)['values']
            if values and values[0]:  # Se ha un OID
                oid = values[0]
                value = values[1] if len(values) > 1 else ""
                type_str = values[2] if len(values) > 2 else ""
                status = values[3] if len(values) > 3 else ""
                
                # Se c'è un valore, mostra dettagli
                if value:
                    # Recupera valore completo se troncato
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
                    
                    # Mostra dialog con valore completo
                    detail_window = tk.Toplevel(self.root)
                    detail_window.title("Dettagli OID")
                    detail_window.geometry("600x400")
                    detail_window.transient(self.root)
                    
                    # Frame info
                    info_frame = ttk.LabelFrame(detail_window, text="Informazioni OID")
                    info_frame.pack(fill=tk.X, padx=10, pady=10)
                    
                    ttk.Label(info_frame, text=f"OID: {oid}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(info_frame, text=f"Nome: {self._get_oid_description(oid)}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(info_frame, text=f"Tipo: {type_str}").pack(anchor=tk.W, padx=5, pady=2)
                    ttk.Label(info_frame, text=f"Stato: {status}").pack(anchor=tk.W, padx=5, pady=2)
                    
                    # Frame valore
                    value_frame = ttk.LabelFrame(detail_window, text="Valore")
                    value_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
                    
                    text_widget = tk.Text(value_frame, wrap=tk.WORD)
                    text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                    text_widget.insert(tk.END, full_value)
                    text_widget.config(state=tk.DISABLED)
                    
                    # Pulsanti
                    btn_frame = ttk.Frame(detail_window)
                    btn_frame.pack(pady=5)
                    
                    def copy_value():
                        self.root.clipboard_clear()
                        self.root.clipboard_append(full_value)
                        messagebox.showinfo("Copiato", "Valore copiato negli appunti!")
                    
                    ttk.Button(btn_frame, text="Copia Valore", command=copy_value).pack(side=tk.LEFT, padx=5)
                    ttk.Button(btn_frame, text="GET", command=lambda: self.get_single_oid(oid)).pack(side=tk.LEFT, padx=5)
                    ttk.Button(btn_frame, text="OK", command=detail_window.destroy).pack(side=tk.LEFT, padx=5)
                else:
                    # Se non c'è valore, prova a fare GET
                    self.get_single_oid(oid)

    def show_context_menu(self, event):
        """Menu contestuale"""
        selection = self.results_tree.selection()
        if not selection:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="GET", command=self.get_selected)
        menu.add_command(label="SET", command=self.set_value)
        menu.add_command(label="WALK", command=self.walk_from_selected)
        menu.add_separator()
        menu.add_command(label="Aggiungi Dashboard", command=self.add_to_dashboard)
        menu.add_command(label="Copia OID", command=self.copy_oid)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def add_to_dashboard(self):
        """Aggiunge a dashboard con supporto v3"""
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

                # Se v3, salva configurazione criptata
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
        self.logger.info(f"Aggiunti {count} elementi al dashboard")
        messagebox.showinfo("Dashboard", f"Aggiunti {count} elementi al dashboard")

    def copy_oid(self):
        """Copia OID negli appunti"""
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            values = self.results_tree.item(item)['values']
            if values:
                self.root.clipboard_clear()
                self.root.clipboard_append(values[0])
                self.status_var.set(f"OID copiato: {values[0]}")

    def remove_from_dashboard(self):
        """Rimuove da dashboard"""
        selection = self.dashboard_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Seleziona elementi da rimuovere")
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
        """Pulisce dashboard"""
        if self.saved_values and messagebox.askyesno("Conferma", "Rimuovere tutti gli elementi?"):
            self.saved_values.clear()
            for item in self.dashboard_tree.get_children():
                self.dashboard_tree.delete(item)
            self.save_saved_values()

    def toggle_auto_refresh(self):
        """Toggle auto-refresh dashboard"""
        if self.auto_refresh_var.get():
            self.refresh_dashboard()
            self.auto_refresh_timer = self.root.after(30000, self.toggle_auto_refresh)
            self.logger.info("Auto-refresh dashboard attivato")
        else:
            if self.auto_refresh_timer:
                self.root.after_cancel(self.auto_refresh_timer)
                self.auto_refresh_timer = None
            self.logger.info("Auto-refresh dashboard disattivato")

    def build_mib_tree(self):
        """Costruisce albero MIB con nomi descrittivi"""
        if not self.scan_results:
            messagebox.showwarning("Avviso", "Effettua prima una scansione")
            return

        # Pulisce albero esistente
        for item in self.mib_tree.get_children():
            self.mib_tree.delete(item)

        self.status_var.set("Costruzione albero MIB...")
        self.progress.start()
        
        # Struttura per organizzare OID gerarchicamente
        tree_structure = {}
        
        # Processa ogni OID dai risultati
        for oid, data in self.scan_results.items():
            parts = oid.split('.')
            current = tree_structure
            
            # Costruisce path completo
            path = []
            for i, part in enumerate(parts):
                if part:  # Ignora parti vuote
                    path.append(part)
                    full_oid = '.'.join(path)
                    
                    if part not in current:
                        current[part] = {
                            '_oid': full_oid,
                            '_name': self._get_oid_description(full_oid),
                            '_data': None,
                            '_children': {}
                        }
                    
                    # Se questo è l'OID completo, salva i dati
                    if full_oid == oid:
                        current[part]['_data'] = data
                        
                    current = current[part]['_children']
        
        # Popola l'albero
        self._populate_mib_tree_enhanced("", tree_structure)
        
        self.progress.stop()
        self.status_var.set("Albero MIB costruito")
        
        # Espandi i primi livelli
        for item in self.mib_tree.get_children():
            self.mib_tree.item(item, open=True)
            for child in self.mib_tree.get_children(item):
                self.mib_tree.item(child, open=True)

    def _populate_mib_tree_enhanced(self, parent, tree_dict):
        """Popola albero MIB con valori visibili direttamente"""
        for key, value in sorted(tree_dict.items(), key=lambda x: (x[0].isdigit(), int(x[0]) if x[0].isdigit() else x[0])):
            if isinstance(value, dict):
                oid = value.get('_oid', key)
                name = value.get('_name', '')
                data = value.get('_data', None)
                children = value.get('_children', {})
                
                # Determina il testo da mostrare
                if name:
                    display_text = f"{key} - {name}"
                else:
                    display_text = key
                
                # Prepara il valore da mostrare
                value_str = ""
                type_str = ""
                status_str = ""
                
                if data:
                    # Se abbiamo dati per questo OID
                    raw_value = data.get('value')
                    
                    # Formatta il valore per la visualizzazione
                    if isinstance(raw_value, SnmpOctetString):
                        try:
                            value_str = raw_value.value.decode('utf-8', errors='replace')
                            # Tronca se troppo lungo
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
                    
                    # Tag per nodi con dati (colore diverso se vogliamo)
                    tag = 'hasdata'
                else:
                    # Nodi senza dati
                    tag = 'nodata'
                
                # Inserisce il nodo con tutte le informazioni incluso il valore
                node = self.mib_tree.insert(parent, tk.END, 
                                        text=display_text,
                                        values=(oid, value_str, type_str, status_str),
                                        tags=(tag,))
                
                # Configurazione colori (nero per tutto)
                self.mib_tree.tag_configure('hasdata', foreground='black', font=('TkDefaultFont', 9, 'normal'))
                self.mib_tree.tag_configure('nodata', foreground='black', font=('TkDefaultFont', 9, 'normal'))
                
                # Processa ricorsivamente i figli
                if children:
                    self._populate_mib_tree_enhanced(node, children)

    def expand_all_mib(self):
        """Espande tutto l'albero MIB"""
        for item in self.mib_tree.get_children():
            self._expand_tree_recursive(item)

    def collapse_all_mib(self):
        """Comprimi tutto l'albero MIB"""
        for item in self.mib_tree.get_children():
            self._collapse_tree_recursive(item)

    def _expand_tree_recursive(self, item):
        """Espande ricorsivamente"""
        self.mib_tree.item(item, open=True)
        for child in self.mib_tree.get_children(item):
            self._expand_tree_recursive(child)

    def _collapse_tree_recursive(self, item):
        """Comprimi ricorsivamente"""
        self.mib_tree.item(item, open=False)
        for child in self.mib_tree.get_children(item):
            self._collapse_tree_recursive(child)

    def clear_cache(self):
        """Pulisce cache e risultati"""
        if messagebox.askyesno("Pulisci Cache", "Pulire tutti i risultati e la cache?"):
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            for item in self.mib_tree.get_children():
                self.mib_tree.delete(item)

            self.scan_results.clear()
            self.mib_tree_data.clear()

            gc.collect()

            self.status_var.set("Cache pulita")
            self.info_var.set("")
            self.logger.info("Cache pulita")

    def load_config_dialog(self):
        """Dialog carica configurazione"""
        filename = filedialog.askopenfilename(
            title="Carica Configurazione",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'r') as f:
                    config = json.load(f)

                # Applica configurazione
                self.host_var.set(config.get('host', '192.168.1.1'))
                self.community_var.set(config.get('community', 'public'))
                self.port_var.set(config.get('port', '161'))
                self.version_var.set(config.get('version', '2c'))
                self.timeout_var.set(config.get('timeout', '5.0'))
                self.retries_var.set(config.get('retries', '3'))

                messagebox.showinfo("Configurazione", "Configurazione caricata con successo!")
                self.logger.info(f"Configurazione caricata da: {filename}")

            except Exception as e:
                messagebox.showerror("Errore", f"Errore caricamento:\n{str(e)}")
                self.logger.error(f"Errore caricamento config: {str(e)}")

    def save_saved_values(self):
        """Salva valori dashboard"""
        try:
            with open(self.saved_values_file, 'w') as f:
                json.dump(self.saved_values, f, indent=2)
        except Exception as e:
            self.logger.error(f"Errore salvataggio dashboard: {e}")

    def load_saved_values(self):
        """Carica valori dashboard"""
        try:
            if os.path.exists(self.saved_values_file):
                with open(self.saved_values_file, 'r') as f:
                    self.saved_values = json.load(f)
                self.logger.info(f"Dashboard caricato: {len(self.saved_values)} elementi")
        except Exception as e:
            self.logger.error(f"Errore caricamento dashboard: {e}")

    def show_snmpv3_wizard(self):
        """Wizard configurazione SNMPv3"""
        wizard = tk.Toplevel(self.root)
        wizard.title("Wizard SNMPv3")
        wizard.geometry("500x400")
        wizard.transient(self.root)

        text = """
CONFIGURAZIONE SNMPv3

1. USERNAME: Identifica l'utente SNMPv3

2. AUTENTICAZIONE:
   • noAuth: Nessuna autenticazione
   • MD5/SHA: Richiede password (min 8 caratteri)

3. PRIVACY (Crittografia):
   • noPriv: Nessuna crittografia
   • DES/AES: Richiede password privacy

4. LIVELLI SICUREZZA:
   • noAuthNoPriv: Solo username
   • authNoPriv: Username + autenticazione
   • authPriv: Username + auth + crittografia

5. ENGINE ID: Identifica univocamente il dispositivo
   (usa "Scopri Engine ID" per ottenerlo)

Le password devono corrispondere a quelle
configurate sul dispositivo SNMP!
"""

        text_widget = tk.Text(wizard, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)

        ttk.Button(wizard, text="OK", command=wizard.destroy).pack(pady=10)

    def show_help(self):
        """Mostra guida"""
        help_text = """
GUIDA SNMP BROWSER

OPERAZIONI BASE:
• Configura host e parametri
• Scegli versione SNMP (1, 2c, 3)
• Clicca "Avvia Scansione"
• Visualizza risultati nel browser

SNMPV3:
• Richiede username e password
• Supporta autenticazione e crittografia
• Usa "Scopri Engine ID" per discovery

FUNZIONI AVANZATE:
• GET: Doppio click su OID
• SET: Click destro > SET
• WALK: Click destro > WALK
• Dashboard: Monitora valori specifici
• Export: Salva in vari formati

NUOVE FUNZIONALITÀ:
• Trap Receiver: Ricevi trap SNMP
• Performance Monitor: Traccia metriche
• Batch Operations: Query multiple hosts
• MIB Loading: Carica file MIB custom
• Profile Manager: Salva configurazioni

LIMITI SICUREZZA:
• Max 10000 risultati per scansione
• Max 500MB memoria
• Timeout 5 minuti per scansione
• Password criptate in configurazione

SHORTCUTS:
• F5: Aggiorna dashboard
• Ctrl+T: Test connessione
• Ctrl+S: Salva configurazione
• ESC: Interrompi scansione
"""

        help_window = tk.Toplevel(self.root)
        help_window.title("Guida")
        help_window.geometry("600x500")
        help_window.transient(self.root)

        text = tk.Text(help_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)

        ttk.Button(help_window, text="OK", command=help_window.destroy).pack(pady=10)

    def show_about(self):
        """Mostra info applicazione con logo"""
        # Crea finestra personalizzata
        about_window = tk.Toplevel(self.root)
        about_window.title("Informazioni su SNMP Browser")
        about_window.geometry("450x490")
        about_window.resizable(False, False)
        about_window.transient(self.root)
        
        # Centra la finestra
        about_window.update_idletasks()
        x = (about_window.winfo_screenwidth() // 2) - (450 // 2)
        y = (about_window.winfo_screenheight() // 2) - (480 // 2)
        about_window.geometry(f'+{x}+{y}')
        
        # Frame principale
        main_frame = ttk.Frame(about_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Logo
        try:
            logo = self.get_about_logo()
            logo_label = ttk.Label(main_frame, image=logo)
            logo_label.image = logo
            logo_label.pack(pady=(5, 10))
        except Exception as e:
            self.logger.error(f"Errore caricamento logo: {e}")
            logo_label = ttk.Label(main_frame, text="SNMP Browser", font=('Arial', 48))
            logo_label.pack(pady=(5, 10))
        
        # Titolo
        title_frame = ttk.Frame(main_frame)
        title_frame.pack()
        
        ttk.Label(title_frame, text="SNMP Browser",
                font=('TkDefaultFont', 16, 'bold')).pack()
        ttk.Label(title_frame, text="Production Ready",
                font=('TkDefaultFont', 10, 'italic')).pack()
        
        # Separatore
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Features in due colonne
        features_frame = ttk.LabelFrame(main_frame, text="✨ Caratteristiche")
        features_frame.pack(fill='x', pady=5)
        
        features_content = ttk.Frame(features_frame)
        features_content.pack(padx=10, pady=8)
        
        # Prima colonna
        col1_features = [
            "Supporto SNMPv1/v2c/v3",
            "Crittografia AES",
            "Logging con rotazione",
            "Memoria ottimizzata"
        ]
        
        # Seconda colonna  
        col2_features = [
            "Export multi-formato",
            "Dashboard real-time",
            "MIB Browser integrato",
            "Scansione bulk"
        ]
        
        # Grid a due colonne
        for i, (feat1, feat2) in enumerate(zip(col1_features, col2_features)):
            ttk.Label(features_content, text=feat1, font=('TkDefaultFont', 8)).grid(
                row=i, column=0, sticky='w', padx=(0, 20))
            ttk.Label(features_content, text=feat2, font=('TkDefaultFont', 8)).grid(
                row=i, column=1, sticky='w')
        
        # Info sistema compatte
        info_frame = ttk.LabelFrame(main_frame, text="Sistema")
        info_frame.pack(fill='x', pady=5)
        
        info_content = ttk.Frame(info_frame)
        info_content.pack(padx=10, pady=8)
        
        # Info in grid compatta
        memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        cpu_percent = psutil.Process().cpu_percent()
        
        info_data = [
            ("OS:", sys.platform.title(), "Python:", sys.version.split()[0]),
            ("Memoria:", f"{memory_mb:.1f} MB", "CPU:", f"{cpu_percent:.1f}%"),
            ("Risultati:", str(len(self.scan_results)), "Thread:", str(threading.active_count()))
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
        
        # Separatore
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=8)
        
        # Copyright e crediti
        credits_frame = ttk.Frame(main_frame)
        credits_frame.pack()
        
        ttk.Label(credits_frame, text="© 2024 - Powered by JustVugg",
                font=('TkDefaultFont', 9)).pack()
        
        # Link a SNMPY
        snmpy_label = ttk.Label(credits_frame, text="Basato su libreria SNMPY", 
                            foreground='blue', cursor='hand2',
                            font=('TkDefaultFont', 9, 'underline'))
        snmpy_label.pack(pady=3)
        snmpy_label.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/JustVugg/snmpy"))
        
        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(8, 5))
        
        ttk.Button(button_frame, text="OK", 
                command=about_window.destroy, width=10).pack()
        
        # Focus e bind
        about_window.focus_set()
        about_window.bind('<Escape>', lambda e: about_window.destroy())
        about_window.bind('<Return>', lambda e: about_window.destroy())

    def get_about_logo(self):
        """Carica il logo da icon.png usando PIL"""
        from PIL import Image, ImageTk
        
        try:
            # Percorso del file icon.png
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
            
            if os.path.exists(icon_path):
                # Usa PIL per caricare e ridimensionare l'immagine
                image = Image.open(icon_path)
                # Ridimensiona a 100x100 pixel
                image = image.resize((100, 100), Image.Resampling.LANCZOS)
                # Converti in PhotoImage per Tkinter
                return ImageTk.PhotoImage(image)
            else:
                raise FileNotFoundError(f"File non trovato: {icon_path}")
                
        except Exception as e:
            self.logger.error(f"Impossibile caricare icona: {e}")
            raise  # Importante: solleva l'eccezione per attivare il fallback


def check_dependencies():
    """Verifica dipendenze necessarie"""
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
        print("Dipendenze mancanti:")
        print(f"   Installa con: pip install {' '.join(missing)}")
        return False

    # Check opzionali
    try:
        import matplotlib
        print("✓ Matplotlib trovato - Grafici performance abilitati")
    except ImportError:
        print("⚠ Matplotlib non trovato - Grafici performance disabilitati")
        print("  Installa con: pip install matplotlib")

    return True


def main():
    """Main function production ready"""
    try:
        # Verifica dipendenze
        if not check_dependencies():
            sys.exit(1)

        # Crea directory necessarie
        os.makedirs("logs", exist_ok=True)

        # Crea finestra principale
        root = tk.Tk()

        # Icona (se disponibile)
        try:
            # Per Windows e Linux
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
            if os.path.exists(icon_path):
                icon = tk.PhotoImage(file=icon_path)
                root.iconphoto(True, icon)
            else:
                # Prova con .ico per Windows
                ico_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
                if os.path.exists(ico_path) and sys.platform.startswith('win'):
                    root.iconbitmap(ico_path)
        except Exception as e:
            print(f"Impossibile caricare icona: {e}")

        # Crea applicazione
        app = SnmpBrowserGUI(root)

        # Bind shortcuts globali
        root.bind('<F1>', lambda e: app.show_help())
        root.bind('<F5>', lambda e: app.refresh_dashboard())
        root.bind('<Control-s>', lambda e: app.save_config())
        root.bind('<Control-o>', lambda e: app.load_config_dialog())
        root.bind('<Control-e>', lambda e: app.export_results())
        root.bind('<Control-t>', lambda e: app.test_connection())
        root.bind('<Control-q>', lambda e: app.on_closing())
        root.bind('<Escape>', lambda e: app.stop_scan() if app.scanning else None)

        # Centra finestra
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')

        # Avvia GUI
        root.mainloop()

    except Exception as e:
        print(f"Errore critico: {e}")
        traceback.print_exc()

        try:
            messagebox.showerror("Errore Critico",
                                 f"Impossibile avviare l'applicazione:\n\n{str(e)}")
        except:
            pass

        sys.exit(1)





if __name__ == "__main__":
    main()

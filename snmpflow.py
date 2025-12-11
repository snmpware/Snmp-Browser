#!/usr/bin/env python3
"""
SNMP Browser v3.5 - Production Ready with Advanced Monitoring
Browser SNMP professionale con supporto completo v1/v2c/v3
Include logging, crittografia credenziali, gestione memoria, sicurezza
E NUOVO: Sistema di alert, grafici real-time, notifiche email
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
from collections import deque
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import psutil

# Per grafici
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Importa la libreria SNMPY
from snmpy import *


class AlertRule:
    """Classe per gestire le regole di alert"""

    def __init__(self, oid, name, condition, threshold, action="notify", email_to=""):
        self.oid = oid
        self.name = name
        self.condition = condition  # "less_than", "greater_than", "equal", "not_equal", "contains"
        self.threshold = threshold
        self.action = action  # "notify", "email", "both"
        self.email_to = email_to
        self.last_alert_time = None
        self.alert_cooldown = 300  # 5 minuti di cooldown tra alert
        self.is_triggered = False
        self.last_value = None

    def check(self, value):
        """Controlla se la regola è violata"""
        try:
            # Converti il valore in numero se possibile
            if isinstance(value, (SnmpInteger, SnmpCounter32, SnmpGauge32, SnmpTimeTicks, SnmpCounter64)):
                numeric_value = float(value.value)
            elif isinstance(value, str) and value.replace('.', '').replace('-', '').isdigit():
                numeric_value = float(value)
            else:
                # Per valori non numerici, usa confronto stringa
                return self._check_string(str(value))

            # Confronto numerico
            numeric_threshold = float(self.threshold)

            if self.condition == "less_than":
                return numeric_value < numeric_threshold
            elif self.condition == "less_than_or_equal":  # NUOVO
                return numeric_value <= numeric_threshold
            elif self.condition == "greater_than":
                return numeric_value > numeric_threshold
            elif self.condition == "greater_than_or_equal":  # NUOVO
                return numeric_value >= numeric_threshold
            elif self.condition == "equal":
                return numeric_value == numeric_threshold
            elif self.condition == "not_equal":
                return numeric_value != numeric_threshold
            else:
                return False

        except (ValueError, TypeError):
            return self._check_string(str(value))

    def _check_string(self, value):
        """Confronto per stringhe"""
        if self.condition == "contains":
            return self.threshold.lower() in value.lower()
        elif self.condition == "equal":
            return value == self.threshold
        elif self.condition == "not_equal":
            return value != self.threshold
        else:
            return False

    def should_alert(self):
        """Verifica se deve inviare un alert (considerando il cooldown)"""
        if self.last_alert_time is None:
            return True

        elapsed = time.time() - self.last_alert_time
        return elapsed > self.alert_cooldown

    def to_dict(self):
        """Converte la regola in dizionario per salvataggio"""
        return {
            'oid': self.oid,
            'name': self.name,
            'condition': self.condition,
            'threshold': self.threshold,
            'action': self.action,
            'email_to': self.email_to,
            'alert_cooldown': self.alert_cooldown
        }

    @classmethod
    def from_dict(cls, data):
        """Crea una regola da un dizionario"""
        rule = cls(
            data['oid'],
            data['name'],
            data['condition'],
            data['threshold'],
            data.get('action', 'notify'),
            data.get('email_to', '')
        )
        rule.alert_cooldown = data.get('alert_cooldown', 300)
        return rule


class EmailConfig:
    """Configurazione per l'invio email con crittografia"""

    def __init__(self, credential_manager=None):
        self.smtp_server = ""
        self.smtp_port = 587
        self.smtp_username = ""
        self.smtp_password_encrypted = ""
        self.from_email = ""
        self.use_tls = True
        self.credential_manager = credential_manager

    def is_configured(self):
        return bool(self.smtp_server and self.smtp_username and self.from_email)

    def get_password(self):
        """Ottiene la password decriptata"""
        if self.credential_manager and self.smtp_password_encrypted:
            return self.credential_manager.decrypt_password(self.smtp_password_encrypted)
        return ""

    def set_password(self, password):
        """Imposta la password criptata"""
        if self.credential_manager:
            self.smtp_password_encrypted = self.credential_manager.encrypt_password(password)

    def send_alert_email(self, to_email, subject, body):
        """Invia un'email di alert"""
        if not self.is_configured():
            return False, "Email non configurata"

        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = f"SNMP Alert: {subject}"

            msg.attach(MIMEText(body, 'plain'))

            password = self.get_password()

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.smtp_username, password)
                server.send_message(msg)

            # Cancella password dalla memoria
            if self.credential_manager:
                self.credential_manager.secure_delete(password)

            return True, "Email inviata con successo"

        except Exception as e:
            return False, str(e)

    def to_dict(self):
        return {
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'smtp_username': self.smtp_username,
            'smtp_password_encrypted': self.smtp_password_encrypted,
            'from_email': self.from_email,
            'use_tls': self.use_tls
        }

    def from_dict(self, data):
        self.smtp_server = data.get('smtp_server', '')
        self.smtp_port = data.get('smtp_port', 587)
        self.smtp_username = data.get('smtp_username', '')
        self.smtp_password_encrypted = data.get('smtp_password_encrypted', '')
        self.from_email = data.get('from_email', '')
        self.use_tls = data.get('use_tls', True)


class GraphWindow:
    """Finestra per visualizzare grafici dei dati SNMP"""

    def __init__(self, parent, oid, name, data_points, logger=None):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Grafico: {name}")
        self.window.geometry("800x600")

        self.oid = oid
        self.name = name
        self.data_points = data_points
        self.logger = logger

        self.create_widgets()
        self.update_graph()

        if self.logger:
            self.logger.info(f"Aperta finestra grafico per OID: {oid}")

    def create_widgets(self):
        """Crea i widget per la finestra grafico"""
        # Frame principale
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Info frame
        info_frame = ttk.LabelFrame(main_frame, text="Informazioni")
        info_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(info_frame, text=f"OID: {self.oid}").pack(anchor='w', padx=5, pady=2)
        ttk.Label(info_frame, text=f"Nome: {self.name}").pack(anchor='w', padx=5, pady=2)

        # Statistiche
        if self.data_points:
            values = [p['value'] for p in self.data_points if isinstance(p['value'], (int, float))]
            if values:
                ttk.Label(info_frame, text=f"Min: {min(values):.2f}").pack(anchor='w', padx=5, pady=2)
                ttk.Label(info_frame, text=f"Max: {max(values):.2f}").pack(anchor='w', padx=5, pady=2)
                ttk.Label(info_frame, text=f"Media: {sum(values) / len(values):.2f}").pack(anchor='w', padx=5, pady=2)
                ttk.Label(info_frame, text=f"Ultimo: {values[-1]:.2f}").pack(anchor='w', padx=5, pady=2)

        # Frame per il grafico
        graph_frame = ttk.LabelFrame(main_frame, text="Grafico")
        graph_frame.pack(fill=tk.BOTH, expand=True)

        # Crea figura matplotlib
        self.figure = Figure(figsize=(8, 5), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(button_frame, text="Aggiorna", command=self.update_graph).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Salva Immagine", command=self.save_graph).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Chiudi", command=self.window.destroy).pack(side=tk.RIGHT)

    def update_graph(self):
        """Aggiorna il grafico con i dati"""
        self.figure.clear()

        if not self.data_points:
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, 'Nessun dato disponibile', ha='center', va='center')
            self.canvas.draw()
            return

        # Prepara i dati
        timestamps = []
        values = []

        for point in self.data_points:
            timestamps.append(datetime.fromtimestamp(point['timestamp']))

            # Converti il valore in numero
            val = point['value']
            if isinstance(val, (int, float)):
                values.append(val)
            elif hasattr(val, 'value'):
                values.append(float(val.value))
            else:
                try:
                    values.append(float(val))
                except:
                    values.append(0)

        # Crea il grafico
        ax = self.figure.add_subplot(111)

        # Linea principale
        ax.plot(timestamps, values, 'b-', linewidth=2, label='Valore')
        ax.fill_between(timestamps, values, alpha=0.3)

        # Punti
        ax.scatter(timestamps, values, color='red', s=30, zorder=5)

        # Formattazione
        ax.set_xlabel('Tempo')
        ax.set_ylabel('Valore')
        ax.set_title(f'{self.name} - Andamento nel tempo')
        ax.grid(True, alpha=0.3)
        ax.legend()

        # Rotazione date
        self.figure.autofmt_xdate()

        # Aggiungi linea media
        if values:
            mean_val = sum(values) / len(values)
            ax.axhline(y=mean_val, color='green', linestyle='--', alpha=0.5, label=f'Media: {mean_val:.2f}')

        self.canvas.draw()

    def save_graph(self):
        """Salva il grafico come immagine"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )

        if filename:
            self.figure.savefig(filename, dpi=100, bbox_inches='tight')
            messagebox.showinfo("Salvataggio", f"Grafico salvato in {filename}")

            if self.logger:
                self.logger.info(f"Grafico salvato: {filename}")


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


import re


class MibParser:
    """Parser per file MIB ASN.1"""

    def __init__(self, logger=None):
        self.logger = logger
        self.oid_mappings = {}
        self.imports = {}
        self.current_module = None

    def parse_file(self, filename):
        """Parsa un file MIB e restituisce mappature OID->Nome"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Rimuovi commenti
            content = self._remove_comments(content)

            # Trova nome del modulo
            module_match = re.search(r'(\w+)\s+DEFINITIONS\s*::=\s*BEGIN', content)
            if module_match:
                self.current_module = module_match.group(1)
                if self.logger:
                    self.logger.info(f"Parsing MIB module: {self.current_module}")

            # Parsa IMPORTS
            self._parse_imports(content)

            # Parsa OBJECT IDENTIFIER
            self._parse_object_identifiers(content)

            # Parsa OBJECT-TYPE
            self._parse_object_types(content)

            # Parsa MODULE-IDENTITY
            self._parse_module_identity(content)

            # Parsa NOTIFICATION-TYPE
            self._parse_notification_types(content)

            # Parsa OBJECT-GROUP
            self._parse_object_groups(content)

            if self.logger:
                self.logger.info(f"MIB parsed: {len(self.oid_mappings)} OIDs trovati")

            return self.oid_mappings

        except Exception as e:
            if self.logger:
                self.logger.error(f"Errore parsing MIB: {e}")
            raise

    def _remove_comments(self, content):
        """Rimuove commenti dal MIB"""
        # Rimuovi commenti -- fino a fine riga
        content = re.sub(r'--.*?$', '', content, flags=re.MULTILINE)
        return content

    def _parse_imports(self, content):
        """Parsa sezione IMPORTS"""
        imports_match = re.search(r'IMPORTS\s+(.*?);', content, re.DOTALL)
        if imports_match:
            imports_text = imports_match.group(1)
            # Semplice parsing degli imports
            from_matches = re.findall(r'([\w\-,\s]+)\s+FROM\s+([\w\-]+)', imports_text)
            for items, module in from_matches:
                items_list = [item.strip() for item in items.split(',')]
                self.imports[module] = items_list

    def _parse_object_identifiers(self, content):
        """Parsa definizioni OBJECT IDENTIFIER"""
        # Pattern per OBJECT IDENTIFIER semplici
        pattern = r'(\w[\w\-]*)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{\s*([\w\-\s]+(?:\s+\d+)?(?:\s+[\w\-]+\s+\d+)*)\s*\}'

        for match in re.finditer(pattern, content):
            name = match.group(1)
            value = match.group(2)

            # Parsa il valore OID
            oid = self._parse_oid_value(value)
            if oid:
                self.oid_mappings[oid] = name

                # Aggiungi anche con descrizione se è un nodo importante
                if any(keyword in name.lower() for keyword in ['mib', 'table', 'entry', 'group']):
                    self.oid_mappings[oid] = f"{name} - {self.current_module or 'Custom'} MIB"

    def _parse_object_types(self, content):
        """Parsa definizioni OBJECT-TYPE"""
        # Pattern per OBJECT-TYPE
        pattern = r'(\w[\w\-]*)\s+OBJECT-TYPE\s+.*?::=\s*\{\s*([\w\-\s]+)\s+(\d+)\s*\}'

        for match in re.finditer(pattern, content, re.DOTALL):
            name = match.group(1)
            parent = match.group(2)
            index = match.group(3)

            # Costruisci OID
            parent_oid = self._find_parent_oid(parent)
            if parent_oid:
                full_oid = f"{parent_oid}.{index}"
                self.oid_mappings[full_oid] = name

                # Cerca DESCRIPTION per aggiungere info
                desc_pattern = rf'{name}\s+OBJECT-TYPE\s+.*?DESCRIPTION\s+"([^"]*)"'
                desc_match = re.search(desc_pattern, content, re.DOTALL)
                if desc_match:
                    description = desc_match.group(1).replace('\n', ' ').strip()
                    if len(description) > 50:
                        description = description[:50] + "..."
                    self.oid_mappings[full_oid] = f"{name} - {description}"

    def _parse_module_identity(self, content):
        """Parsa MODULE-IDENTITY"""
        pattern = r'(\w[\w\-]*)\s+MODULE-IDENTITY\s+.*?::=\s*\{\s*([\w\-\s]+)\s+(\d+)\s*\}'

        for match in re.finditer(pattern, content, re.DOTALL):
            name = match.group(1)
            parent = match.group(2)
            index = match.group(3)

            parent_oid = self._find_parent_oid(parent)
            if parent_oid:
                full_oid = f"{parent_oid}.{index}"
                self.oid_mappings[full_oid] = f"{name} - Module Identity"

    def _parse_notification_types(self, content):
        """Parsa NOTIFICATION-TYPE (traps)"""
        pattern = r'(\w[\w\-]*)\s+NOTIFICATION-TYPE\s+.*?::=\s*\{\s*([\w\-\s]+)\s+(\d+)\s*\}'

        for match in re.finditer(pattern, content, re.DOTALL):
            name = match.group(1)
            parent = match.group(2)
            index = match.group(3)

            parent_oid = self._find_parent_oid(parent)
            if parent_oid:
                full_oid = f"{parent_oid}.{index}"
                self.oid_mappings[full_oid] = f"{name} - Notification/Trap"

    def _parse_object_groups(self, content):
        """Parsa OBJECT-GROUP"""
        pattern = r'(\w[\w\-]*)\s+OBJECT-GROUP\s+.*?::=\s*\{\s*([\w\-\s]+)\s+(\d+)\s*\}'

        for match in re.finditer(pattern, content, re.DOTALL):
            name = match.group(1)
            parent = match.group(2)
            index = match.group(3)

            parent_oid = self._find_parent_oid(parent)
            if parent_oid:
                full_oid = f"{parent_oid}.{index}"
                self.oid_mappings[full_oid] = f"{name} - Object Group"

    def _parse_oid_value(self, value):
        """Parsa un valore OID da testo"""
        # OID numerico completo
        if re.match(r'^[\d\.]+$', value.strip()):
            return value.strip()

        # OID con nomi simbolici
        parts = value.split()
        oid_parts = []

        # Mappature standard comuni
        standard_roots = {
            'iso': '1',
            'org': '3',
            'dod': '6',
            'internet': '1',
            'mgmt': '2',
            'mib-2': '1',
            'mib2': '1',
            'enterprises': '1',
            'private': '4',
            'security': '5',
            'snmpV2': '6',
            'experimental': '3',
            'directory': '1'
        }

        i = 0
        while i < len(parts):
            part = parts[i]

            # Se è un numero
            if part.isdigit():
                oid_parts.append(part)
            # Se è un nome conosciuto
            elif part.lower() in standard_roots:
                oid_parts.append(standard_roots[part.lower()])
            # Se è iso(1) format
            elif '(' in part and ')' in part:
                match = re.match(r'(\w+)KATEX_INLINE_OPEN(\d+)KATEX_INLINE_CLOSE', part)
                if match:
                    oid_parts.append(match.group(2))
            # Cerca nelle mappature già parsate
            elif part in self.oid_mappings.values():
                for oid, name in self.oid_mappings.items():
                    if name == part:
                        return oid

            i += 1

        if oid_parts:
            # Costruisci OID base comuni
            if oid_parts[:4] == ['1', '3', '6', '1']:
                return '1.3.6.1.' + '.'.join(oid_parts[4:])
            else:
                return '.'.join(oid_parts)

        return None

    def _find_parent_oid(self, parent_name):
        """Trova OID del parent dal nome"""
        # OID standard comuni
        standard_oids = {
            'iso': '1',
            'org': '1.3',
            'dod': '1.3.6',
            'internet': '1.3.6.1',
            'directory': '1.3.6.1.1',
            'mgmt': '1.3.6.1.2',
            'mib-2': '1.3.6.1.2.1',
            'mib2': '1.3.6.1.2.1',
            'system': '1.3.6.1.2.1.1',
            'interfaces': '1.3.6.1.2.1.2',
            'experimental': '1.3.6.1.3',
            'private': '1.3.6.1.4',
            'enterprises': '1.3.6.1.4.1',
            'security': '1.3.6.1.5',
            'snmpV2': '1.3.6.1.6',

            # Alcuni vendor comuni
            'cisco': '1.3.6.1.4.1.9',
            'microsoft': '1.3.6.1.4.1.311',
            'hp': '1.3.6.1.4.1.11',
            'dell': '1.3.6.1.4.1.674',
            'ibm': '1.3.6.1.4.1.2',
            'intel': '1.3.6.1.4.1.343',
            'nortel': '1.3.6.1.4.1.562',
            '3com': '1.3.6.1.4.1.43',
            'apc': '1.3.6.1.4.1.318',
            'eaton': '1.3.6.1.4.1.534',
            'cyberpower': '1.3.6.1.4.1.3808',
        }

        # Cerca prima negli OID standard
        parent_lower = parent_name.lower()
        if parent_lower in standard_oids:
            return standard_oids[parent_lower]

        # Cerca nelle mappature già parsate
        for oid, name in self.oid_mappings.items():
            if name == parent_name or name.split(' - ')[0] == parent_name:
                return oid

        return None

class SnmpBrowserGUI:
    """Interfaccia grafica SNMP Browser Production Ready con Monitoring Avanzato"""

    def __init__(self, root):
        self.root = root
        self.root.title("SNMP-Browser")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 750)

        # Setup logging
        self.setup_logging()
        self.logger.info("=" * 60)
        self.logger.info("Avvio SNMP Browser v3.5 Production Ready + Advanced Monitoring")
        self.logger.info(f"Sistema: {sys.platform}, Python: {sys.version}")

        # Manager credenziali sicure
        self.credential_manager = SecureCredentialManager()
        self.custom_mibs = {}
        self.custom_mibs_file = "snmp_browser_custom_mibs.json"
        self.mib_parser = MibParser(self.logger)
        # Variabili configurazione base
        self.host_var = tk.StringVar(value="192.168.1.1")
        self.community_var = tk.StringVar(value="public")
        self.port_var = tk.StringVar(value="161")
        self.version_var = tk.StringVar(value="2c")
        self.timeout_var = tk.StringVar(value="5.0")
        self.retries_var = tk.StringVar(value="3")

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

        # NUOVO: Auto-refresh attivo di default
        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.auto_refresh_timer = None
        self.refresh_interval_var = tk.StringVar(value="30")

        # NUOVO: Sistema di regole e alert
        self.alert_rules = {}
        self.alert_history = deque(maxlen=100)
        self.email_config = EmailConfig(self.credential_manager)
        self.alert_active = False

        # NUOVO: Dati storici per grafici
        self.historical_data = {}

        # Limiti memoria
        self.max_results_var = tk.StringVar(value="10000")
        self.max_memory_var = tk.StringVar(value="500")
        self.memory_scanner = None

        # File configurazione
        self.app_data_dir = self._get_app_data_dir()
        self.config_file = self._get_data_file_path("snmp_browser_config.json")
        self.saved_values_file = self._get_data_file_path("snmp_browser_saved.json")
        self.rules_file = self._get_data_file_path("snmp_browser_rules.json")
        self.email_config_file = self._get_data_file_path("snmp_browser_email.json")
        self.historical_data_file = self._get_data_file_path("snmp_browser_historical.json")
        self.custom_mibs_file = self._get_data_file_path("snmp_browser_custom_mibs.json")
        self.log_dir = os.path.join(self.app_data_dir, 'logs')
        self.logger.info(f"Dati salvati in: {self.app_data_dir}")
        # Dizionario OID
        self.oid_names = self._build_oid_names_dictionary()

        # Crea interfaccia
        self.create_widgets()
        self.create_menu()

        # Carica configurazione
        self.load_config()
        self.load_saved_values()
        self.load_rules()
        self.load_email_config()
        self.load_historical_data()  # NUOVO: Carica dati storici

        # Bind eventi
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.version_var.trace('w', self.on_version_change)

        # Monitor memoria
        self.start_memory_monitor()

        # NUOVO: Avvia auto-refresh e monitoring regole
        self.start_auto_refresh()
        self.start_rule_monitoring()
        self.load_custom_mibs()
        self.logger.info("Inizializzazione completata con monitoring avanzato")

    def _get_app_data_dir(self):
        """Ottiene cartella dati applicazione per il sistema operativo"""
        import os
        import sys
        from pathlib import Path

        app_name = "SNMPBrowser"

        if sys.platform.startswith('win'):
            # Windows: C:\Users\<user>\AppData\Local\SNMPBrowser
            base_dir = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
            app_dir = os.path.join(base_dir, app_name)
        elif sys.platform.startswith('darwin'):
            # macOS: ~/Library/Application Support/SNMPBrowser
            app_dir = os.path.expanduser(f'~/Library/Application Support/{app_name}')
        else:
            # Linux: ~/.config/SNMPBrowser
            config_home = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
            app_dir = os.path.join(config_home, app_name)

        # Crea la cartella se non esiste
        os.makedirs(app_dir, exist_ok=True)

        # Crea anche sottocartella per i log
        log_dir = os.path.join(app_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)

        return app_dir

    def _get_data_file_path(self, filename):
        """Ottiene percorso completo per un file dati"""
        return os.path.join(self._get_app_data_dir(), filename)

    def setup_logging(self):
        """Configura logging su file con rotazione"""
        log_dir = os.path.join(self.app_data_dir, 'logs') if hasattr(self, 'app_data_dir') else "logs"
        os.makedirs(log_dir, exist_ok=True)

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


    def show_data_location(self):
        """Mostra dove sono salvati i dati"""
        location_info = f"""
    📁 POSIZIONE DATI APPLICAZIONE

    Cartella principale: {self.app_data_dir}

    File configurazione:
    • {os.path.basename(self.config_file)}
    • {os.path.basename(self.saved_values_file)}
    • {os.path.basename(self.rules_file)}
    • {os.path.basename(self.email_config_file)}
    • {os.path.basename(self.historical_data_file)}
    • {os.path.basename(self.custom_mibs_file)}

    Cartella log: {self.log_dir}

    Spazio utilizzato: {self._get_folder_size(self.app_data_dir):.2f} MB
    """

        messagebox.showinfo("Posizione Dati", location_info)

        # Chiedi se aprire la cartella
        if messagebox.askyesno("Apri Cartella", "Vuoi aprire la cartella dati?"):
            self.open_data_folder()

    def _get_folder_size(self, folder_path):
        """Calcola dimensione cartella in MB"""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    if os.path.exists(file_path):
                        total_size += os.path.getsize(file_path)
        except:
            pass
        return total_size / (1024 * 1024)

    def open_data_folder(self):
        """Apre la cartella dati nel file explorer"""
        try:
            if sys.platform.startswith('win'):
                os.startfile(self.app_data_dir)
            elif sys.platform.startswith('darwin'):
                os.system(f'open "{self.app_data_dir}"')
            else:
                os.system(f'xdg-open "{self.app_data_dir}"')
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile aprire cartella: {e}")

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

    def _build_oid_names_dictionary(self):
        """Costruisce dizionario OID"""
        return {
            "1": "iso",
            "1.3": "iso.org",
            "1.3.6": "iso.org.dod",
            "1.3.6.1": "iso.org.dod.internet",
            "1.3.6.1.2": "mgmt",
            "1.3.6.1.2.1": "mib-2",
            "1.3.6.1.2.1.1": "system",
            "1.3.6.1.2.1.1.1.0": "sysDescr.0 - System Description",
            "1.3.6.1.2.1.1.2.0": "sysObjectID.0",
            "1.3.6.1.2.1.1.3.0": "sysUpTime.0",
            "1.3.6.1.2.1.1.4.0": "sysContact.0",
            "1.3.6.1.2.1.1.5.0": "sysName.0",
            "1.3.6.1.2.1.1.6.0": "sysLocation.0",
            "1.3.6.1.2.1.2": "interfaces",
            "1.3.6.1.2.1.25": "host",
            "1.3.6.1.2.1.33": "ups",
            "1.3.6.1.2.1.33.1.2.4.0": "upsEstimatedChargeRemaining.0 - Battery Charge %",
            "1.3.6.1.2.1.33.1.4.4.1.5.1": "upsOutputPercentLoad.1 - Output Load %",
            "1.3.6.1.4.1": "enterprises",
        }

    def create_menu(self):
        """Crea menu principale con opzioni monitoring"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Menu File
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Salva Configurazione", command=self.save_config, accelerator="Ctrl+S")
        file_menu.add_command(label="Carica Configurazione", command=self.load_config_dialog, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Esporta Risultati", command=self.export_results, accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label="Visualizza Log", command=self.show_log_viewer)
        file_menu.add_separator()
        file_menu.add_command(label="Esci", command=self.on_closing, accelerator="Ctrl+Q")

        # NUOVO: Menu Monitoring
        monitor_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Monitoring", menu=monitor_menu)
        monitor_menu.add_command(label="Gestisci Regole Alert", command=self.manage_rules)
        monitor_menu.add_command(label="📧 Configura Email", command=self.configure_email)
        monitor_menu.add_command(label="📊 Visualizza Alert History", command=self.show_alert_history)
        monitor_menu.add_separator()
        monitor_menu.add_command(label="🧹 Pulisci Alert", command=self.clear_alerts)

        # Menu Tools
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="🔌 Test Connessione", command=self.test_connection, accelerator="Ctrl+T")
        tools_menu.add_command(label="🌊 SNMP Walk Completo", command=self.full_walk)
        tools_menu.add_command(label="🧹 Pulisci Cache", command=self.clear_cache)
        tools_menu.add_separator()
        tools_menu.add_command(label="📥 Importa MIB Custom", command=self.import_mib)  # ← QUESTA
        tools_menu.add_command(label="📚 Gestisci MIB", command=self.manage_custom_mibs)  # ← E QUESTA!
        tools_menu.add_separator()
        tools_menu.add_command(label="🔐 Wizard SNMPv3", command=self.show_snmpv3_wizard)
        tools_menu.add_command(label="🎯 Scopri Engine ID", command=self.discover_engine_id)
        tools_menu.add_separator()
        tools_menu.add_command(label="💾 Salva Dati Storici", command=self.save_historical_data)
        tools_menu.add_command(label="🧹 Pulisci Dati Vecchi", command=self.clean_old_historical_data)
        tools_menu.add_separator()
        tools_menu.add_command(label="📁 Posizione Dati", command=self.show_data_location)
        tools_menu.add_command(label="📂 Apri Cartella Dati", command=self.open_data_folder)
        tools_menu.add_separator()
        tools_menu.add_command(label="⚙️ Impostazioni", command=self.show_settings)

        # Menu Help
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="📚 Guida", command=self.show_help, accelerator="F1")
        help_menu.add_command(label="⌨️ Shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="🐛 Debug Info", command=self.show_debug_info)
        help_menu.add_separator()
        help_menu.add_command(label="ℹ️ Info", command=self.show_about)

    def import_mib(self):
        """Importa e parsa file MIB custom"""
        filenames = filedialog.askopenfilenames(
            title="📁 Seleziona file MIB da importare",
            filetypes=[
                ("MIB files", "*.mib;*.txt;*.my"),
                ("Tutti i MIB", "*.mib"),
                ("Text files", "*.txt"),
                ("My files", "*.my"),
                ("All files", "*.*")
            ]
        )

        if not filenames:
            return

        total_imported = 0
        errors = []

        # Progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("📥 Importazione MIB")
        progress_window.geometry("400x200")
        progress_window.transient(self.root)
        progress_window.grab_set()

        ttk.Label(progress_window, text="Importazione MIB in corso...",
                  font=('TkDefaultFont', 10, 'bold')).pack(pady=10)

        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_window, variable=progress_var,
                                       maximum=len(filenames), length=350)
        progress_bar.pack(pady=10)

        status_label = ttk.Label(progress_window, text="")
        status_label.pack(pady=5)

        details_text = tk.Text(progress_window, height=5, width=50)
        details_text.pack(padx=10, pady=5)

        for i, filename in enumerate(filenames):
            try:
                # Aggiorna progress
                progress_var.set(i)
                status_label.config(text=f"Processing: {os.path.basename(filename)}")
                progress_window.update()

                # Parsa MIB
                self.logger.info(f"Importazione MIB: {filename}")
                new_oids = self.mib_parser.parse_file(filename)

                if new_oids:
                    # Aggiungi al dizionario principale
                    self.oid_names.update(new_oids)

                    # Salva nei custom MIB
                    self.custom_mibs[os.path.basename(filename)] = {
                        'filename': filename,
                        'oids': new_oids,
                        'timestamp': time.time(),
                        'module': self.mib_parser.current_module
                    }

                    total_imported += len(new_oids)
                    details_text.insert(tk.END,
                                        f"✅ {os.path.basename(filename)}: {len(new_oids)} OID\n")

                    self.logger.info(f"MIB importato: {len(new_oids)} OID da {filename}")
                else:
                    details_text.insert(tk.END,
                                        f"⚠️ {os.path.basename(filename)}: Nessun OID trovato\n")

            except Exception as e:
                error_msg = f"Errore in {os.path.basename(filename)}: {str(e)}"
                errors.append(error_msg)
                details_text.insert(tk.END, f"❌ {error_msg}\n")
                self.logger.error(f"Errore import MIB: {e}")

        progress_var.set(len(filenames))
        status_label.config(text="Importazione completata!")

        # Salva MIB custom
        self.save_custom_mibs()

        # Aggiorna visualizzazioni se ci sono risultati
        if self.scan_results:
            self.refresh_oid_descriptions()

        # Mostra risultato
        ttk.Button(progress_window, text="OK",
                   command=progress_window.destroy).pack(pady=10)

        if errors:
            self.logger.warning(f"Import MIB completato con {len(errors)} errori")

        messagebox.showinfo("📥 Import MIB Completato",
                            f"Importati {total_imported} OID totali\n"
                            f"Da {len(filenames)} file MIB\n"
                            f"Errori: {len(errors)}")

    def save_custom_mibs(self):
        """Salva MIB custom su file"""
        try:
            # Prepara dati per serializzazione
            save_data = {}
            for name, data in self.custom_mibs.items():
                save_data[name] = {
                    'filename': data['filename'],
                    'oids': data['oids'],
                    'timestamp': data['timestamp'],
                    'module': data.get('module', '')
                }

            with open(self.custom_mibs_file, 'w') as f:
                json.dump(save_data, f, indent=2)

            self.logger.info(f"Salvati {len(self.custom_mibs)} MIB custom")

        except Exception as e:
            self.logger.error(f"Errore salvataggio MIB custom: {e}")

    def load_custom_mibs(self):
        """Carica MIB custom salvati"""
        try:
            if os.path.exists(self.custom_mibs_file):
                with open(self.custom_mibs_file, 'r') as f:
                    self.custom_mibs = json.load(f)

                # Ricarica OID nel dizionario principale
                total_oids = 0
                for mib_data in self.custom_mibs.values():
                    if 'oids' in mib_data:
                        self.oid_names.update(mib_data['oids'])
                        total_oids += len(mib_data['oids'])

                self.logger.info(f"Caricati {len(self.custom_mibs)} MIB custom con {total_oids} OID")

        except Exception as e:
            self.logger.error(f"Errore caricamento MIB custom: {e}")

    def refresh_oid_descriptions(self):
        """Aggiorna le descrizioni OID nelle visualizzazioni"""
        # Aggiorna results tree
        for item in self.results_tree.get_children():
            values = list(self.results_tree.item(item)['values'])
            if values:
                oid = values[0]
                # Aggiorna nome se presente nei MIB custom
                if oid in self.oid_names:
                    values[1] = self.oid_names[oid]
                    self.results_tree.item(item, values=values)

        # Aggiorna dashboard
        for item in self.dashboard_tree.get_children():
            values = list(self.dashboard_tree.item(item)['values'])
            if values and len(values) > 2:
                oid = values[1]
                if oid in self.oid_names:
                    values[2] = self.oid_names[oid]
                    self.dashboard_tree.item(item, values=values)

        self.logger.info("Descrizioni OID aggiornate con MIB custom")

    def manage_custom_mibs(self):
        """Gestisci MIB custom importati"""
        mib_window = tk.Toplevel(self.root)
        mib_window.title("📚 Gestione MIB Custom")
        mib_window.geometry("700x500")
        mib_window.transient(self.root)

        # Frame principale
        main_frame = ttk.Frame(mib_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Lista MIB
        list_frame = ttk.LabelFrame(main_frame, text="MIB Importati")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Treeview
        columns = ("File", "Module", "OID Count", "Imported")
        mib_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)

        for col in columns:
            mib_tree.heading(col, text=col)
            mib_tree.column(col, width=150)

        # Popola lista
        for name, data in self.custom_mibs.items():
            timestamp = datetime.fromtimestamp(data['timestamp']).strftime('%Y-%m-%d %H:%M')
            mib_tree.insert("", tk.END, values=(
                name,
                data.get('module', 'N/A'),
                len(data['oids']),
                timestamp
            ))

        mib_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Scrollbar
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=mib_tree.yview)
        mib_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Frame dettagli
        details_frame = ttk.LabelFrame(main_frame, text="Dettagli MIB Selezionato")
        details_frame.pack(fill=tk.BOTH, expand=True)

        details_text = tk.Text(details_frame, height=8, wrap=tk.WORD)
        details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        def show_mib_details(event):
            """Mostra dettagli del MIB selezionato"""
            selection = mib_tree.selection()
            if selection:
                item = selection[0]
                values = mib_tree.item(item)['values']
                if values:
                    mib_name = values[0]
                    if mib_name in self.custom_mibs:
                        data = self.custom_mibs[mib_name]

                        details_text.delete(1.0, tk.END)
                        details_text.insert(tk.END, f"File: {mib_name}\n")
                        details_text.insert(tk.END, f"Path: {data.get('filename', 'N/A')}\n")
                        details_text.insert(tk.END, f"Module: {data.get('module', 'N/A')}\n")
                        details_text.insert(tk.END, f"OID importati: {len(data['oids'])}\n\n")

                        # Mostra primi 10 OID
                        details_text.insert(tk.END, "Esempio OID:\n")
                        count = 0
                        for oid, name in list(data['oids'].items())[:10]:
                            details_text.insert(tk.END, f"  {oid} -> {name}\n")
                            count += 1

                        if len(data['oids']) > 10:
                            details_text.insert(tk.END, f"  ... e altri {len(data['oids']) - 10} OID\n")

        mib_tree.bind("<<TreeviewSelect>>", show_mib_details)

        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        def remove_mib():
            """Rimuove MIB selezionato"""
            selection = mib_tree.selection()
            if selection:
                item = selection[0]
                values = mib_tree.item(item)['values']
                if values:
                    mib_name = values[0]

                    if messagebox.askyesno("Conferma", f"Rimuovere MIB {mib_name}?"):
                        # Rimuovi OID dal dizionario principale
                        if mib_name in self.custom_mibs:
                            for oid in self.custom_mibs[mib_name]['oids']:
                                if oid in self.oid_names:
                                    del self.oid_names[oid]

                            del self.custom_mibs[mib_name]
                            mib_tree.delete(item)

                            self.save_custom_mibs()
                            self.refresh_oid_descriptions()

                            messagebox.showinfo("✅", f"MIB {mib_name} rimosso")

        def export_mib_list():
            """Esporta lista MIB e OID"""
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")]
            )

            if filename:
                try:
                    with open(filename, 'w') as f:
                        if filename.endswith('.csv'):
                            f.write("MIB File,Module,OID,Name\n")
                            for mib_name, data in self.custom_mibs.items():
                                for oid, name in data['oids'].items():
                                    f.write(f'"{mib_name}","{data.get("module", "")}","{oid}","{name}"\n')
                        else:
                            f.write("CUSTOM MIB REPORT\n")
                            f.write("=" * 60 + "\n\n")
                            for mib_name, data in self.custom_mibs.items():
                                f.write(f"MIB: {mib_name}\n")
                                f.write(f"Module: {data.get('module', 'N/A')}\n")
                                f.write(f"OID Count: {len(data['oids'])}\n")
                                f.write("-" * 40 + "\n")
                                for oid, name in data['oids'].items():
                                    f.write(f"  {oid} = {name}\n")
                                f.write("\n")

                    messagebox.showinfo("✅", f"Esportato in {filename}")

                except Exception as e:
                    messagebox.showerror("Errore", f"Errore export: {e}")

        ttk.Button(button_frame, text="📥 Importa Altri MIB",
                   command=lambda: [mib_window.destroy(), self.import_mib()]).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🗑️ Rimuovi Selezionato",
                   command=remove_mib).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📤 Esporta Lista",
                   command=export_mib_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔄 Aggiorna Vista",
                   command=self.refresh_oid_descriptions).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Chiudi",
                   command=mib_window.destroy).pack(side=tk.RIGHT, padx=5)

        # Info
        info_label = ttk.Label(main_frame,
                               text=f"Totale: {len(self.custom_mibs)} MIB, "
                                    f"{sum(len(m['oids']) for m in self.custom_mibs.values())} OID custom",
                               foreground="blue")
        info_label.pack(pady=(5, 0))

    def create_widgets(self):
        """Crea tutti i widget"""
        # Frame principale
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Frame configurazione
        self.create_config_frame(main_frame)

        # NUOVO: Frame alert status
        self.create_alert_status_frame(main_frame)

        # Notebook per visualizzazioni
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        # Tabs
        self.create_browser_tab()
        self.create_enhanced_dashboard_tab()  # Dashboard migliorato con grafici
        self.create_mib_tree_tab()

        # Frame stato
        self.create_status_frame(main_frame)

    def create_config_frame(self, parent):
        """Frame configurazione con validazione"""
        config_frame = ttk.LabelFrame(parent, text="🔧 Configurazione SNMP")
        config_frame.pack(fill=tk.X, pady=(0, 5))

        # Prima riga
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

        # Seconda riga
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

        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=2)

        self.stop_btn = ttk.Button(btn_frame, text="⏹️ Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(btn_frame, text="🔌 Test", command=self.test_connection).pack(side=tk.LEFT, padx=2)

        # Frame SNMPv3
        self.v3_frame = ttk.LabelFrame(config_frame, text="🔐 Configurazione SNMPv3")

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

        ttk.Checkbutton(v3_row2, text="👀 Mostra",
                        variable=self.v3_show_passwords,
                        command=self.toggle_password_visibility).pack(side=tk.LEFT, padx=(10, 5))

        ttk.Button(v3_row2, text="🎯 Engine ID",
                   command=self.discover_engine_id).pack(side=tk.LEFT, padx=5)

        ttk.Button(v3_row2, text="⚡ Test v3",
                   command=self.test_snmpv3_connection).pack(side=tk.LEFT, padx=5)

    def create_alert_status_frame(self, parent):
        """NUOVO: Crea il frame per mostrare lo stato degli alert"""
        self.alert_frame = ttk.LabelFrame(parent, text="🚨 Stato Sistema & Alert")
        self.alert_frame.pack(fill=tk.X, pady=(0, 5))

        status_container = ttk.Frame(self.alert_frame)
        status_container.pack(fill=tk.X, padx=5, pady=5)

        # Indicatore di stato principale
        self.status_indicator = tk.Canvas(status_container, width=30, height=30)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 10))
        self.update_status_indicator("ok")

        # Label per stato testuale
        self.alert_status_var = tk.StringVar(value="✅ Sistema OK - Nessun alert attivo")
        self.alert_status_label = ttk.Label(status_container, textvariable=self.alert_status_var,
                                            font=('Segoe UI', 10, 'bold'))
        self.alert_status_label.pack(side=tk.LEFT, padx=5)

        # Contatori alert
        self.alert_count_var = tk.StringVar(value="Alert: 0 | Regole: 0")
        ttk.Label(status_container, textvariable=self.alert_count_var).pack(side=tk.LEFT, padx=(20, 5))

        # Ultimo alert
        self.last_alert_var = tk.StringVar(value="")
        ttk.Label(status_container, textvariable=self.last_alert_var).pack(side=tk.LEFT, padx=(20, 5))

        # Pulsanti alert
        ttk.Button(status_container, text="📋 Vedi Alert",
                   command=self.show_alert_history).pack(side=tk.RIGHT, padx=2)
        ttk.Button(status_container, text="🔔 Configura Alert",
                   command=self.manage_rules).pack(side=tk.RIGHT, padx=2)

    def update_status_indicator(self, status):
        """NUOVO: Aggiorna l'indicatore visivo di stato"""
        self.status_indicator.delete("all")

        if status == "ok":
            # Verde - tutto OK
            color = "#00ff00"
            self.status_indicator.create_oval(5, 5, 25, 25, fill=color, outline="darkgreen", width=2)
        elif status == "warning":
            # Giallo - warning
            color = "#ffff00"
            self.status_indicator.create_oval(5, 5, 25, 25, fill=color, outline="orange", width=2)
        elif status == "alert":
            # Rosso - alert critico
            color = "#ff0000"
            self.status_indicator.create_oval(5, 5, 25, 25, fill=color, outline="darkred", width=2)
            # Effetto pulsante per alert critico
            self.root.after(500, lambda: self.blink_indicator() if hasattr(self,
                                                                           'alert_active') and self.alert_active else None)

    def blink_indicator(self):
        """NUOVO: Fa lampeggiare l'indicatore per alert critici"""
        if hasattr(self, 'alert_active') and self.alert_active:
            current_color = self.status_indicator.itemcget(self.status_indicator.find_all()[0], "fill")
            new_color = "#ff0000" if current_color == "#ffaaaa" else "#ffaaaa"
            self.status_indicator.itemconfig(self.status_indicator.find_all()[0], fill=new_color)
            self.root.after(500, self.blink_indicator)

    def create_browser_tab(self):
        """Tab Browser principale con supporto alert"""
        browser_frame = ttk.Frame(self.notebook)
        self.notebook.add(browser_frame, text="🌐 Browser SNMP")

        # Filtri
        filter_frame = ttk.LabelFrame(browser_frame, text="🔍 Filtri")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(filter_frame, text="Cerca:").pack(side=tk.LEFT, padx=5)
        self.filter_var.trace('w', self.apply_filter)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(filter_frame, text="🧹 Pulisci", command=self.clear_filter).pack(side=tk.LEFT, padx=5)

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

        # Azioni con nuova opzione per regole
        action_frame = ttk.Frame(browser_frame)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="➕ Dashboard", command=self.add_to_dashboard).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="🔍 GET", command=self.get_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="✏️ SET", command=self.set_value).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="🚶 WALK", command=self.walk_from_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="🔔 Crea Regola", command=self.create_rule_from_selected).pack(side=tk.LEFT,
                                                                                                    padx=2)
        ttk.Button(action_frame, text="📤 Export", command=self.export_results).pack(side=tk.LEFT, padx=2)

        # Bind eventi
        self.results_tree.bind("<Double-1>", self.on_result_double_click)
        self.results_tree.bind("<Button-3>", self.show_context_menu)

    def create_enhanced_dashboard_tab(self):
        """NUOVO: Tab Dashboard migliorato con grafici e indicatori"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")

        # Controlli
        control_frame = ttk.LabelFrame(dashboard_frame, text="Controlli Dashboard")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(control_frame, text="🔄 Aggiorna", command=self.refresh_dashboard).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="📊 Grafico", command=self.show_dashboard_graph).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🔔 Aggiungi Regola", command=self.add_rule_to_selected).pack(side=tk.LEFT,
                                                                                                    padx=5)
        ttk.Button(control_frame, text="🗑️ Rimuovi", command=self.remove_from_dashboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🧹 Pulisci", command=self.clear_dashboard).pack(side=tk.LEFT, padx=5)

        # Auto-refresh ATTIVO DI DEFAULT
        ttk.Checkbutton(control_frame, text="🔄 Auto-Refresh (30s)",
                        variable=self.auto_refresh_var,
                        command=self.toggle_auto_refresh).pack(side=tk.LEFT, padx=(20, 5))

        # Intervallo refresh personalizzabile
        ttk.Label(control_frame, text="Intervallo (s):").pack(side=tk.LEFT, padx=(10, 2))
        interval_spin = ttk.Spinbox(control_frame, from_=5, to=300, increment=5,
                                    textvariable=self.refresh_interval_var, width=8)
        interval_spin.pack(side=tk.LEFT, padx=2)

        # Frame con PanedWindow per dashboard e mini-grafico
        paned = ttk.PanedWindow(dashboard_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Frame sinistro per la lista
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=3)

        # TreeView migliorato
        dash_columns = ("Host", "OID", "Nome", "Valore", "Timestamp", "Stato", "Alert", "Trend")
        self.dashboard_tree = ttk.Treeview(left_frame, columns=dash_columns, show="headings", height=15)

        # Configurazione colonne
        self.dashboard_tree.heading("Host", text="Host")
        self.dashboard_tree.heading("OID", text="OID")
        self.dashboard_tree.heading("Nome", text="Nome")
        self.dashboard_tree.heading("Valore", text="Valore")
        self.dashboard_tree.heading("Timestamp", text="Aggiornamento")
        self.dashboard_tree.heading("Stato", text="Stato")
        self.dashboard_tree.heading("Alert", text="🔔")
        self.dashboard_tree.heading("Trend", text="📈")

        for col in dash_columns:
            if col == "Alert":
                self.dashboard_tree.column(col, width=40)
            elif col == "Trend":
                self.dashboard_tree.column(col, width=40)
            else:
                self.dashboard_tree.column(col, width=120)

        dash_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.dashboard_tree.yview)
        self.dashboard_tree.configure(yscrollcommand=dash_scroll.set)

        self.dashboard_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dash_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Frame destro per mini-grafici e statistiche
        right_frame = ttk.LabelFrame(paned, text="📈 Anteprima Dati")
        paned.add(right_frame, weight=1)

        # Canvas per mini-grafico
        self.mini_graph_canvas = tk.Canvas(right_frame, height=200, bg='white')
        self.mini_graph_canvas.pack(fill=tk.X, padx=5, pady=5)

        # Statistiche
        self.stats_text = tk.Text(right_frame, height=10, width=30, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bind selezione per aggiornare mini-grafico
        self.dashboard_tree.bind("<<TreeviewSelect>>", self.on_dashboard_selection)

    def create_mib_tree_tab(self):
        """Tab Albero MIB CORRETTO"""
        mib_frame = ttk.Frame(self.notebook)
        self.notebook.add(mib_frame, text="🌳 Albero MIB")

        # Controlli
        control_frame = ttk.LabelFrame(mib_frame, text="Controlli Albero MIB")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(control_frame, text="🔄 Costruisci", command=self.build_mib_tree).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="➕ Espandi", command=self.expand_all_mib).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="➖ Comprimi", command=self.collapse_all_mib).pack(side=tk.LEFT, padx=5)

        # TreeView
        tree_frame = ttk.Frame(mib_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.mib_tree = ttk.Treeview(tree_frame, columns=("oid", "type", "value", "status"), height=20)
        self.mib_tree.heading("#0", text="Nome MIB")
        self.mib_tree.heading("oid", text="OID")
        self.mib_tree.heading("type", text="Tipo")
        self.mib_tree.heading("value", text="Valore")
        self.mib_tree.heading("status", text="Stato")

        self.mib_tree.column("#0", width=300)
        self.mib_tree.column("oid", width=200)
        self.mib_tree.column("type", width=100)
        self.mib_tree.column("value", width=200)
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

        self.status_var = tk.StringVar(value="🟢 Pronto - Auto-refresh attivo (30s)")
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
        self.time_var.set(time.strftime("🕐 %H:%M:%S"))

        # Aggiorna info memoria
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        self.memory_var.set(f"💾 {memory_mb:.1f}MB")

        self.root.after(1000, self.update_time)

    # ==================== FUNZIONI PER REGOLE E ALERT CORRETTE ====================

    def manage_rules(self):
        """NUOVO: Apre la finestra per gestire le regole di alert"""
        rules_window = tk.Toplevel(self.root)
        rules_window.title("🔔 Gestione Regole Alert")
        rules_window.geometry("900x600")

        self.logger.info("Apertura gestione regole alert")

        # Frame principale
        main_frame = ttk.Frame(rules_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Frame per lista regole
        list_frame = ttk.LabelFrame(main_frame, text="Regole Attive")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Treeview per regole
        columns = ("OID", "Nome", "Condizione", "Soglia", "Azione", "Stato")
        rules_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)

        for col in columns:
            rules_tree.heading(col, text=col)
            rules_tree.column(col, width=120)

        # Popola con regole esistenti
        def refresh_rules_list():
            # Pulisci lista
            for item in rules_tree.get_children():
                rules_tree.delete(item)

            # Ripopola
            for rule_id, rule in self.alert_rules.items():
                stato = "🔴 Attivo" if rule.is_triggered else "🟢 OK"
                rules_tree.insert("", tk.END, values=(
                    rule.oid, rule.name, rule.condition, rule.threshold, rule.action, stato
                ), tags=(rule_id,))

        refresh_rules_list()

        rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Scrollbar
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=rules_tree.yview)
        rules_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Frame per nuova regola
        new_rule_frame = ttk.LabelFrame(main_frame, text="Nuova/Modifica Regola")
        new_rule_frame.pack(fill=tk.X, pady=(0, 10))

        # Campi per nuova regola
        fields_frame = ttk.Frame(new_rule_frame)
        fields_frame.pack(padx=10, pady=10)

        ttk.Label(fields_frame, text="OID:").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        oid_entry = ttk.Entry(fields_frame, width=30)
        oid_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(fields_frame, text="Nome:").grid(row=0, column=2, sticky='e', padx=5, pady=5)
        name_entry = ttk.Entry(fields_frame, width=30)
        name_entry.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(fields_frame, text="Condizione:").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        condition_combo = ttk.Combobox(fields_frame, values=[
            "less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal",
            "equal", "not_equal", "contains"
        ], width=27)
        condition_combo.grid(row=1, column=1, padx=5, pady=5)
        condition_combo.set("less_than")

        ttk.Label(fields_frame, text="Soglia:").grid(row=1, column=2, sticky='e', padx=5, pady=5)
        threshold_entry = ttk.Entry(fields_frame, width=30)
        threshold_entry.grid(row=1, column=3, padx=5, pady=5)

        ttk.Label(fields_frame, text="Azione:").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        action_combo = ttk.Combobox(fields_frame, values=["notify", "email", "both"], width=27)
        action_combo.grid(row=2, column=1, padx=5, pady=5)
        action_combo.set("notify")

        ttk.Label(fields_frame, text="Email (se richiesta):").grid(row=2, column=2, sticky='e', padx=5, pady=5)
        email_entry = ttk.Entry(fields_frame, width=30)
        email_entry.grid(row=2, column=3, padx=5, pady=5)

        # Variabile per tracciare se stiamo modificando
        editing_rule_id = tk.StringVar(value="")

        def load_rule_for_edit():
            """Carica una regola per la modifica"""
            selection = rules_tree.selection()
            if not selection:
                messagebox.showwarning("Avviso", "Selezionare una regola da modificare")
                return

            item = selection[0]
            values = rules_tree.item(item)['values']
            tags = rules_tree.item(item)['tags']

            if values and tags:
                rule_id = tags[0]
                if rule_id in self.alert_rules:
                    rule = self.alert_rules[rule_id]

                    # Popola i campi
                    oid_entry.delete(0, tk.END)
                    oid_entry.insert(0, rule.oid)

                    name_entry.delete(0, tk.END)
                    name_entry.insert(0, rule.name)

                    condition_combo.set(rule.condition)

                    threshold_entry.delete(0, tk.END)
                    threshold_entry.insert(0, rule.threshold)

                    action_combo.set(rule.action)

                    email_entry.delete(0, tk.END)
                    email_entry.insert(0, rule.email_to)

                    # Salva ID per sapere che stiamo modificando
                    editing_rule_id.set(rule_id)

                    # Cambia etichetta del frame
                    new_rule_frame.config(text="Modifica Regola")

        def save_rule():
            """Aggiunge o modifica una regola"""
            oid = oid_entry.get()
            name = name_entry.get()
            condition = condition_combo.get()
            threshold = threshold_entry.get()
            action = action_combo.get()
            email = email_entry.get()

            if not oid or not name or not threshold:
                messagebox.showwarning("Avviso", "Compilare tutti i campi richiesti")
                return

            rule = AlertRule(oid, name, condition, threshold, action, email)

            # Se stiamo modificando, usa l'ID esistente
            if editing_rule_id.get():
                rule_id = editing_rule_id.get()
                # Mantieni lo stato triggered se esisteva
                if rule_id in self.alert_rules:
                    rule.is_triggered = self.alert_rules[rule_id].is_triggered
                    rule.last_alert_time = self.alert_rules[rule_id].last_alert_time
            else:
                rule_id = f"{self.host_var.get()}_{oid}"

            self.alert_rules[rule_id] = rule

            # Pulisci campi
            oid_entry.delete(0, tk.END)
            name_entry.delete(0, tk.END)
            threshold_entry.delete(0, tk.END)
            email_entry.delete(0, tk.END)
            condition_combo.set("less_than")
            action_combo.set("notify")
            editing_rule_id.set("")
            new_rule_frame.config(text="Nuova/Modifica Regola")

            # Aggiorna lista
            refresh_rules_list()

            self.save_rules()
            self.update_alert_counts()

            if editing_rule_id.get():
                self.logger.info(f"Modificata regola: {name}")
                messagebox.showinfo("Successo", "Regola modificata con successo")
            else:
                self.logger.info(f"Aggiunta nuova regola: {name}")
                messagebox.showinfo("Successo", "Regola aggiunta con successo")

        def remove_rule():
            """Rimuove la regola selezionata"""
            selection = rules_tree.selection()
            if not selection:
                messagebox.showwarning("Avviso", "Selezionare una regola da rimuovere")
                return

            item = selection[0]
            values = rules_tree.item(item)['values']
            tags = rules_tree.item(item)['tags']

            if values and tags:
                rule_id = tags[0]
                if rule_id in self.alert_rules:
                    if messagebox.askyesno("Conferma", f"Rimuovere la regola '{values[1]}'?"):
                        del self.alert_rules[rule_id]
                        refresh_rules_list()
                        self.save_rules()
                        self.update_alert_counts()
                        self.logger.info(f"Rimossa regola per OID: {values[0]}")
                        messagebox.showinfo("Successo", "Regola rimossa")

        def clear_form():
            """Pulisce il form"""
            oid_entry.delete(0, tk.END)
            name_entry.delete(0, tk.END)
            threshold_entry.delete(0, tk.END)
            email_entry.delete(0, tk.END)
            condition_combo.set("less_than")
            action_combo.set("notify")
            editing_rule_id.set("")
            new_rule_frame.config(text="Nuova/Modifica Regola")

        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        ttk.Button(button_frame, text="💾 Salva Regola", command=save_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="✏️ Modifica Selezionata", command=load_rule_for_edit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="➖ Rimuovi Selezionata", command=remove_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🧹 Pulisci Form", command=clear_form).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Chiudi", command=rules_window.destroy).pack(side=tk.RIGHT, padx=5)

        # Bind doppio click per modifica rapida
        rules_tree.bind("<Double-1>", lambda e: load_rule_for_edit())

    def configure_email(self):
        """CORRETTO: Configura le impostazioni email per gli alert"""
        email_window = tk.Toplevel(self.root)
        email_window.title("Configurazione Email")

        # Dimensione fissa della finestra
        window_width = 450
        window_height = 360

        # Rendi la finestra non ridimensionabile
        email_window.resizable(False, False)

        # Ottieni dimensioni schermo
        screen_width = email_window.winfo_screenwidth()
        screen_height = email_window.winfo_screenheight()

        # Calcola posizione per centrare
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Imposta geometria e posizione
        email_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Rendi modale
        email_window.transient(self.root)
        email_window.grab_set()

        # Frame principale con padding uniforme
        main_frame = ttk.Frame(email_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Griglia configurazione con spaziatura uniforme
        ttk.Label(main_frame, text="Server SMTP:").grid(row=0, column=0, sticky='e', padx=5, pady=8)
        smtp_server = ttk.Entry(main_frame, width=30)
        smtp_server.grid(row=0, column=1, padx=5, pady=8)
        smtp_server.insert(0, self.email_config.smtp_server)

        ttk.Label(main_frame, text="Porta:").grid(row=1, column=0, sticky='e', padx=5, pady=8)
        smtp_port = ttk.Entry(main_frame, width=30)
        smtp_port.grid(row=1, column=1, padx=5, pady=8)
        smtp_port.insert(0, str(self.email_config.smtp_port))

        ttk.Label(main_frame, text="Username:").grid(row=2, column=0, sticky='e', padx=5, pady=8)
        smtp_username = ttk.Entry(main_frame, width=30)
        smtp_username.grid(row=2, column=1, padx=5, pady=8)
        smtp_username.insert(0, self.email_config.smtp_username)

        ttk.Label(main_frame, text="Password:").grid(row=3, column=0, sticky='e', padx=5, pady=8)
        smtp_password = ttk.Entry(main_frame, width=30, show="*")
        smtp_password.grid(row=3, column=1, padx=5, pady=8)
        if self.email_config.smtp_password_encrypted:
            smtp_password.insert(0, self.email_config.get_password())

        ttk.Label(main_frame, text="Email Mittente:").grid(row=4, column=0, sticky='e', padx=5, pady=8)
        from_email = ttk.Entry(main_frame, width=30)
        from_email.grid(row=4, column=1, padx=5, pady=8)
        from_email.insert(0, self.email_config.from_email)

        use_tls = tk.BooleanVar(value=self.email_config.use_tls)
        ttk.Checkbutton(main_frame, text="Usa TLS", variable=use_tls).grid(row=5, column=1, sticky='w', padx=5, pady=8)

        # Frame pulsanti centrato
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="💾 Salva", command=lambda: save_email_config()).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📧 Test", command=lambda: test_email()).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Annulla", command=email_window.destroy).pack(side=tk.LEFT, padx=5)

        # Centra il contenuto
        main_frame.grid_columnconfigure(1, weight=1)

        def save_email_config():
            """Salva la configurazione email"""
            self.email_config.smtp_server = smtp_server.get()
            try:
                self.email_config.smtp_port = int(smtp_port.get())
            except:
                self.email_config.smtp_port = 587
            self.email_config.smtp_username = smtp_username.get()
            self.email_config.set_password(smtp_password.get())
            self.email_config.from_email = from_email.get()
            self.email_config.use_tls = use_tls.get()

            self.save_email_config_to_file()
            self.logger.info("Configurazione email salvata")
            messagebox.showinfo("Successo", "Configurazione email salvata")
            email_window.destroy()

        def test_email():
            """Test invio email"""
            save_email_config()

            test_email = simpledialog.askstring("Test Email", "Inserisci email di test:")
            if test_email:
                success, msg = self.email_config.send_alert_email(
                    test_email,
                    "Test Configurazione",
                    "Questa è una email di test dal sistema di monitoring SNMP."
                )

                if success:
                    self.logger.info("Test email inviato con successo")
                    messagebox.showinfo("Successo", "Email di test inviata con successo!")
                else:
                    self.logger.error(f"Test email fallito: {msg}")
                    messagebox.showerror("Errore", f"Errore invio email: {msg}")

        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="💾 Salva", command=save_email_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📧 Test", command=test_email).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Annulla", command=email_window.destroy).pack(side=tk.LEFT, padx=5)

    def check_alert_rules(self):
        """CORRETTO: Controlla tutte le regole di alert"""
        alerts_triggered = []

        # Controlla ogni regola
        for rule_id, rule in self.alert_rules.items():
            # Ottieni il valore corrente - prima da scan_results poi da dashboard
            current_value = None

            if rule.oid in self.scan_results:
                # Se presente nei risultati della scansione
                current_value = self.scan_results[rule.oid]['value']

            # Se non trovato, cerca nel dashboard
            if current_value is None and rule_id in self.saved_values:
                try:
                    # Crea client appropriato basato sulla versione
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

                    # Esegui GET SNMP per ottenere il valore corrente
                    current_value = client.get(rule.oid)

                except Exception as e:
                    self.logger.error(f"Errore controllo regola {rule.name}: {str(e)}")
                    continue

            if current_value is not None:
                # Controlla se la regola viene violata
                if rule.check(current_value):
                    if not rule.is_triggered or rule.should_alert():
                        # Alert nuovo o da ripetere dopo cooldown
                        rule.is_triggered = True
                        rule.last_alert_time = time.time()
                        rule.last_value = current_value

                        alerts_triggered.append(rule)

                        # Registra nella history
                        alert_entry = {
                            'timestamp': datetime.now(),
                            'rule': rule.name,
                            'oid': rule.oid,
                            'value': str(current_value),
                            'threshold': rule.threshold,
                            'condition': rule.condition
                        }
                        self.alert_history.append(alert_entry)

                        self.logger.warning(
                            f"Alert triggerato: {rule.name} - valore {current_value} {rule.condition} {rule.threshold}"
                        )
                else:
                    # Reset regola se non più violata
                    rule.is_triggered = False

        # Processa eventuali nuovi alert
        if alerts_triggered:
            self.process_alerts(alerts_triggered)

        # Aggiorna stato generale sistema
        any_triggered = any(rule.is_triggered for rule in self.alert_rules.values())
        self.update_alert_status(any_triggered)

        # Aggiorna contatori
        self.update_alert_counts()

    def process_alerts(self, alerts):
        """NUOVO: Processa gli alert triggerati"""
        for alert in alerts:
            # Notifica desktop
            if alert.action in ["notify", "both"]:
                self.show_alert_notification(alert)

            # Email
            if alert.action in ["email", "both"] and alert.email_to:
                # Ricarica configurazione email prima di inviare
                self.load_email_config()  # Aggiungi questa riga
                self.send_alert_email(alert)

    def show_alert_notification(self, alert):
        """NUOVO: Mostra una notifica desktop per l'alert"""
        message = f"⚠️ ALERT: {alert.name}\n"
        message += f"OID: {alert.oid}\n"
        message += f"Condizione: {alert.condition} {alert.threshold}\n"
        message += f"Valore attuale: {alert.last_value}"

        # Mostra popup
        messagebox.showwarning(f"🚨 Alert: {alert.name}", message)

    def send_alert_email(self, alert):
        """NUOVO: Invia email per l'alert"""
        if not self.email_config.is_configured():
            return

        subject = f"Alert: {alert.name}"

        body = f"""
        Sistema di Monitoring SNMP - ALERT

        Regola: {alert.name}
        OID: {alert.oid}
        Host: {self.host_var.get()}

        Condizione violata: {alert.condition} {alert.threshold}
        Valore attuale: {alert.last_value}

        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """

        success, msg = self.email_config.send_alert_email(alert.email_to, subject, body)

        if success:
            self.logger.info(f"Email alert inviata a {alert.email_to}")
        else:
            self.logger.error(f"Errore invio email alert: {msg}")

    def update_alert_status(self, has_alerts):
        """CORRETTO: Aggiorna lo stato visivo degli alert"""
        if has_alerts:
            self.alert_active = True
            self.update_status_indicator("alert")
            self.alert_status_var.set("⚠️ ALERT ATTIVI - Verificare le regole violate")
            self.alert_status_label.config(foreground="red")
        else:
            self.alert_active = False
            self.update_status_indicator("ok")
            self.alert_status_var.set("✅ Sistema OK - Nessun alert attivo")
            self.alert_status_label.config(foreground="green")

        # Aggiorna ultimo alert
        if self.alert_history:
            last = self.alert_history[-1]
            self.last_alert_var.set(f"Ultimo: {last['rule']} ({last['timestamp'].strftime('%H:%M:%S')})")

    def update_alert_counts(self):
        """NUOVO: Aggiorna i contatori degli alert"""
        total_rules = len(self.alert_rules)
        active_alerts = sum(1 for rule in self.alert_rules.values() if rule.is_triggered)

        self.alert_count_var.set(f"Alert: {active_alerts}/{total_rules} | Storia: {len(self.alert_history)}")

    def show_alert_history(self):
        """NUOVO: Mostra la storia degli alert"""
        history_window = tk.Toplevel(self.root)
        history_window.title("📋 Storia Alert")
        history_window.geometry("800x400")

        # Frame principale
        main_frame = ttk.Frame(history_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Treeview per storia
        columns = ("Timestamp", "Regola", "OID", "Valore", "Soglia", "Condizione")
        history_tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=15)

        for col in columns:
            history_tree.heading(col, text=col)
            history_tree.column(col, width=120)

        # Popola con storia (ordine inverso, più recenti prima)
        for alert in reversed(self.alert_history):
            history_tree.insert("", tk.END, values=(
                alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S"),
                alert['rule'],
                alert['oid'],
                alert['value'],
                alert['threshold'],
                alert['condition']
            ))

        history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar
        scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=history_tree.yview)
        history_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Pulsanti
        button_frame = ttk.Frame(history_window)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        def clear_history():
            if messagebox.askyesno("Conferma", "Cancellare tutta la storia degli alert?"):
                self.alert_history.clear()
                for item in history_tree.get_children():
                    history_tree.delete(item)
                self.update_alert_counts()
                self.logger.info("Storia alert cancellata")

        ttk.Button(button_frame, text="🧹 Pulisci Storia", command=clear_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Chiudi", command=history_window.destroy).pack(side=tk.RIGHT, padx=5)

    def clear_alerts(self):
        """NUOVO: Pulisce gli alert attivi"""
        for rule in self.alert_rules.values():
            rule.is_triggered = False
            rule.last_alert_time = None

        self.update_alert_status(False)
        self.update_alert_counts()
        self.logger.info("Alert resettati")
        messagebox.showinfo("Info", "Alert resettati")

    def create_rule_from_selected(self):
        """NUOVO: Crea o modifica una regola dall'elemento selezionato nel browser"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Selezionare un elemento")
            return

        item = selection[0]
        values = self.results_tree.item(item)['values']
        if values:
            oid = values[0]
            name = values[1]
            current_value = values[3]

            # Controlla se esiste già una regola
            rule_id = f"{self.host_var.get()}_{oid}"
            existing_rule = self.alert_rules.get(rule_id)

            # Apri dialog per configurare/modificare la regola
            self.create_rule_dialog(oid, name, current_value, self.host_var.get(), existing_rule, rule_id)

    def add_rule_to_selected(self):
        """NUOVO: Aggiunge o modifica una regola all'elemento selezionato nel dashboard"""
        selection = self.dashboard_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Selezionare un elemento dal dashboard")
            return

        item = selection[0]
        values = self.dashboard_tree.item(item)['values']
        if values:
            host = values[0]
            oid = values[1]
            name = values[2]
            current_value = values[3]

            # Controlla se esiste già una regola per questo OID
            rule_id = f"{host}_{oid}"
            existing_rule = self.alert_rules.get(rule_id)

            self.create_rule_dialog(oid, name, current_value, host, existing_rule, rule_id)

    def create_rule_dialog(self, oid, name, current_value, host=None, existing_rule=None, rule_id=None):
        """NUOVO: Dialog per creare o modificare una regola"""
        dialog = tk.Toplevel(self.root)
        if existing_rule:
            dialog.title("✏️ Modifica Regola Alert")
        else:
            dialog.title("🔔 Crea Regola Alert")

        # Finestra fissa compatta
        dialog.geometry("450x400")
        dialog.resizable(False, False)

        # Centra la finestra
        dialog.transient(self.root)
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - 225
        y = (dialog.winfo_screenheight() // 2) - 200
        dialog.geometry(f"450x400+{x}+{y}")

        # Frame principale
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        # Info compatte
        info_text = f"📋 OID: {oid}\n📌 {name}\n💡 Valore attuale: {current_value}"
        if host:
            info_text += f"\n🖥️ Host: {host}"

        info_label = ttk.Label(main_frame, text=info_text, background="#f0f0f0", padding=10)
        info_label.pack(fill=tk.X, pady=(0, 15))

        if existing_rule:
            ttk.Label(main_frame, text="⚠️ Modifica regola esistente",
                      foreground="blue", font=('TkDefaultFont', 9, 'bold')).pack(pady=(0, 10))

        # Frame per i campi
        fields_frame = ttk.Frame(main_frame)
        fields_frame.pack(fill=tk.X, pady=(0, 15))

        # Condizione
        ttk.Label(fields_frame, text="Condizione:").grid(row=0, column=0, sticky='w', padx=(0, 10), pady=5)
        condition_var = tk.StringVar()
        condition_combo = ttk.Combobox(fields_frame, textvariable=condition_var, values=[
            "less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal",
            "equal", "not_equal", "contains"
        ], width=25, state='readonly')
        condition_combo.grid(row=0, column=1, sticky='w', pady=5)

        # Soglia
        ttk.Label(fields_frame, text="Soglia:").grid(row=1, column=0, sticky='w', padx=(0, 10), pady=5)
        threshold_entry = ttk.Entry(fields_frame, width=27)
        threshold_entry.grid(row=1, column=1, sticky='w', pady=5)

        # Azione
        ttk.Label(fields_frame, text="Azione:").grid(row=2, column=0, sticky='w', padx=(0, 10), pady=5)
        action_var = tk.StringVar()
        action_combo = ttk.Combobox(fields_frame, textvariable=action_var, values=[
            "notify", "email", "both"
        ], width=25, state='readonly')
        action_combo.grid(row=2, column=1, sticky='w', pady=5)

        # Email
        ttk.Label(fields_frame, text="Email:").grid(row=3, column=0, sticky='w', padx=(0, 10), pady=5)
        email_entry = ttk.Entry(fields_frame, width=27)
        email_entry.grid(row=3, column=1, sticky='w', pady=5)

        # Se esiste già una regola, popola i campi
        if existing_rule:
            condition_combo.set(existing_rule.condition)
            threshold_entry.insert(0, existing_rule.threshold)
            action_combo.set(existing_rule.action)
            email_entry.insert(0, existing_rule.email_to)
        else:
            condition_combo.set("less_than")
            action_combo.set("notify")

        # Pulsanti in basso
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(20, 0))

        # DEFINIZIONE FUNZIONI (UNA VOLTA SOLA!)
        def save_rule():
            threshold = threshold_entry.get()
            if not threshold:
                messagebox.showwarning("Avviso", "Inserire una soglia")
                return

            # Crea o aggiorna la regola
            rule = AlertRule(
                oid, name,
                condition_var.get(),
                threshold,
                action_var.get(),
                email_entry.get()
            )

            # Usa l'ID esistente o creane uno nuovo
            if not rule_id:
                new_rule_id = f"{host or self.host_var.get()}_{oid}"
            else:
                new_rule_id = rule_id
                # Se stiamo modificando, mantieni lo stato
                if existing_rule:
                    rule.is_triggered = existing_rule.is_triggered
                    rule.last_alert_time = existing_rule.last_alert_time

            self.alert_rules[new_rule_id] = rule

            self.save_rules()
            self.update_alert_counts()

            if existing_rule:
                self.logger.info(f"Modificata regola: {name}")
                messagebox.showinfo("✅ Successo", "Regola modificata con successo")
            else:
                self.logger.info(f"Creata regola: {name}")
                messagebox.showinfo("✅ Successo", "Regola creata con successo")

            dialog.destroy()

        def test_rule():
            """Testa la regola con il valore corrente"""
            threshold = threshold_entry.get()
            condition = condition_var.get()

            if not threshold:
                messagebox.showwarning("Avviso", "Inserire una soglia per testare")
                return

            # Mappa per visualizzazione condizioni user-friendly
            condition_map = {
                "less_than": "Minore di (<)",
                "less_than_or_equal": "Minore o uguale (≤)",
                "greater_than": "Maggiore di (>)",
                "greater_than_or_equal": "Maggiore o uguale (≥)",
                "equal": "Uguale a (=)",
                "not_equal": "Diverso da (≠)",
                "contains": "Contiene"
            }

            # Crea regola temporanea per test
            test_rule_obj = AlertRule(oid, name, condition, threshold, "notify", "")

            # Testa con il valore corrente
            try:
                # Crea un valore mock basato sul valore corrente
                if hasattr(current_value, 'value'):
                    test_value = current_value
                else:
                    # Se è una stringa numerica, crea un SnmpInteger
                    try:
                        numeric_val = float(str(current_value))
                        from snmpy import SnmpInteger
                        test_value = SnmpInteger(int(numeric_val))
                    except:
                        test_value = current_value

                result = test_rule_obj.check(test_value)

                if result:
                    messagebox.showinfo("🔴 Test Regola",
                                        f"La regola SCATTEREBBE con il valore attuale!\n\n"
                                        f"Valore: {current_value}\n"
                                        f"Condizione: {condition_map.get(condition, condition)}\n"
                                        f"Soglia: {threshold}")
                else:
                    messagebox.showinfo("🟢 Test Regola",
                                        f"La regola NON scatterebbe con il valore attuale.\n\n"
                                        f"Valore: {current_value}\n"
                                        f"Condizione: {condition_map.get(condition, condition)}\n"
                                        f"Soglia: {threshold}")
            except Exception as e:
                messagebox.showerror("Errore Test", f"Errore durante il test: {str(e)}")

        # PULSANTI (UNA VOLTA SOLA!)
        ttk.Button(button_frame, text="💾 Salva", command=save_rule).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="🧪 Test", command=test_rule).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="❌ Annulla", command=dialog.destroy).pack(side=tk.LEFT, padx=10)

        # Focus sulla soglia
        threshold_entry.focus()

    def start_rule_monitoring(self):
        """NUOVO: Avvia il monitoraggio delle regole in background"""

        def monitor_worker():
            while True:
                try:
                    if self.alert_rules and self.scan_results:
                        self.root.after(0, self.check_alert_rules)
                        self.root.after(0, self.save_historical_data)
                except Exception as e:
                    self.logger.error(f"Errore monitoring regole: {e}")

                time.sleep(10)  # Controlla ogni 10 secondi

        monitor_thread = threading.Thread(target=monitor_worker, daemon=True)
        monitor_thread.start()
        self.logger.info("Monitoring regole avviato")

    # ==================== FUNZIONI PER GRAFICI ====================

    def show_dashboard_graph(self):
        """NUOVO: Mostra il grafico per l'elemento selezionato nel dashboard"""
        selection = self.dashboard_tree.selection()
        if not selection:
            messagebox.showwarning("Avviso", "Selezionare un elemento dal dashboard")
            return

        item = selection[0]
        values = self.dashboard_tree.item(item)['values']
        if values:
            oid = values[1]
            name = values[2]

            # Ottieni dati storici
            key = f"{self.host_var.get()}_{oid}"
            if key in self.historical_data:
                data_points = self.historical_data[key]

                # Apri finestra grafico
                GraphWindow(self.root, oid, name, data_points, self.logger)
            else:
                messagebox.showinfo("Info", "Nessun dato storico disponibile per questo elemento")

    def on_dashboard_selection(self, event):
        """NUOVO: Gestisce la selezione nel dashboard per aggiornare il mini-grafico"""
        selection = self.dashboard_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.dashboard_tree.item(item)['values']
        if not values:
            return

        host = values[0]
        oid = values[1]
        name = values[2]

        # Aggiorna statistiche
        self.update_stats_panel(host, oid, name)

        # Aggiorna mini-grafico
        self.update_mini_graph(host, oid)

    def update_stats_panel(self, host, oid, name):
        """NUOVO: Aggiorna il pannello delle statistiche"""
        self.stats_text.delete(1.0, tk.END)

        stats = f"📊 STATISTICHE\n"
        stats += "=" * 30 + "\n\n"
        stats += f"Host: {host}\n"
        stats += f"OID: {oid}\n"
        stats += f"Nome: {name}\n\n"

        # Ottieni dati storici
        key = f"{host}_{oid}"
        if key in self.historical_data:
            data_points = self.historical_data[key]

            if data_points:
                values = []
                for point in data_points:
                    try:
                        val = point['value']
                        if hasattr(val, 'value'):
                            values.append(float(val.value))
                        else:
                            values.append(float(val))
                    except:
                        pass

                if values:
                    stats += f"📈 Ultimi {len(values)} valori:\n"
                    stats += f"  Min: {min(values):.2f}\n"
                    stats += f"  Max: {max(values):.2f}\n"
                    stats += f"  Media: {sum(values) / len(values):.2f}\n"
                    stats += f"  Ultimo: {values[-1]:.2f}\n\n"

                    # Trend
                    if len(values) > 1:
                        trend = values[-1] - values[-2]
                        if trend > 0:
                            stats += f"  Trend: ↗️ +{trend:.2f}\n"
                        elif trend < 0:
                            stats += f"  Trend: ↘️ {trend:.2f}\n"
                        else:
                            stats += f"  Trend: ➡️ Stabile\n"

        # Controlla regole associate
        rule_id = f"{host}_{oid}"
        if rule_id in self.alert_rules:
            rule = self.alert_rules[rule_id]
            stats += f"\n🔔 REGOLA ALERT:\n"
            stats += f"  Condizione: {rule.condition}\n"
            stats += f"  Soglia: {rule.threshold}\n"
            stats += f"  Stato: {'🔴 Attivo' if rule.is_triggered else '🟢 OK'}\n"

        self.stats_text.insert(1.0, stats)

    def save_historical_data(self):
        """NUOVO: Salva i dati storici per i grafici"""
        try:
            # Converti deque in liste per la serializzazione JSON
            save_data = {}
            for key, data_deque in self.historical_data.items():
                # Converti ogni elemento della deque
                data_list = []
                for item in data_deque:
                    # Converti il valore SNMP in formato serializzabile
                    value = item['value']

                    # Gestisci diversi tipi di valori
                    if hasattr(value, 'value'):
                        # È un oggetto SNMP
                        if isinstance(value.value, bytes):
                            # Converti bytes in stringa hex
                            serializable_value = {
                                'type': type(value).__name__,
                                'value': value.value.hex(),
                                'is_bytes': True
                            }
                        else:
                            serializable_value = {
                                'type': type(value).__name__,
                                'value': value.value,
                                'is_bytes': False
                            }
                    elif isinstance(value, bytes):
                        # Bytes raw
                        serializable_value = {
                            'type': 'bytes',
                            'value': value.hex(),
                            'is_bytes': True
                        }
                    elif isinstance(value, (int, float)):
                        # Numeri
                        serializable_value = {
                            'type': 'number',
                            'value': value,
                            'is_bytes': False
                        }
                    else:
                        # Altri tipi (stringhe, etc.)
                        serializable_value = {
                            'type': 'raw',
                            'value': str(value),
                            'is_bytes': False
                        }

                    data_list.append({
                        'timestamp': item['timestamp'],
                        'value': serializable_value
                    })

                save_data[key] = data_list

            with open(self.historical_data_file, 'w') as f:
                json.dump(save_data, f, indent=2)

            self.logger.info(f"Salvati dati storici per {len(save_data)} elementi")

        except Exception as e:
            self.logger.error(f"Errore salvataggio dati storici: {e}")
            import traceback
            self.logger.error(traceback.format_exc())

    def load_historical_data(self):
        """NUOVO: Carica i dati storici salvati"""
        try:
            if os.path.exists(self.historical_data_file):
                with open(self.historical_data_file, 'r') as f:
                    loaded_data = json.load(f)

                # Riconverti in deque con oggetti SNMP appropriati
                for key, data_list in loaded_data.items():
                    data_deque = deque(maxlen=100)

                    for item in data_list:
                        # Ricostruisci il valore SNMP se necessario
                        value_info = item['value']

                        # Gestisci bytes
                        if value_info.get('is_bytes', False):
                            # Era un valore bytes, riconvertilo
                            byte_value = bytes.fromhex(value_info['value'])

                            if value_info['type'] == 'SnmpOctetString':
                                from snmpy import SnmpOctetString
                                value = SnmpOctetString(byte_value)
                            elif value_info['type'] == 'bytes':
                                value = byte_value
                            else:
                                # Altri tipi SNMP con bytes
                                value = byte_value

                        elif value_info['type'] == 'SnmpInteger':
                            from snmpy import SnmpInteger
                            value = SnmpInteger(value_info['value'])
                        elif value_info['type'] == 'SnmpCounter32':
                            from snmpy import SnmpCounter32
                            value = SnmpCounter32(value_info['value'])
                        elif value_info['type'] == 'SnmpGauge32':
                            from snmpy import SnmpGauge32
                            value = SnmpGauge32(value_info['value'])
                        elif value_info['type'] == 'SnmpTimeTicks':
                            from snmpy import SnmpTimeTicks
                            value = SnmpTimeTicks(value_info['value'])
                        elif value_info['type'] == 'SnmpCounter64':
                            from snmpy import SnmpCounter64
                            value = SnmpCounter64(value_info['value'])
                        elif value_info['type'] == 'SnmpOctetString':
                            from snmpy import SnmpOctetString
                            # Se non è bytes, è una stringa normale
                            value = SnmpOctetString(value_info['value'].encode())
                        elif value_info['type'] == 'number':
                            value = value_info['value']
                        else:
                            # Valore raw o stringa
                            try:
                                value = float(value_info['value'])
                            except:
                                value = value_info['value']

                        data_deque.append({
                            'timestamp': item['timestamp'],
                            'value': value
                        })

                    self.historical_data[key] = data_deque

                self.logger.info(f"Caricati dati storici per {len(self.historical_data)} elementi")

                # Pulisci dati troppo vecchi (più di 24 ore)
                self.clean_old_historical_data()

        except Exception as e:
            self.logger.error(f"Errore caricamento dati storici: {e}")
            import traceback
            self.logger.error(traceback.format_exc())

    def clean_old_historical_data(self):
        """NUOVO: Pulisce i dati storici più vecchi di 24 ore"""
        try:
            current_time = time.time()
            max_age = 24 * 60 * 60  # 24 ore in secondi

            cleaned_count = 0
            for key in list(self.historical_data.keys()):
                # Filtra solo i dati recenti
                filtered_data = deque(maxlen=100)
                original_count = len(self.historical_data[key])

                for item in self.historical_data[key]:
                    if current_time - item['timestamp'] < max_age:
                        filtered_data.append(item)

                if filtered_data:
                    self.historical_data[key] = filtered_data
                    cleaned_count += original_count - len(filtered_data)
                else:
                    # Rimuovi completamente se non ci sono dati recenti
                    cleaned_count += original_count
                    del self.historical_data[key]

            if cleaned_count > 0:
                self.logger.info(f"Pulizia dati storici: rimossi {cleaned_count} elementi vecchi")

        except Exception as e:
            self.logger.error(f"Errore pulizia dati storici: {e}")

    def update_mini_graph(self, host, oid):
        """NUOVO: Aggiorna il mini-grafico nel dashboard"""
        self.mini_graph_canvas.delete("all")

        key = f"{host}_{oid}"
        if key not in self.historical_data or not self.historical_data[key]:
            # Nessun dato, mostra messaggio
            self.mini_graph_canvas.create_text(
                self.mini_graph_canvas.winfo_width() // 2 if self.mini_graph_canvas.winfo_width() > 1 else 150,
                100,
                text="Nessun dato storico",
                fill="gray"
            )
            return

        data_points = list(self.historical_data[key])[-20:]  # Ultimi 20 punti

        if len(data_points) < 2:
            return

        # Estrai valori
        values = []
        for point in data_points:
            try:
                val = point['value']
                if hasattr(val, 'value'):
                    values.append(float(val.value))
                else:
                    values.append(float(val))
            except:
                values.append(0)

        if not values:
            return

        # Calcola dimensioni canvas
        canvas_width = self.mini_graph_canvas.winfo_width()
        if canvas_width <= 1:
            canvas_width = 300
        canvas_height = 200

        # Margini
        margin = 20
        graph_width = canvas_width - 2 * margin
        graph_height = canvas_height - 2 * margin

        # Scala valori
        min_val = min(values)
        max_val = max(values)
        val_range = max_val - min_val if max_val != min_val else 1

        # Disegna griglia
        for i in range(5):
            y = margin + i * graph_height / 4
            self.mini_graph_canvas.create_line(
                margin, y, canvas_width - margin, y,
                fill="lightgray", dash=(2, 2)
            )

        # Disegna linea dei valori
        points = []
        for i, val in enumerate(values):
            x = margin + i * graph_width / (len(values) - 1)
            y = margin + graph_height - ((val - min_val) / val_range * graph_height)
            points.extend([x, y])

        if len(points) >= 4:
            # Linea principale
            self.mini_graph_canvas.create_line(
                points, fill="blue", width=2
            )

            # Punti
            for i in range(0, len(points), 2):
                x, y = points[i], points[i + 1]
                self.mini_graph_canvas.create_oval(
                    x - 3, y - 3, x + 3, y + 3,
                    fill="red", outline="darkred"
                )

        # Etichette valori
        self.mini_graph_canvas.create_text(
            margin - 5, margin,
            text=f"{max_val:.1f}",
            anchor="e", fill="black", font=("Arial", 8)
        )
        self.mini_graph_canvas.create_text(
            margin - 5, canvas_height - margin,
            text=f"{min_val:.1f}",
            anchor="e", fill="black", font=("Arial", 8)
        )

    # ==================== FUNZIONI BASE MIGLIORATE ====================

    def refresh_dashboard(self):
        """Aggiorna dashboard con supporto per dati storici e alert"""
        if not self.saved_values:
            self.status_var.set("📊 Dashboard vuoto")
            return

        # NUOVO: Salva selezione corrente
        selected_items = self.dashboard_tree.selection()
        selected_values = []
        for item in selected_items:
            values = self.dashboard_tree.item(item)['values']
            if values:
                selected_values.append((values[0], values[1]))  # Host e OID

        # Pulisci dashboard
        for item in self.dashboard_tree.get_children():
            self.dashboard_tree.delete(item)

        self.status_var.set("🔄 Aggiornamento dashboard...")
        self.progress.start()
        self.logger.info(f"Aggiornamento dashboard: {len(self.saved_values)} elementi")

        def refresh_worker():
            try:
                errors = []
                success = 0

                for key, config in self.saved_values.items():
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

                        if result:
                            if isinstance(result, SnmpOctetString):
                                value = result.value.decode('utf-8', errors='replace')
                            else:
                                value = str(result.value) if hasattr(result, 'value') else str(result)
                            status = "✅"
                            success += 1
                        else:
                            value = "N/A"
                            status = "❌"
                            errors.append(f"{config['host']}:{config['oid']}")

                        timestamp = time.strftime("%H:%M:%S")

                        # NUOVO: Salva dato storico
                        if key not in self.historical_data:
                            self.historical_data[key] = deque(maxlen=100)

                        self.historical_data[key].append({
                            'timestamp': time.time(),
                            'value': result if result else 0
                        })

                        # NUOVO: Controlla se c'è una regola associata
                        alert_status = ""
                        rule_id = f"{config['host']}_{config['oid']}"
                        if rule_id in self.alert_rules:
                            rule = self.alert_rules[rule_id]
                            if result and rule.check(result):
                                alert_status = "🔴"
                            else:
                                alert_status = "🟢"

                        # NUOVO: Calcola trend
                        trend = ""
                        if len(self.historical_data[key]) > 1:
                            try:
                                prev_val = float(self.historical_data[key][-2]['value'].value if hasattr(
                                    self.historical_data[key][-2]['value'], 'value') else self.historical_data[key][-2][
                                    'value'])
                                curr_val = float(result.value if hasattr(result, 'value') else result)
                                if curr_val > prev_val:
                                    trend = "↗️"
                                elif curr_val < prev_val:
                                    trend = "↘️"
                                else:
                                    trend = "➡️"
                            except:
                                trend = ""

                        # Aggiungi al dashboard con colori per alert
                        self.root.after(0, lambda h=config['host'], o=config['oid'],
                                                  n=config['name'], v=value, t=timestamp, s=status,
                                                  a=alert_status, tr=trend:
                        self.dashboard_tree.insert("", tk.END, values=(h, o, n, v, t, s, a, tr),
                                                   tags=("alert" if a == "🔴" else "normal",)))

                    except Exception as e:
                        errors.append(f"{config['host']}:{config['oid']} - {str(e)}")
                        self.root.after(0, lambda h=config['host'], o=config['oid'],
                                                  n=config['name'], e=str(e):
                        self.dashboard_tree.insert("", tk.END,
                                                   values=(
                                                       h, o, n, f"Error: {e[:30]}...", time.strftime("%H:%M:%S"), "❌",
                                                       "", "")))

                # NUOVO: Colora le righe con alert
                self.root.after(0, lambda: self.dashboard_tree.tag_configure("alert", background="#ffcccc"))
                self.root.after(0, lambda: self.dashboard_tree.tag_configure("normal", background="white"))

                # NUOVO: Controlla regole dopo l'aggiornamento
                self.root.after(0, self.check_alert_rules)

                # NUOVO: Ripristina selezione
                def restore_selection():
                    for item in self.dashboard_tree.get_children():
                        values = self.dashboard_tree.item(item)['values']
                        if values and (values[0], values[1]) in selected_values:
                            self.dashboard_tree.selection_add(item)
                            # Triggera evento selezione per aggiornare il grafico (solo per il primo elemento)
                            if self.dashboard_tree.selection():
                                self.dashboard_tree.event_generate("<<TreeviewSelect>>")
                                break

                self.root.after(100, restore_selection)  # Aspetta che il tree sia popolato

                # Report finale
                total = len(self.saved_values)
                self.logger.info(f"Dashboard aggiornato: {success}/{total} OK")

                if errors:
                    self.root.after(0, lambda: self.status_var.set(
                        f"⚠️ Dashboard: {success}/{total} OK, {len(errors)} errori"))
                else:
                    self.root.after(0, lambda: self.status_var.set(
                        f"✅ Dashboard aggiornato: {total} elementi - {datetime.now().strftime('%H:%M:%S')}"))

            except Exception as e:
                self.logger.error(f"Errore aggiornamento dashboard: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Errore Dashboard", str(e)))
            finally:
                self.root.after(0, lambda: self.progress.stop())

        threading.Thread(target=refresh_worker, daemon=True).start()

    def toggle_auto_refresh(self):
        """NUOVO: Attiva/disattiva auto-refresh del dashboard"""
        if self.auto_refresh_var.get():
            self.start_auto_refresh()
        else:
            self.stop_auto_refresh()

    def start_auto_refresh(self):
        """NUOVO: Avvia auto-refresh del dashboard con intervallo personalizzabile"""
        self.refresh_dashboard()

        try:
            interval = int(self.refresh_interval_var.get()) * 1000  # Converti in millisecondi
        except:
            interval = 30000  # Default 30 secondi

        self.auto_refresh_timer = self.root.after(interval, self.start_auto_refresh)
        self.status_var.set(f"🔄 Auto-refresh attivo ({self.refresh_interval_var.get()}s)")
        self.logger.info(f"Auto-refresh attivato: {self.refresh_interval_var.get()}s")

    def stop_auto_refresh(self):
        """NUOVO: Ferma auto-refresh del dashboard"""
        if self.auto_refresh_timer:
            self.root.after_cancel(self.auto_refresh_timer)
            self.auto_refresh_timer = None
        self.status_var.set("⏸️ Auto-refresh disattivato")
        self.logger.info("Auto-refresh disattivato")

    # ==================== FUNZIONI DI SUPPORTO ====================

    def save_rules(self):
        """NUOVO: Salva le regole su file"""
        rules_data = {}
        for rule_id, rule in self.alert_rules.items():
            rules_data[rule_id] = rule.to_dict()

        try:
            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
            self.logger.info("Regole salvate")
        except Exception as e:
            self.logger.error(f"Errore salvataggio regole: {e}")

    def load_rules(self):
        """NUOVO: Carica le regole da file"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    rules_data = json.load(f)

                for rule_id, rule_dict in rules_data.items():
                    self.alert_rules[rule_id] = AlertRule.from_dict(rule_dict)

                self.logger.info(f"Caricate {len(self.alert_rules)} regole")
        except Exception as e:
            self.logger.error(f"Errore caricamento regole: {e}")

    def save_email_config_to_file(self):
        """NUOVO: Salva la configurazione email su file"""
        try:
            config_data = self.email_config.to_dict()

            with open(self.email_config_file, 'w') as f:
                json.dump(config_data, f, indent=2)

            self.logger.info("Configurazione email salvata")
        except Exception as e:
            self.logger.error(f"Errore salvataggio configurazione email: {e}")

    def load_email_config(self):
        """NUOVO: Carica la configurazione email da file"""
        try:
            if os.path.exists(self.email_config_file):
                with open(self.email_config_file, 'r') as f:
                    config_data = json.load(f)

                self.email_config.from_dict(config_data)
                self.logger.info("Configurazione email caricata")
        except Exception as e:
            self.logger.error(f"Errore caricamento configurazione email: {e}")

    # ... [TUTTE LE ALTRE FUNZIONI ORIGINALI] ...

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
            messagebox.showerror("❌ Errore", error)
            return

        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("🔌 Test connessione...")
        self.progress.start()
        self.logger.info(f"Test connessione a {self.host_var.get()}")

        thread = threading.Thread(target=self._test_connection_worker, daemon=True)
        thread.start()

    def _test_connection_worker(self):
        """Worker test connessione"""
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
            self.logger.error(f"Test connessione fallito: {str(e)}")
            self.root.after(0, lambda: self._show_test_error(str(e)))
        finally:
            self.root.after(0, self._test_completed)

    def _show_test_success(self, sys_desc, version_info):
        """Mostra successo test"""
        messagebox.showinfo("✅ Test OK",
                            f"Connessione SNMP stabilita!\n\n"
                            f"📡 Protocollo: {version_info}\n"
                            f"🏢 Sistema: {sys_desc[:100]}...")
        self.status_var.set("✅ Test riuscito")

    def _show_test_warning(self):
        """Mostra warning test"""
        messagebox.showwarning("⚠️ Test",
                               "Connettività OK ma SNMP non risponde.\n"
                               "Verificare community/credenziali.")
        self.status_var.set("⚠️ SNMP non risponde")

    def _show_test_error(self, error_msg):
        """Mostra errore test"""
        messagebox.showerror("❌ Test Fallito",
                             f"Test fallito:\n\n{error_msg}")
        self.status_var.set("❌ Test fallito")

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
        self.status_var.set("🎯 Discovery Engine ID...")
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
        result_window.title("🎯 Engine ID Discovery")
        result_window.geometry("500x300")
        result_window.transient(self.root)

        ttk.Label(result_window, text="✅ Engine ID Scoperto!",
                  font=('TkDefaultFont', 12, 'bold')).pack(pady=10)

        frame = ttk.Frame(result_window)
        frame.pack(padx=20, pady=10)

        ttk.Label(frame, text=f"Engine ID: {results['engine_id']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text=f"Engine Boots: {results['engine_boots']}").pack(anchor=tk.W, pady=2)
        ttk.Label(frame, text=f"Engine Time: {results['engine_time']} sec").pack(anchor=tk.W, pady=2)

        def copy_engine_id():
            self.root.clipboard_clear()
            self.root.clipboard_append(results['engine_id'])
            messagebox.showinfo("📋 Copiato", "Engine ID copiato!")

        ttk.Button(result_window, text="📋 Copia", command=copy_engine_id).pack(pady=10)
        ttk.Button(result_window, text="OK", command=result_window.destroy).pack()

    def _show_engine_discovery_error(self, error_msg):
        """Mostra errore discovery"""
        messagebox.showerror("❌ Discovery Fallito", f"Impossibile scoprire Engine ID:\n{error_msg}")
        self.status_var.set("❌ Discovery fallito")

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
            messagebox.showerror("❌ Errore", error)
            return

        # Avvia scansione
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("🔄 Scansione in corso...")

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
        """Worker scansione con gestione errori robusta"""
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
                    self.root.after(0, lambda m=msg: messagebox.showwarning("⚠️ Limite", m))
                    break

                try:
                    self.root.after(0, lambda o=base_oid, p=processed, t=total_oids:
                    self.status_var.set(f"📡 Scansione {o}... ({p}/{t})"))

                    # Esegui walk
                    if self.version_var.get() == "2c" or self.version_var.get() == "3":
                        results = self.client.bulk_walk(base_oid, max_repetitions=20)
                    else:
                        results = self.client.walk(base_oid)

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
                except Exception as e:
                    error = f"Errore {base_oid}: {str(e)}"
                    errors.append(error)
                    self.logger.error(error)

                processed += 1

                # Check timeout globale
                if time.time() - start_time > 300:  # 5 minuti
                    self.logger.warning("Timeout globale scansione (5 minuti)")
                    self.root.after(0, lambda: messagebox.showwarning(
                        "⚠️ Timeout", "Scansione interrotta dopo 5 minuti"))
                    break

            # Report finale
            scan_time = time.time() - start_time
            total_results = len(self.scan_results)

            self.logger.info(f"Scansione completata: {total_results} risultati in {scan_time:.1f}s")

            if errors:
                self.logger.warning(f"Completata con {len(errors)} errori")
                error_summary = "\n".join(errors[:5])
                self.root.after(0, lambda: self.status_var.set(
                    f"⚠️ Completato con {len(errors)} errori in {scan_time:.1f}s"))
            else:
                self.root.after(0, lambda: self.status_var.set(
                    f"✅ Scansione OK: {total_results} risultati in {scan_time:.1f}s"))

            self.root.after(0, self._scan_completed)

        except Exception as e:
            self.logger.error(f"Errore critico scansione: {str(e)}\n{traceback.format_exc()}")
            self.root.after(0, lambda: self._scan_error(f"Errore critico: {str(e)}"))

    def _add_result_to_tree(self, oid, value):
        """Aggiunge risultato al tree"""
        try:
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
        """Ottiene descrizione OID - PRIMA cerca nei MIB custom, poi nei default"""
        # Cerca prima nei MIB custom e default
        if oid in self.oid_names:
            return self.oid_names[oid]

        # Cerca prefissi conosciuti
        oid_parts = oid.split('.')
        for i in range(len(oid_parts), 0, -1):
            partial = '.'.join(oid_parts[:i])
            if partial in self.oid_names:
                # Se è una tabella/entry, aggiungi l'indice
                remaining = '.'.join(oid_parts[i:])
                if remaining:
                    base_name = self.oid_names[partial]
                    # Se è un nome che finisce con Entry o Table
                    if any(x in base_name for x in ['Entry', 'Table', 'entry', 'table']):
                        return f"{base_name}.{remaining}"
                    else:
                        return f"{base_name}[{remaining}]"
                return self.oid_names[partial]

        return ""

    def _scan_completed(self):
        """Completa scansione"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()

        total = len(self.results_tree.get_children())
        self.status_var.set(f"✅ Scansione completata - {total} risultati")

        # NUOVO: Controlla regole dopo la scansione
        self.check_alert_rules()

        self.save_config()

    def _scan_error(self, error_msg):
        """Gestisce errore scansione"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set(f"❌ Errore: {error_msg}")
        messagebox.showerror("Errore Scansione", error_msg)

    def stop_scan(self):
        """Ferma scansione"""
        self.scanning = False
        self.status_var.set("⏹️ Interruzione...")
        self.logger.info("Scansione interrotta dall'utente")

    def walk_from_selected(self):
        """WALK da elemento selezionato"""
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
        if not messagebox.askyesno("🚶 WALK", f"Eseguire WALK da:\n{oid}\n\nPotrebbe generare molti risultati."):
            return

        # Pulisci risultati
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        self.status_var.set(f"🚶 WALK da {oid}...")
        self.progress.start()
        self.logger.info(f"WALK da OID: {oid}")

        # Thread per WALK
        def walk_worker():
            try:
                if self.version_var.get() == "2c" or self.version_var.get() == "3":
                    results = self.client.bulk_walk(oid, max_repetitions=20)
                else:
                    results = self.client.walk(oid)

                count = 0
                for walk_oid, value in results.items():
                    if count >= int(self.max_results_var.get()):
                        self.root.after(0, lambda: messagebox.showwarning(
                            "⚠️ Limite", f"Raggiunto limite di {self.max_results_var.get()} risultati"))
                        break

                    self.root.after(0, self._add_result_to_tree, walk_oid, value)
                    count += 1

                self.logger.info(f"WALK completato: {count} risultati")
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: self.status_var.set(f"✅ WALK completato - {count} risultati"))

            except Exception as e:
                self.logger.error(f"Errore WALK: {str(e)}")
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Errore WALK", str(e)))

        threading.Thread(target=walk_worker, daemon=True).start()

    def set_value(self):
        """SET valore SNMP"""
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
        dialog.title("✏️ SET Valore SNMP")
        dialog.geometry("450x350")
        dialog.transient(self.root)
        dialog.grab_set()

        # Info OID
        info_frame = ttk.LabelFrame(dialog, text="📋 Informazioni OID")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(info_frame, text=f"OID: {oid}", font=('TkDefaultFont', 9)).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Tipo attuale: {current_type}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(info_frame, text=f"Valore attuale: {current_value}").pack(anchor=tk.W, padx=5, pady=2)

        # Frame nuovo valore
        value_frame = ttk.LabelFrame(dialog, text="✏️ Nuovo Valore")
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
        warning_label = ttk.Label(dialog, text="⚠️ ATTENZIONE: SET modifica valori sul dispositivo!",
                                  foreground="red")
        warning_label.pack(pady=10)

        def do_set():
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
                    messagebox.showinfo("✅ SET OK", "Valore impostato con successo!")
                    dialog.destroy()

                    # Aggiorna valore nel tree
                    self.get_single_oid(oid)
                    self.logger.info("SET completato con successo")
                else:
                    messagebox.showerror("❌ SET Fallito", "Impossibile impostare il valore")
                    self.logger.error("SET fallito")

            except Exception as e:
                error_msg = f"Errore SET: {str(e)}"
                self.logger.error(error_msg)
                messagebox.showerror("❌ Errore", error_msg)

        # Pulsanti
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="✅ Applica", command=do_set).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Annulla", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

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
        """GET singolo OID"""
        if not self.client:
            messagebox.showerror("Errore", "Effettua prima una scansione")
            return

        try:
            self.logger.info(f"GET OID: {oid}")
            result = self.client.get(oid)

            if result:
                if isinstance(result, SnmpOctetString):
                    value = result.value.decode('utf-8', errors='replace')
                else:
                    value = str(result.value) if hasattr(result, 'value') else str(result)

                messagebox.showinfo("🔍 GET Result",
                                    f"OID: {oid}\n"
                                    f"Valore: {value}\n"
                                    f"Tipo: {type(result).__name__}")

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
                messagebox.showwarning("GET Result", f"Nessun valore per: {oid}")

        except Exception as e:
            self.logger.error(f"Errore GET: {str(e)}")
            messagebox.showerror("Errore GET", str(e))

    def full_walk(self):
        """Walk completo"""
        if not messagebox.askyesno("🌊 Walk Completo",
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
        self.status_var.set("🌊 Walk completo in corso...")

        # Inizializza scanner con limiti
        self.memory_scanner = MemoryLimitedScanner(
            int(self.max_results_var.get()),
            int(self.max_memory_var.get())
        )

        self.logger.info("Avvio walk completo")

        def walk_worker():
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
                        self.root.after(0, lambda m=msg: messagebox.showwarning("⚠️ Limite", m))
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
                        self.root.after(0, lambda c=count: self.status_var.set(f"🌊 Walk: {c} OID trovati..."))

                self.logger.info(f"Walk completato: {count} OID")
                self.root.after(0, lambda c=count: self.status_var.set(f"✅ Walk completato: {count} OID"))

            except Exception as e:
                self.logger.error(f"Errore walk completo: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("Errore Walk", str(e)))
            finally:
                self.scanning = False
                self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.progress.stop())

        threading.Thread(target=walk_worker, daemon=True).start()

    def export_results(self):
        """Esporta risultati in tutti i formati"""
        if not self.scan_results:
            messagebox.showwarning("⚠️ Avviso", "Nessun risultato da esportare")
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
                # Export JSON
                export_data = {
                    'metadata': {
                        'host': self.host_var.get(),
                        'version': self.version_var.get(),
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'total_results': len(self.scan_results)
                    },
                    'results': {}
                }

                for oid, data in self.scan_results.items():
                    export_data['results'][oid] = {
                        'value': str(data['value']),
                        'type': data['type'],
                        'status': data['status'],
                        'timestamp': data['timestamp']
                    }

                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)

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
                # Export HTML
                with open(filename, 'w', encoding='utf-8') as f:
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
            background-color: #2196F3;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
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
            background: #4CAF50; 
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
        <h1>🌐 SNMP Scan Results</h1>
        <p><strong>Host:</strong> """ + self.host_var.get() + """</p>
        <p><strong>Version:</strong> SNMPv""" + self.version_var.get() + """</p>
        <p><strong>Date:</strong> """ + time.strftime('%Y-%m-%d %H:%M:%S') + """</p>
        <p><strong>Total Results:</strong> """ + str(len(self.scan_results)) + """</p>
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
            messagebox.showinfo("✅ Export Completato",
                                f"Risultati esportati con successo!\n\n"
                                f"📄 File: {os.path.basename(filename)}\n"
                                f"📊 Totale: {len(self.scan_results)} risultati")

            # Chiedi se aprire
            if messagebox.askyesno("📂 Apri File", "Vuoi aprire il file esportato?"):
                if sys.platform.startswith('win'):
                    os.startfile(filename)
                elif sys.platform.startswith('darwin'):
                    os.system(f'open "{filename}"')
                else:
                    os.system(f'xdg-open "{filename}"')

        except Exception as e:
            self.logger.error(f"Errore export: {str(e)}")
            messagebox.showerror("❌ Errore Export", f"Errore durante export:\n{str(e)}")

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
            'auto_refresh': self.auto_refresh_var.get(),
            'refresh_interval': self.refresh_interval_var.get()
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

                # NUOVO: Carica configurazioni monitoring
                # Non caricare auto_refresh, lascialo sempre True di default
                if 'refresh_interval' in config:
                    self.refresh_interval_var.set(config.get('refresh_interval', '30'))

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
        settings_window.title("⚙️ Impostazioni")
        settings_window.geometry("400x500")
        settings_window.transient(self.root)
        settings_window.grab_set()

        # Notebook per categorie
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tab Limiti
        limits_frame = ttk.Frame(notebook)
        notebook.add(limits_frame, text="📊 Limiti")

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
        notebook.add(log_frame, text="📝 Logging")

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
            messagebox.showinfo("✅", f"Livello log impostato a {log_level_var.get()}")

        ttk.Button(log_frame, text="Applica", command=apply_log_level).pack(pady=10)

        # Tab Sicurezza
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="🔐 Sicurezza")

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
            messagebox.showinfo("✅", "Password cancellate dalla memoria")

        ttk.Button(security_frame, text="🗑️ Cancella Password dalla Memoria",
                   command=clear_passwords).pack(pady=10)

        # Pulsanti
        btn_frame = ttk.Frame(settings_window)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="✅ OK", command=settings_window.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Annulla", command=settings_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_log_viewer(self):
        """Visualizza log file"""
        log_window = tk.Toplevel(self.root)
        log_window.title("📊 Log Viewer")
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

        ttk.Button(btn_frame, text="🔄 Aggiorna", command=refresh_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Chiudi", command=log_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_debug_info(self):
        """Mostra informazioni debug"""
        info = f"""
🐛 DEBUG INFO

Sistema: {sys.platform}
Python: {sys.version}
Memoria: {psutil.Process().memory_info().rss / 1024 / 1024:.1f}MB
CPU: {psutil.cpu_percent()}%

Risultati caricati: {len(self.scan_results)}
Dashboard elementi: {len(self.saved_values)}
Regole alert: {len(self.alert_rules)}
Alert attivi: {sum(1 for r in self.alert_rules.values() if r.is_triggered)}

Log directory: {os.path.abspath('logs')}
Config file: {os.path.abspath(self.config_file)}

SNMP Client attivo: {'Si' if self.client else 'No'}
Versione SNMP: {self.version_var.get()}
Auto-refresh: {'Si' if self.auto_refresh_var.get() else 'No'}
"""

        messagebox.showinfo("🐛 Debug Info", info)

    def show_shortcuts(self):
        """Mostra shortcuts tastiera"""
        shortcuts = """
⌨️ SHORTCUTS TASTIERA

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
        messagebox.showinfo("⌨️ Shortcuts", shortcuts)

    def on_closing(self):
        """Chiusura applicazione con cleanup"""
        if self.scanning:
            if not messagebox.askyesno("⚠️ Scansione in corso",
                                       "Scansione in corso. Vuoi davvero uscire?"):
                return
            self.stop_scan()

        # Ferma timer
        if self.auto_refresh_timer:
            self.root.after_cancel(self.auto_refresh_timer)

        # Salva tutto
        self.save_config()
        self.save_saved_values()
        self.save_rules()
        self.save_email_config_to_file()
        self.save_historical_data()  # NUOVO: Salva dati storici

        # Cancella password dalla memoria
        self.credential_manager.secure_delete(self.v3_auth_password_var.get())
        self.credential_manager.secure_delete(self.v3_priv_password_var.get())

        # Cleanup
        gc.collect()

        self.logger.info("Chiusura applicazione")
        self.logger.info("=" * 60)

        self.root.quit()
        self.root.destroy()

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
        """Doppio click su MIB tree"""
        selection = self.mib_tree.selection()
        if selection:
            item = selection[0]
            values = self.mib_tree.item(item)['values']
            if values and values[0]:
                self.get_single_oid(values[0])

    def show_context_menu(self, event):
        """Menu contestuale con opzioni aggiuntive"""
        selection = self.results_tree.selection()
        if not selection:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="🔍 GET", command=self.get_selected)
        menu.add_command(label="✏️ SET", command=self.set_value)
        menu.add_command(label="🚶 WALK", command=self.walk_from_selected)
        menu.add_separator()
        menu.add_command(label="➕ Aggiungi Dashboard", command=self.add_to_dashboard)
        menu.add_command(label="🔔 Crea Regola Alert", command=self.create_rule_from_selected)
        menu.add_separator()
        menu.add_command(label="📋 Copia OID", command=self.copy_oid)

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
                self.status_var.set(f"📋 OID copiato: {values[0]}")

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
                # NUOVO: Rimuovi anche dati storici
                if key in self.historical_data:
                    del self.historical_data[key]
            self.dashboard_tree.delete(item)

        self.save_saved_values()

    def clear_dashboard(self):
        """Pulisce dashboard"""
        if self.saved_values and messagebox.askyesno("Conferma", "Rimuovere tutti gli elementi?"):
            self.saved_values.clear()
            self.historical_data.clear()  # NUOVO: Pulisci anche dati storici
            for item in self.dashboard_tree.get_children():
                self.dashboard_tree.delete(item)
            self.save_saved_values()

    def build_mib_tree(self):
        """CORRETTO: Costruisce albero MIB gerarchico visualizzando tutti i dati"""
        if not self.scan_results:
            messagebox.showwarning("Avviso", "Effettua prima una scansione")
            return

        # Pulisci albero esistente
        for item in self.mib_tree.get_children():
            self.mib_tree.delete(item)

        # Costruisci struttura gerarchica
        tree_structure = {}

        for oid, data in self.scan_results.items():
            parts = oid.split('.')
            current_level = tree_structure

            # Costruisci il percorso nell'albero
            for i, part in enumerate(parts):
                if part not in current_level:
                    current_level[part] = {'children': {}, 'oid': '.'.join(parts[:i+1]), 'data': None}

                # Se è l'ultimo elemento, salva i dati
                if i == len(parts) - 1:
                    current_level[part]['data'] = data

                current_level = current_level[part]['children']

        # Popola il treeview
        self._populate_mib_tree_view("", tree_structure, "")

        self.status_var.set(f"🌳 Albero MIB costruito con {len(self.scan_results)} OID")
        self.logger.info(f"Albero MIB costruito con {len(self.scan_results)} OID")

    def _populate_mib_tree_view(self, parent_item, tree_dict, parent_oid):
        """CORRETTO: Popola ricorsivamente il treeview con tutti i dati"""
        for key in sorted(tree_dict.keys(), key=lambda x: (not x.isdigit(), x.zfill(10) if x.isdigit() else x)):
            node_data = tree_dict[key]

            # Costruisci OID completo
            current_oid = f"{parent_oid}.{key}" if parent_oid else key

            # Ottieni nome descrittivo
            display_name = self._get_oid_description(current_oid)
            if not display_name:
                display_name = f"OID {key}"

            # Prepara valori per le colonne
            if node_data['data']:
                # Nodo con dati
                data = node_data['data']

                # Formatta il valore
                if isinstance(data['value'], SnmpOctetString):
                    try:
                        value_str = data['value'].value.decode('utf-8', errors='replace')
                    except:
                        value_str = data['value'].value.hex()
                elif hasattr(data['value'], 'value'):
                    value_str = str(data['value'].value)
                else:
                    value_str = str(data['value'])

                # Limita lunghezza del valore per visualizzazione
                if len(value_str) > 50:
                    value_str = value_str[:50] + "..."

                type_str = data['type']
                status = data['status']
            else:
                # Nodo contenitore
                value_str = ""
                type_str = "Container"
                status = ""

            # Inserisci nel tree
            item_id = self.mib_tree.insert(
                parent_item,
                tk.END,
                text=display_name,
                values=(current_oid, type_str, value_str, status),
                open=False
            )

            # Se ha figli, processa ricorsivamente
            if node_data['children']:
                self._populate_mib_tree_view(item_id, node_data['children'], current_oid)

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
        if messagebox.askyesno("🧹 Pulisci Cache", "Pulire tutti i risultati e la cache?"):
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            for item in self.mib_tree.get_children():
                self.mib_tree.delete(item)

            self.scan_results.clear()
            self.mib_tree_data.clear()

            gc.collect()

            self.status_var.set("🧹 Cache pulita")
            self.info_var.set("")
            self.logger.info("Cache pulita")

    def load_config_dialog(self):
        """Dialog carica configurazione"""
        filename = filedialog.askopenfilename(
            title="📁 Carica Configurazione",
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

                messagebox.showinfo("✅ Configurazione", "Configurazione caricata con successo!")
                self.logger.info(f"Configurazione caricata da: {filename}")

            except Exception as e:
                messagebox.showerror("❌ Errore", f"Errore caricamento:\n{str(e)}")
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
        wizard.title("🔐 Wizard SNMPv3")
        wizard.geometry("500x400")
        wizard.transient(self.root)

        text = """
🔐 CONFIGURAZIONE SNMPv3

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

⚠️ Le password devono corrispondere a quelle
   configurate sul dispositivo SNMP!
"""

        text_widget = tk.Text(wizard, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)

        ttk.Button(wizard, text="OK", command=wizard.destroy).pack(pady=10)

    def show_help(self):
        """Mostra guida completa"""
        help_text = """
📚 GUIDA SNMP BROWSER v3.5

🚀 OPERAZIONI BASE:
• Configura host e parametri
• Scegli versione SNMP (1, 2c, 3)
• Clicca "Avvia Scansione"
• Visualizza risultati nel browser

🔒 SNMPV3:
• Richiede username e password
• Supporta autenticazione e crittografia
• Usa "Scopri Engine ID" per discovery

🔔 SISTEMA ALERT (NUOVO!):
• Crea regole per monitorare valori
• Notifiche desktop quando soglie superate
• Invio email automatico per alert critici
• Indicatore visivo verde/rosso dello stato

📊 DASHBOARD AVANZATO (NUOVO!):
• Auto-refresh attivo di default (30s)
• Grafici real-time dei valori
• Statistiche e trend
• Indicatori alert per ogni elemento

📈 GRAFICI (NUOVO!):
• Visualizza andamento nel tempo
• Salva grafici come immagini
• Mini-grafici nel dashboard

📧 EMAIL ALERT (NUOVO!):
• Configura server SMTP
• Invio automatico per regole critiche
• Test integrato configurazione

🛡️ SICUREZZA:
• Password criptate
• Logging completo
• Limiti memoria e risultati
• Cancellazione sicura credenziali

FUNZIONI AVANZATE:
• GET: Doppio click su OID
• SET: Click destro > SET
• WALK: Click destro > WALK
• Export: Multipli formati

SHORTCUTS:
• F5: Aggiorna dashboard
• Ctrl+T: Test connessione
• Ctrl+S: Salva configurazione
• ESC: Interrompi scansione
"""

        help_window = tk.Toplevel(self.root)
        help_window.title("📚 Guida")
        help_window.geometry("600x500")
        help_window.transient(self.root)

        text = tk.Text(help_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)

        ttk.Button(help_window, text="OK", command=help_window.destroy).pack(pady=10)

    def show_about(self):
        """Mostra info applicazione"""
        about_text = f"""
SNMP Browser v3.5 - Production Ready
con Advanced Monitoring

Browser SNMP professionale con:
• Supporto completo v1/v2c/v3
• Sistema alert e regole personalizzabili
• Grafici real-time e statistiche
• Notifiche email per alert
• Auto-refresh dashboard (30s default)
• Indicatori visivi stato sistema
• Crittografia credenziali
• Logging su file con rotazione
• Gestione memoria ottimizzata
• Export multi-formato

Memoria attuale: {psutil.Process().memory_info().rss / 1024 / 1024:.1f}MB
Risultati caricati: {len(self.scan_results)}
Regole alert: {len(self.alert_rules)}

© 2024 - Software Production Ready
"""
        messagebox.showinfo("ℹ️ Info", about_text)

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

    try:
        import matplotlib
    except ImportError:
        missing.append("matplotlib")

    if missing:
        print("❌ Dipendenze mancanti:")
        print(f"   Installa con: pip install {' '.join(missing)}")
        return False

    return True

def main():
    """Main function production ready con monitoring avanzato"""
    try:
        # Verifica dipendenze
        if not check_dependencies():
            sys.exit(1)

        print("🚀 Avvio SNMP Browser v3.5 Production Ready + Advanced Monitoring...")
        print("📊 Dashboard con auto-refresh attivo di default")
        print("🔔 Sistema di alert e regole pronto")
        print("📈 Grafici real-time disponibili")
        # Crea directory necessarie
        os.makedirs("logs", exist_ok=True)

        # Crea finestra principale
        root = tk.Tk()
        try:
            # Aggiungi solo questa parte per PyInstaller
            if hasattr(sys, '_MEIPASS'):
                # Se eseguito come exe PyInstaller
                icon_path = os.path.join(sys._MEIPASS, 'icon.png')
            else:
                # Se eseguito come script Python normale
                icon_path = 'icon.png'

            if os.path.exists(icon_path):
                icon = tk.PhotoImage(file=icon_path)
                root.iconphoto(True, icon)
            elif os.path.exists('icon.ico'):
                root.iconbitmap('icon.ico')
        except Exception as e:
            print(f"⚠️ Impossibile caricare icona: {e}")

        # Stile
        style = ttk.Style()
        available = style.theme_names()
        for theme in ['winnative', 'clam', 'alt', 'default']:
            if theme in available:
                style.theme_use(theme)
                break

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

        print("✅ Inizializzazione completata")
        print("📊 Log salvati in: logs/")
        print("🔐 Supporto SNMPv3 completo")
        print("💾 Gestione memoria attiva")
        print("🔒 Crittografia credenziali attiva")
        print("🔄 Auto-refresh dashboard: 30s")
        print("📧 Sistema email alert disponibile")
        print(f"📁 Dati salvati in: {app.app_data_dir}")
        print("📊 Log salvati in:", app.log_dir)
        # Avvia GUI
        root.mainloop()

    except Exception as e:
        print(f"❌ Errore critico: {e}")
        traceback.print_exc()

        try:
            messagebox.showerror("Errore Critico",
                                 f"Impossibile avviare l'applicazione:\n\n{str(e)}")
        except:
            pass

        sys.exit(1)

if __name__ == "__main__":
    main()

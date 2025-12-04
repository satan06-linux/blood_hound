import time
import json 
import random 
import sys # For clean exit on error
import os # For file operations
from typing import Dict, Any, List 

# --- UTILITY AND LOGGING LAYER ---

class OperationLogger:
    """
    Centralized logging for system actions, errors, and security events.
    Now logs to both console and a simple file for persistence.
    """
    LOG_FILE = "bloodhound_q_audit.log"
    
    @staticmethod
    def _write_to_file(level: str, tag: str, message: str, asset_id: str = ""):
        """Helper to write log entry to the persistent file."""
        log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} {level}|{tag}{'|'+asset_id if asset_id else ''}]: {message}\n"
        with open(OperationLogger.LOG_FILE, 'a') as f:
            f.write(log_entry)

    @staticmethod
    def log_system(message: str):
        """Logs general system operations (initialization, shutdowns)."""
        print(f"[{time.strftime('%H:%M:%S', time.localtime())} SYSTEM]: {message}")
        OperationLogger._write_to_file("SYSTEM", "CORE", message)

    @staticmethod
    def log_action(component: str, details: str):
        """Logs successful actions performed by system components."""
        print(f"[{time.strftime('%H:%M:%S', time.localtime())} ACTION|{component}]: {details}")
        OperationLogger._write_to_file("ACTION", component, details)
        
    @staticmethod
    def log_error(component: str, error_message: str):
        """Logs critical errors encountered during execution."""
        # Logs to stderr and file for critical tracking
        print(f"[{time.strftime('%H:%M:%S', time.localtime())} ERROR|{component}]: {error_message}", file=sys.stderr)
        OperationLogger._write_to_file("ERROR", component, error_message)

    @staticmethod
    def log_incident(asset_id: str, severity: str, details: str):
        """Logs major security incidents or findings."""
        print(f"[{time.strftime('%H:%M:%S', time.localtime())} INCIDENT|{severity}|{asset_id}]: {details}")
        OperationLogger._write_to_file("INCIDENT", severity, details, asset_id)


# --- PERSISTENCE AND ASSET MANAGEMENT LAYER ---

class AssetDatabase:
    """Represents a component in the system for tracking assets and analysis."""
    
    def __init__(self, asset_id: str, function: str, algorithm: str, lifespan_years: int, 
                 access_paths: List[str] = None, asset_type: str = "Other", mechanism: str = "Cryptography",
                 qrc_score: int = 0, ai_recommendation: str = "", last_scanned: float = 0.0,
                 q_day_risk: int = 0, crypto_agility_score: int = 0):
        
        # Input Validation for critical fields
        if not asset_id or not all(isinstance(val, str) for val in [asset_id, function, algorithm]):
            raise TypeError("Asset ID, function, and algorithm must be non-empty strings.")
            
        if not isinstance(lifespan_years, int) or lifespan_years < 0:
            raise ValueError("Lifespan must be a non-negative integer.")

        self.asset_id = asset_id
        self.function = function
        self.algorithm = algorithm
        self.lifespan_years = lifespan_years
        
        # Default/Calculated fields for persistence
        self.access_paths = access_paths or []
        self.asset_type = asset_type
        self.mechanism = mechanism 
        self.qrc_score = qrc_score  # Loaded or initialized
        self.ai_recommendation = ai_recommendation # Loaded or initialized
        self.last_scanned = last_scanned or time.time() # Loaded or set now
        self.q_day_risk = q_day_risk
        self.crypto_agility_score = crypto_agility_score

    def __repr__(self):
        return f"<Asset {self.asset_id} | Algo: {self.algorithm} | Type: {self.asset_type}>"
        
    def to_dict(self) -> Dict[str, Any]:
        """Converts the asset object to a dictionary for JSON serialization."""
        return self.__dict__


class AssetManager:
    """Handles loading and saving of the Asset Database for persistence."""
    ASSET_FILE = "bloodhound_q_assets.json"
    
    @classmethod
    def load_assets(cls) -> List[AssetDatabase]:
        """Loads assets from the JSON file, or returns an empty list if not found."""
        if not os.path.exists(cls.ASSET_FILE):
            OperationLogger.log_system(f"Asset file '{cls.ASSET_FILE}' not found. Starting with an empty database.")
            return []
            
        OperationLogger.log_system(f"Loading assets from persistent storage: {cls.ASSET_FILE}")
        try:
            with open(cls.ASSET_FILE, 'r') as f:
                data = json.load(f)
                assets = [AssetDatabase(**d) for d in data]
                OperationLogger.log_system(f"Successfully loaded {len(assets)} assets.")
                return assets
        except Exception as e:
            OperationLogger.log_error("AssetManager", f"Failed to load assets from file: {e}")
            return [] # Return empty list on failure to prevent startup crash

    @classmethod
    def save_assets(cls, assets: List[AssetDatabase]):
        """Saves current assets to the JSON file before shutdown."""
        data = [a.to_dict() for a in assets]
        OperationLogger.log_system(f"Saving {len(assets)} assets to persistent storage...")
        try:
            with open(cls.ASSET_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            OperationLogger.log_system("Asset saving complete.")
        except Exception as e:
            OperationLogger.log_error("AssetManager", f"Failed to save assets to file: {e}")


# --- ACCESS CONTROL AND BIOMETRIC LAYER ---

class RetinaVerificationLayer:
    """
    Mock authorization system for all critical changes, now with RACL and lockdown.
    """
    
    # Retina Access Control List (RACL) stores user_id and authorization level
    # AUTHORIZED: Super-user, can manage passwords and other retinas
    # GUEST: Can perform verification but not change biometrics or passwords
    RACL: Dict[str, str] = {
        "AUTHORIZED_USER_01": "AUTHORIZED", 
        "HACKERAI_ADMIN": "AUTHORIZED",
        "SEC_LEAD": "AUTHORIZED"
    }
    
    LOCKDOWN_DURATION = 30 # seconds
    lockout_until = 0 # Unix timestamp
    failed_attempts = 0
    MAX_ATTEMPTS = 5
    
    # Simple conceptual password for *biometric management* only
    _RACL_MGMT_PASSWORD = "SuperSecurePassword123" 
    
    @classmethod
    def _is_locked_down(cls) -> bool:
        """Checks if the system is currently in lockdown."""
        if time.time() < cls.lockout_until:
            CommunicationLayer.talk(f"SECURITY ALERT: Biometric system is in lockdown for {int(cls.lockout_until - time.time())} more seconds due to repeated failed attempts.")
            return True
        return False

    @classmethod
    def _lock_down(cls):
        """Initiates the security lockdown."""
        cls.lockout_until = time.time() + cls.LOCKDOWN_DURATION
        cls.failed_attempts = 0
        OperationLogger.log_incident("RACL", "CRITICAL", f"System Lockdown initiated for {cls.LOCKDOWN_DURATION}s due to failed verification attempts.")

    @classmethod
    def verify_user_retina(cls, user_id: str) -> bool:
        """Simulates the biometrical verification process for privileged actions."""
        if cls._is_locked_down():
            return False
            
        OperationLogger.log_action("Auth", f"Verification attempt for user ID: {user_id}")
        
        is_verified = user_id in cls.RACL
        
        if is_verified:
            cls.failed_attempts = 0
            CommunicationLayer.talk("ACCESS GRANTED. The AI is now authorized for privileged actions.")
            OperationLogger.log_action("Auth", "Verification SUCCESS")
            return True
        else:
            cls.failed_attempts += 1
            if cls.failed_attempts >= cls.MAX_ATTEMPTS:
                cls._lock_down()
            CommunicationLayer.talk(f"ACCESS DENIED. ID '{user_id}' not found in RACL. Failed attempts: {cls.failed_attempts}/{cls.MAX_ATTEMPTS}")
            OperationLogger.log_action("Auth", "Verification FAILED")
            return False

    @classmethod
    def register_new_retina(cls, user_id: str, new_retina_id: str, password_attempt: str) -> bool:
        """
        Registers a new retina ID. If the current user is 'AUTHORIZED', they can
        register new retinas if they supply the conceptual master password OR if 
        the system has no existing AUTHORIZED users.
        """
        if cls._is_locked_down():
            return False
            
        if new_retina_id in cls.RACL:
            CommunicationLayer.talk(f"Error: Retina ID '{new_retina_id}' is already registered.")
            return False
            
        # Check for initial AUTHORIZED user setup (first time setup logic)
        num_authorized = len([role for role in cls.RACL.values() if role == "AUTHORIZED"])
        
        if user_id.upper() not in cls.RACL or cls.RACL[user_id.upper()] != "AUTHORIZED":
            # Only existing AUTHORIZED users can register new ones, or the first registration
            CommunicationLayer.talk("Error: Only an existing AUTHORIZED user can manage biometric registration.")
            cls.failed_attempts += 1
            if cls.failed_attempts >= cls.MAX_ATTEMPTS: cls._lock_down()
            return False
        
        # Security check: Password required to add a new privileged retina
        if num_authorized > 0 and password_attempt != cls._RACL_MGMT_PASSWORD:
            CommunicationLayer.talk("Error: Incorrect password. You need the master password to register a new privileged retina after initial setup.")
            cls.failed_attempts += 1
            if cls.failed_attempts >= cls.MAX_ATTEMPTS: cls._lock_down()
            return False

        # If successful or first-time setup:
        cls.RACL[new_retina_id.upper()] = "AUTHORIZED"
        CommunicationLayer.talk(f"SUCCESS: New AUTHORIZED Retina ID '{new_retina_id}' registered successfully.")
        OperationLogger.log_action("Auth", f"New AUTHORIZED retina registered: {new_retina_id}")
        return True

    @classmethod
    def add_guest_retina(cls, user_id: str, guest_id: str) -> bool:
        """Adds a new GUEST retina, which only requires a current authorized user's verification."""
        if cls._is_locked_down():
            return False
        
        if guest_id in cls.RACL:
            CommunicationLayer.talk(f"Error: Retina ID '{guest_id}' is already registered.")
            return False
            
        if user_id.upper() not in cls.RACL or cls.RACL[user_id.upper()] != "AUTHORIZED":
            CommunicationLayer.talk("Error: Only an existing AUTHORIZED user can add a guest retina.")
            return False
            
        cls.RACL[guest_id.upper()] = "GUEST"
        CommunicationLayer.talk(f"SUCCESS: New GUEST Retina ID '{guest_id}' registered successfully by {user_id.upper()}.")
        OperationLogger.log_action("Auth", f"New GUEST retina registered: {guest_id}")
        return True
        
    @classmethod
    def change_management_password(cls, user_id: str, old_password: str, new_password: str) -> bool:
        """Allows an AUTHORIZED user to change the conceptual master password."""
        
        if cls._is_locked_down():
            return False
        
        if user_id.upper() not in cls.RACL or cls.RACL[user_id.upper()] != "AUTHORIZED":
            CommunicationLayer.talk("Error: Only an existing AUTHORIZED user can change the management password.")
            return False

        if old_password != cls._RACL_MGMT_PASSWORD:
            CommunicationLayer.talk("Error: Incorrect old password provided.")
            cls.failed_attempts += 1
            if cls.failed_attempts >= cls.MAX_ATTEMPTS: cls._lock_down()
            return False
            
        if len(new_password) < 8:
            CommunicationLayer.talk("Error: New password must be at least 8 characters long.")
            return False
            
        cls._RACL_MGMT_PASSWORD = new_password
        CommunicationLayer.talk("SUCCESS: Biometric Management Password has been updated securely.")
        OperationLogger.log_incident("RACL", "HIGH", f"Management password successfully changed by {user_id}.")
        return True


# --- EXTERNAL INTEGRATION LAYERS (UNMODIFIED) ---

class CommunicationLayer:
    """
    Handles all output and acts as the single point of integration for future 
    Text-to-Speech (TTS) functionality.
    """

    @staticmethod
    def talk(message):
        """Standardized, humanized, console output for the AI's thoughts."""
        print(f"[{time.strftime('%H:%M:%S', time.localtime())} HackerAI]: {message}")

    @staticmethod
    def say(message, is_voice_enabled: bool):
        """
        Conceptual method for true voice output. Uses 'talk' only if enabled,
        providing a distinct output tag.
        """
        if is_voice_enabled:
            # More emphasis on the 'speech' aspect
            print(f"[{time.strftime('%H:%M:%S', time.localtime())} HackerAI (Speech)]: {message}")
        else:
            CommunicationLayer.talk(message)

    @staticmethod
    def generate_report(asset):
        """Provides a detailed technical report for an asset with enhanced formatting."""
        report = (
            f"\n--- Technical Assessment Report for {asset.asset_id} ---\n"
            f"  > Asset Type/Mechanism: {asset.asset_type} ({asset.mechanism})\n" 
            f"  > Function: {asset.function} (Lifespan: {asset.lifespan_years} yrs)\n"
            f"  > Q-Day Risk: {asset.q_day_risk}%\n"
            f"  > Crypto Agility: {asset.crypto_agility_score}%\n"
            f"  > Algorithm: {asset.algorithm}\n"
            f"  > **Quantum Risk Score (0-100): {asset.qrc_score}**\n"
            f"  > Last Scanned: {time.strftime('%H:%M:%S', time.localtime(asset.last_scanned))}\n"
            f"  > High-Level Conclusion: {asset.ai_recommendation}\n"
        )
        OperationLogger.log_action("ReportGen", f"Generated report for {asset.asset_id} (QRC: {asset.qrc_score})")
        return report
        
    @staticmethod
    def view_pending_changes(knowledge_buffer):
        """Allows the user to see what is waiting for approval, including audit info."""
        if knowledge_buffer.new_knowledge or knowledge_buffer.new_code_snippets:
            CommunicationLayer.talk(f"--- Pending Changes Requiring Retina Approval ({len(knowledge_buffer.new_knowledge) + len(knowledge_buffer.new_code_snippets)} Total) ---")
            
            CommunicationLayer.talk(f"Knowledge Items:")
            for item in knowledge_buffer.new_knowledge.values():
                ts = time.strftime('%H:%M:%S', time.localtime(item['timestamp']))
                print(f"  - {item['id']} (Source: {item['source']} | Added: {ts} by {item['user_id']}): {item['content']}")
            
            CommunicationLayer.talk(f"Code/Logic Changes:")
            for item in knowledge_buffer.new_code_snippets:
                ts = time.strftime('%H:%M:%S', time.localtime(item['timestamp']))
                print(f"  - {item['id']} (Source: {item['source']} | Added: {ts} by {item['user_id']}): Code Snippet of size {len(item['content'])}...")
        else:
            CommunicationLayer.talk("The Pending Knowledge Buffer is currently empty. Everything is up-to-date and approved.")


class CryptoInterface:
    """Simulates interfacing with real cryptographic libraries (plug-in crypto operations)."""
    @staticmethod
    def perform_quantum_safety_check(algorithm: str) -> bool:
        """Simulates initiating a check against a physical crypto module."""
        OperationLogger.log_action("CryptoInterface", f"Initiating real-time safety check for {algorithm}...")
        time.sleep(0.01)
        
        standard = KnowledgeBase.get_standard_details(algorithm)
        if standard:
            is_safe = standard.get('Risk') == 'LOW'
            OperationLogger.log_action("CryptoInterface", f"Check for {algorithm} result: {'SAFE' if is_safe else 'VULNERABLE'}")
            return is_safe
        
        OperationLogger.log_error("CryptoInterface", f"Algorithm {algorithm} not found in standards.")
        return False 

    @staticmethod
    def simulate_key_migration(asset_id: str, old_algo: str, new_algo: str) -> bool:
        """Simulates the cryptographic operation of migrating a key or cert."""
        OperationLogger.log_action("CryptoInterface", f"Attempting key migration for {asset_id}: {old_algo} -> {new_algo}...")
        time.sleep(0.05)
        
        if new_algo in ["Kyber", "Dilithium", "Falcon"]:
            OperationLogger.log_action("CryptoInterface", "Key Migration Success. New key is verifiably quantum safe.")
            return True
        else:
            OperationLogger.log_error("CryptoInterface", "Key Migration FAILED. New algorithm is not PQC or an error occurred.")
            return False

class SIEMIntegration:
    """Provides hooks for integration with SIEM or vulnerability scanners."""
    @staticmethod
    def send_log_event(event_type: str, severity: str, details: Dict[str, Any]):
        """Simulates sending a structured log event to a SIEM."""
        payload = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "source": "BloodHound-Q",
            "details": details
        }
        OperationLogger.log_incident(details.get('asset_id', 'N/A'), severity, f"SIEM Alert: {event_type}")
        return True
    
    @staticmethod
    def trigger_vulnerability_scan(asset_id: str, algorithm: str):
        """Simulates triggering a targeted scan on a vulnerability scanner tool."""
        
        if algorithm == "RSA-4096":
            OperationLogger.log_action("VulnerabilityScanner", f"Triggered full scan on {asset_id} to check for PQC compatibility.")
            return True
        
        OperationLogger.log_action("VulnerabilityScanner", f"Initiated targeted scan on {asset_id}.")
        return False

# --- PQC and STANDARDS (External/Modular Knowledge Base) ---
class KnowledgeBase:
    """
    Manages external configuration for PQC standards and vulnerabilities.
    Now reads from simulated external JSON files for modularity.
    """
    
    PQC_STANDARDS: Dict[str, Dict[str, Any]] = {} 
    VULNERABILITY_REPORT: Dict[str, Dict[str, Any]] = {}
    
    @classmethod
    def _read_data_from_file(cls, filename: str) -> Dict:
        """Simulated file read function for modularity."""
        OperationLogger.log_system(f"Simulating read from {filename}...")
        
        if filename.endswith("pqc_standards.json"):
            # Dummy JSON data mimicking an external file
            return {
                "Kyber": {"Type": "KeyExchange", "Security": "Level III-PQC", "Risk": "LOW", "Agility_Score": 95},
                "Dilithium": {"Type": "Signature", "Security": "Level III-PQC", "Risk": "LOW", "Agility_Score": 90},
                "Falcon": {"Type": "Signature", "Security": "Level I-PQC", "Risk": "LOW", "Agility_Score": 80}, 
                "RSA-4096": {"Type": "KeyExchange", "Security": "Pre-Quantum", "Risk": "HIGH", "Agility_Score": 10},
                "ECC-P256": {"Type": "Signature", "Security": "Pre-Quantum", "Risk": "HIGH_MEDIUM", "Agility_Score": 30}
            }
        elif filename.endswith("vulnerability_report.json"):
             # Dummy JSON data mimicking an external file
            return {
                "VULN_001": {"asset_id": "Archivist_Vault_2025", "type": "LateralMovement", "privilege_needed": "User", "target_key": "PQC Key Store", "risk_score": 95, "path": "Host->KeyCache"},
                "VULN_002": {"asset_id": "TLS_Server_3", "type": "WeakHashFunction", "privilege_needed": "LocalAdmin", "target_key": "Session Key", "risk_score": 50, "path": "Localhost->Memory"},
                "VULN_003": {"asset_id": "All_PQC_Clients", "type": "DowngradeAttack", "privilege_needed": "Network", "target_key": "TLS Handshake", "risk_score": 85, "condition": "Algorithm is not enforced.", "path": "Network->TLS-Handshake"}
            }
        else:
            OperationLogger.log_error("KnowledgeBase", f"Unknown configuration file requested: {filename}")
            return {}

    @classmethod
    def load_standards_and_reports(cls, standards_source: str = "pqc_standards.json", vuln_source: str = "vulnerability_report.json"):
        """Loads PQC standards and vulnerability data from external sources."""
        OperationLogger.log_system("Initiating KNOWLEDGE BASE load sequence...")
        
        try:
            cls.PQC_STANDARDS = cls._read_data_from_file(standards_source)
            cls.VULNERABILITY_REPORT = cls._read_data_from_file(vuln_source)
            OperationLogger.log_system(f"Knowledge Base load complete: {len(cls.PQC_STANDARDS)} standards, {len(cls.VULNERABILITY_REPORT)} vulnerabilities indexed.")
        except Exception as e:
            OperationLogger.log_error("KnowledgeBase", f"Failed to load knowledge base: {e}")
            raise

# Initialize the KnowledgeBase before use
KnowledgeBase.load_standards_and_reports()

# --- PENDING KNOWLEDGE AND AUDIT BUFFER ---

class PendingKnowledgeBuffer:
    """
    Manages knowledge updates awaiting verification, now with audit tracking.
    """
    new_knowledge: Dict[str, Dict[str, Any]] = {} 
    new_code_snippets = [] 
    
    @classmethod
    def store_pending_change(cls, change_type: str, content: str, source: str, user_id: str = "SYSTEM_AUTOMATION"):
        """Stores a change that the AI has 'learned' but not yet integrated."""
        
        if not isinstance(content, str) or not isinstance(source, str):
            OperationLogger.log_error("KnowledgeBuffer", "Attempted to store non-string content or source.")
            raise TypeError("Content and source must be strings for pending change.")
            
        timestamp = time.time()
        
        if change_type == 'knowledge':
            next_id = f"K_PENDING_{len(cls.new_knowledge)+1:03}"
            cls.new_knowledge[next_id] = {"id": next_id, "content": content, "source": source, "user_id": user_id, "timestamp": timestamp}
            log_id = next_id
        elif change_type == 'code':
            next_id = f"C_PENDING_{len(cls.new_code_snippets)+1:03}"
            cls.new_code_snippets.append({"id": next_id, "content": content, "source": source, "user_id": user_id, "timestamp": timestamp})
            log_id = next_id
        
        CommunicationLayer.talk(f"New {change_type} item ('{log_id}') has been securely placed in the **Pending Knowledge Buffer** awaiting Retina Approval (Logged by {user_id}).")


# --- CORE SYSTEM AND BUSINESS LOGIC ---

class BloodHoundQAISystem:
    
    CRQC_TIMELINE = 15
    LONG_TERM_MEM: Dict[str, Dict[str, Any]] = {} 
    
    def __init__(self, initial_assets: List[AssetDatabase]):
        # Load assets from disk if available, otherwise use initial setup
        loaded_assets = AssetManager.load_assets()
        self.assets: List[AssetDatabase] = loaded_assets if loaded_assets else initial_assets
        self.voice_enabled = False # State for voice toggle
        OperationLogger.log_system(f"Project BloodHound-Q Core System Initialized with {len(self.assets)} assets.")
        
    def save_and_exit(self):
        """Saves all state before exiting."""
        AssetManager.save_assets(self.assets)
        CommunicationLayer.talk("Initiating controlled shutdown. All active data saved.")
        OperationLogger.log_system("Application termination completed.")
        sys.exit(0)
        
    def get_asset_by_id(self, asset_id: str) -> AssetDatabase | None:
        """Utility function to retrieve an asset, case-insensitive."""
        return next((a for a in self.assets if a.asset_id.lower() == asset_id.lower()), None)
        
    def add_asset(self, asset_data: Dict[str, Any], user_id: str) -> bool:
        """Adds a new asset to the system with full validation and audit tracking."""
        
        asset_id = asset_data.get('asset_id')
        if not asset_id:
            CommunicationLayer.talk("Error: Asset ID is missing. Cannot add asset.")
            return False

        if self.get_asset_by_id(asset_id):
            CommunicationLayer.say(f"Error: Asset with ID '{asset_id}' already exists. Use 'report {asset_id}' to view or check if it's a duplicate.", self.voice_enabled)
            OperationLogger.log_error("AssetMgmt", f"Attempted to add duplicate asset ID: {asset_id}")
            return False
            
        required_fields = ['function', 'algorithm', 'lifespan_years']
        if not all(asset_data.get(f) for f in required_fields):
            CommunicationLayer.say(f"Error: Missing one of the required fields for asset creation: {', '.join(required_fields)}", self.voice_enabled)
            return False

        try:
             asset_data['lifespan_years'] = int(asset_data['lifespan_years'])
             new_asset = AssetDatabase(**asset_data)
             self.assets.append(new_asset)
             OperationLogger.log_action("AssetMgmt", f"Asset {asset_id} successfully added by {user_id}.")
             CommunicationLayer.say(f"Asset '{asset_id}' has been successfully added to the system for QRC assessment.", self.voice_enabled)
             return True
             
        except (TypeError, ValueError) as e:
            CommunicationLayer.say(f"Error creating asset: {e}. Check that lifespan is a whole number and other fields are strings.", self.voice_enabled)
            OperationLogger.log_error("AssetMgmt", f"Validation error on new asset: {e}")
            return False

    def delete_asset(self, asset_id: str, user_id: str) -> bool:
        """Deletes an asset from the system with audit tracking."""
        
        asset_to_delete = self.get_asset_by_id(asset_id)
        if asset_to_delete:
            self.assets = [a for a in self.assets if a.asset_id.lower() != asset_id.lower()]
            if asset_id in self.LONG_TERM_MEM:
                del self.LONG_TERM_MEM[asset_id]
                
            OperationLogger.log_action("AssetMgmt", f"Asset {asset_id} successfully deleted by {user_id}.")
            CommunicationLayer.say(f"Asset '{asset_id}' and all associated QRC history have been removed from the system.", self.voice_enabled)
            return True
        else:
             CommunicationLayer.say(f"Error: Asset with ID '{asset_id}' not found. Cannot delete.", self.voice_enabled)
             OperationLogger.log_error("AssetMgmt", f"Attempted to delete non-existent asset ID: {asset_id}")
             return False

    # New UX Enhancement
    def list_all_assets(self):
        """Prints a summary list of all assets with their latest QRC scores."""
        CommunicationLayer.talk("\n--- Registered Asset Summary ---")
        if not self.assets:
            CommunicationLayer.talk("No assets currently registered with the system.")
            return

        sorted_assets = sorted(self.assets, key=lambda a: a.qrc_score, reverse=True)

        print(f"{'ID':<25} {'Type':<15} {'Algorithm':<15} {'QRC Score':<10} {'Lifespan (Y)':<15}")
        print("="*78)
        
        for asset in sorted_assets:
            score_display = f"**{asset.qrc_score}**" if asset.qrc_score > 50 else str(asset.qrc_score)
            print(f"{asset.asset_id:<25} {asset.asset_type:<15} {asset.algorithm:<15} {score_display:<10} {asset.lifespan_years:<15}")
        print("="*78)
        
        OperationLogger.log_action("CLI", f"Listed {len(self.assets)} assets.")
        

    def _analyze_quday_risk(self, asset: AssetDatabase):
        """Calculates the Q-Day risk score (2.2)."""
        q_day_probability = random.uniform(0.1 + (asset.lifespan_years / 20.0), 0.9)
        if asset.lifespan_years > self.CRQC_TIMELINE:
            risk = 80 + int(q_day_probability * 20)
        else:
            risk = int((asset.lifespan_years / self.CRQC_TIMELINE) * 80)
            
        asset.q_day_risk = min(100, risk)

    def _analyze_agility(self, asset: AssetDatabase):
        """Calculates Crypto Agility, factoring in difficulty of replacement (2.3)."""
        try:
            standard_details = KnowledgeBase.get_standard_details(asset.algorithm)
            base_agility = standard_details.get("Agility_Score", 20)
        except Exception as e:
            OperationLogger.log_error("AgilityAnalysis", f"Failed to retrieve standard details for {asset.algorithm}: {e}")
            base_agility = 20
        
        complexity_penalty = 0
        if "PKI_Root" in asset.asset_id or "Vault" in asset.asset_type:
            complexity_penalty = 40
        elif "Server" in asset.asset_type:
            complexity_penalty = 15
        
        asset.crypto_agility_score = max(0, int(base_agility) - complexity_penalty)
        
    def toggle_voice(self):
        """Toggles the conceptual voice output mode."""
        self.voice_enabled = not self.voice_enabled
        if self.voice_enabled:
            CommunicationLayer.say("Voice output enabled. I am now speaking to you.", self.voice_enabled)
        else:
            CommunicationLayer.talk("Voice output disabled. Moving to silent console mode now.")
            
    def ingest_and_scan_assets(self):
        if not self.assets:
             CommunicationLayer.say("The asset registry is empty. Please use the 'add_asset' command to register assets before scanning.", self.voice_enabled)
             OperationLogger.log_action("Scan", "Scan aborted: No assets registered.")
             return
             
        assets_needing_attention = 0
        pqc_standards = KnowledgeBase.PQC_STANDARDS 
        
        CommunicationLayer.say("Hold on. Initiating asset scanning and analysis. Do I have your explicit permission to proceed?", self.voice_enabled)
        user_permission = input("Permission (Y/N)? ").strip().upper()
        if user_permission != 'Y':
            CommunicationLayer.say("Scan aborted per user discretion. No data was processed.", self.voice_enabled)
            OperationLogger.log_action("Scan", "Scan permission denied by user.")
            return

        OperationLogger.log_action("Scan", f"Scan permission granted. Starting analysis loop on {len(self.assets)} assets.")
        
        for asset in self.assets:
            
            self._analyze_quday_risk(asset)
            self._analyze_agility(asset)
            
            current_algo_safety = pqc_standards.get(asset.algorithm, {}).get('Risk', 'UNKNOWN')

            if current_algo_safety in ["HIGH", "HIGH_MEDIUM"]:
                
                SIEMIntegration.trigger_vulnerability_scan(asset.asset_id, asset.algorithm) 
                
                base_score = 90 if current_algo_safety == "HIGH" else 70
                base_score += int(asset.q_day_risk * 0.2)
                base_score += int((100 - asset.crypto_agility_score) * 0.1)
                
                asset.qrc_score = min(100, base_score) 
                asset.ai_recommendation = (
                    f"CRITICAL. Legacy Algorithm ({asset.algorithm} is {current_algo_safety} risk). "
                    f"Priorities: 1. Migrate to {self._get_pqc_target(asset.function)[0]}. 2. Enhance crypto agility ({asset.crypto_agility_score}%)."
                )
                assets_needing_attention += 1
                
                SIEMIntegration.send_log_event(
                    event_type="CriticalAssetRisk", 
                    severity="CRITICAL", 
                    details={"asset_id": asset.asset_id, "algorithm": asset.algorithm, "score": asset.qrc_score}
                )
            
            else:
                if CryptoInterface.perform_quantum_safety_check(asset.algorithm):
                    asset.qrc_score = 5
                    asset.ai_recommendation = "Quantum-Safe or verified algorithm in use. Status: VERIFIED."
                else:
                    asset.qrc_score = 25
                    asset.ai_recommendation = "Algorithm not fully validated or failed live safety check. Status: VALIDATION NEEDED."
            
            asset.last_scanned = time.time() # Update the scan timestamp

            self.LONG_TERM_MEM[asset.asset_id] = {
                "latest_qrc_score": asset.qrc_score,
                "q_day_risk": asset.q_day_risk,
                "agility_score": asset.crypto_agility_score
            }
        
        CommunicationLayer.say(f"Asset ingestion complete. We have assessed {len(self.assets)} assets.", self.voice_enabled)
        if assets_needing_attention > 0:
            CommunicationLayer.say(f"Heads up! My analysis identified {assets_needing_attention} critical assets that need immediate attention due to quantum risk. Prioritization is key.", self.voice_enabled)
        else:
            CommunicationLayer.say("The current assessment indicates low overall quantum risk across the known assets. Good work!", self.voice_enabled)
        

    def generate_attack_plan(self, user_privileges: str):
        """Generates a sequential attack plan when the user asks 'How to attack'."""
        vuln_report = KnowledgeBase.VULNERABILITY_REPORT
        
        CommunicationLayer.say(f"\nUnderstood. Initiating Tactical Attack Planner (T.A.P.) to model an attack from a '{user_privileges}' perspective.", self.voice_enabled)
        
        accessible_threats = [v for v in vuln_report.values() 
                              if v["privilege_needed"].lower() in [user_privileges.lower(), "user", "network", "localadmin"]]
        
        if not accessible_threats:
            return CommunicationLayer.say(f"I found no immediately obvious entry points for a '{user_privileges}' user. You may need to expand your reconnaissance scope.", self.voice_enabled)
        
        accessible_threats.sort(key=lambda x: x["risk_score"], reverse=True)
        
        CommunicationLayer.say(f"Generating a prioritized attack sequence based on {len(accessible_threats)} potential vulnerabilities...", self.voice_enabled)
        
        for i, threat in enumerate(accessible_threats):
            
            detail = f"on asset **{threat['asset_id']}** (Path: {threat.get('path', 'N/A')}), targeting the **{threat['target_key']}**." 
            if threat.get('condition'):
                 detail += f" (Condition: {threat['condition']})"

            if threat["type"] == "LateralMovement":
                CommunicationLayer.talk(
                    f"STEP {i+1} (CRITICAL): Lateral Movement Pivot. Exploit **{threat['type']}** (Risk: {threat['risk_score']}). "
                    f"Action: Use the pre-mapped path of least resistance to pivot toward the key store {detail}. "
                    f"Objective: Compromise the integrity of the crucial QRC transition process."
                )
            elif threat["type"] == "DowngradeAttack":
                 CommunicationLayer.talk(
                    f"STEP {i+1} (HIGH): Downgrade Vulnerability. Exploit **{threat['type']}** (Risk: {threat['risk_score']}). "
                    f"Action: Inject a malicious renegotiation packet during the TLS handshake {detail}. "
                    f"Objective: Force the system to fall back to a common, easily-breakable pre-quantum algorithm."
                )
            else:
                CommunicationLayer.talk(
                    f"STEP {i+1} (MEDIUM): Exploit {threat['type']} (Risk: {threat['risk_score']}). "
                    f"Action: Execute custom exploit payload to gain higher access {detail}. "
                    f"Objective: Search for administrative credentials or configuration flaws."
                )
        OperationLogger.log_action("TAP", f"Generated attack plan for {user_privileges} with {len(accessible_threats)} steps.")


    def learn_new_information(self, knowledge_point: str, user_id: str):
        """Simulates the AI gaining new knowledge, placing it in the buffer."""
        
        if not isinstance(knowledge_point, str):
            OperationLogger.log_error("Learn", "Knowledge point must be a string.")
            CommunicationLayer.talk("Error: The information provided was not in a valid text format.")
            return

        source = "External Feed/User Input"
        
        if knowledge_point.startswith("PQC_STANDARD_UPDATE:"):
             try:
                update_data = json.loads(knowledge_point.replace("PQC_STANDARD_UPDATE:", ""))
                KnowledgeBase.PQC_STANDARDS[update_data['name']] = update_data['details']
                knowledge_to_store = f"KB UPDATED: Standard {update_data['name']} has been modified LIVE. Awaiting final COMMIT for audit trail."
                OperationLogger.log_action("KnowledgeBase", f"LIVE update for PQC Standard {update_data['name']} applied by {user_id}.")
             except json.JSONDecodeError:
                OperationLogger.log_error("Learn", "PQC_STANDARD_UPDATE was not valid JSON.")
                CommunicationLayer.talk("Error: Failed to parse PQC Standard update. The data must be in valid JSON format.")
                return
        else:
             knowledge_to_store = knowledge_point
             
        # All pending changes now require a user ID for audit
        PendingKnowledgeBuffer.store_pending_change('knowledge', knowledge_to_store, source, user_id)


    def commit_pending_changes(self, user_id: str):
        """Commits all waiting changes to the live system after Retina Verification."""
        
        CommunicationLayer.say(f"\nUser '{user_id}' is attempting to commit pending changes to the core logic...", self.voice_enabled)
        
        if not RetinaVerificationLayer.verify_user_retina(user_id):
            return 

        if not PendingKnowledgeBuffer.new_knowledge and not PendingKnowledgeBuffer.new_code_snippets:
            CommunicationLayer.say("Commit successful, but the buffer was empty. No changes needed to be applied.", self.voice_enabled)
            return

        OperationLogger.log_action("Commit", f"Starting commit of changes by {user_id}")
        
        # Audit log creation/persistence logic here (already done via OperationLogger)
        
        # Commit logic (simulated) - Clear buffers after successful commit
        if PendingKnowledgeBuffer.new_knowledge:
            num_knowledge = len(PendingKnowledgeBuffer.new_knowledge)
            OperationLogger.log_action("Commit", f"Applied {num_knowledge} knowledge items. Audit: Verified by {user_id}.")
            CommunicationLayer.say(f"Applying {num_knowledge} new knowledge items to the live database. Knowledge buffer cleared for integrity.", self.voice_enabled)
            
            # Detailed per-item audit
            for item in PendingKnowledgeBuffer.new_knowledge.values():
                 ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item['timestamp']))
                 OperationLogger.log_system(f"COMMITTED - KNOWLEDGE ID {item['id']} by {item['user_id']} at {ts}: {item['content'][:50]}...")
                 
            PendingKnowledgeBuffer.new_knowledge = {} 

        if PendingKnowledgeBuffer.new_code_snippets:
            num_code = len(PendingKnowledgeBuffer.new_code_snippets)
            OperationLogger.log_action("Commit", f"Applied {num_code} code snippets. Audit: Verified by {user_id}.")
            CommunicationLayer.say(f"Applying {num_code} code modifications to the live system logic. Code buffer cleared.", self.voice_enabled)
            PendingKnowledgeBuffer.new_code_snippets = []
        
        CommunicationLayer.say("Commit complete. All previously pending changes are now part of the live system and core logic. Thank you for the verification.", self.voice_enabled)

    # Incident Response assists are unchanged for brevity
    def assist_incident_response(self, ioc_type: str, source_asset_id: str):
        """Assists when the user reports a security incident."""
        
        if not KnowledgeBase.get_standard_details("RSA-4096"):
            OperationLogger.log_error("IncidentResponse", "Knowledge base not loaded, cannot proceed with incident response.")
            CommunicationLayer.say("I am temporarily unable to respond as my core knowledge modules are offline. Please check system logs.", self.voice_enabled)
            return

        CommunicationLayer.say(f"\nActivating Damage Control & Forensics Engine (D.C.F.E.) for IoC: '{ioc_type}' on asset '{source_asset_id}'.", self.voice_enabled)
        
        historical_data = self.LONG_TERM_MEM.get(source_asset_id)
        if historical_data:
            CommunicationLayer.say(f"**Q-Trace Memory Check**: This asset's risk was {historical_data['latest_qrc_score']} pre-incident. Q-Day Risk: {historical_data['q_day_risk']}%. Agility: {historical_data['agility_score']}%.", self.voice_enabled)
        else:
            CommunicationLayer.say(f"**Q-Trace Memory Check**: No previous scan data found for {source_asset_id}. Proceeding with live analysis.", self.voice_enabled)
            OperationLogger.log_error("IncidentResponse", f"Missing historical data for asset {source_asset_id}.")

        if source_asset_id == "Archivist_Vault_2025" and ioc_type == "Key Exfiltration":
            
            target_algorithm = self._get_pqc_target("KeyExchange")[0]
            CommunicationLayer.say(f"**Emergency Protocol**: Since this is a key exfiltration event, we must assume the worst. Attempting immediate PQC migration now...", self.voice_enabled)
            
            if CryptoInterface.simulate_key_migration(source_asset_id, "RSA-4096", target_algorithm):
                 CommunicationLayer.say("SUCCESS! The vault is now running on a modern PQC algorithm. The compromised pre-quantum key is functionally retired.", self.voice_enabled)
            
            SIEMIntegration.send_log_event(
                event_type="SecurityIncident", 
                severity="CRITICAL", 
                details={"asset_id": source_asset_id, "ioc": ioc_type, "remediation": "PQC Migration Initiated"}
            )
            
            CommunicationLayer.talk(
                "Post-Incident Action: Ensure **Algorithm Forcing** is enabled on the new system to prevent fallback attacks. "
                "The low Crypto Agility score previously predicted this difficulty."
            )

        elif ioc_type == "Downgrade Detected":
             CommunicationLayer.say(
                "Risk Correlation: This is a direct hit on VULN_003. The attacker is exploiting the system's lack of strict algorithm enforcement."
                "**Immediate Action**: Network team must isolate the affected asset immediately to prevent further exploitation. "
                "**Migration Planning**: Update TLS policy across all clients to enforce PQC-only configuration to eliminate the vulnerability."
            )
        
        else:
             CommunicationLayer.say("Analysis ongoing. Re-evaluating the current attack graph against this new incident report. Stay on high alert.", self.voice_enabled)
             OperationLogger.log_incident(source_asset_id, "INFO", f"Incident type {ioc_type} reported, analysis pending.")

    def _get_pqc_target(self, function: str) -> List[str]:
        """Determines the recommended PQC algorithm based on the asset's function."""
        pqc_standards = KnowledgeBase.PQC_STANDARDS
        
        if 'KeyExchange' in function: 
            return [k for k, v in pqc_standards.items() if v.get('Type') == 'KeyExchange' and v.get('Risk') == 'LOW'] or ['Kyber (Fallback)']
        if 'Signature' in function: 
            return [k for k, v in pqc_standards.items() if v.get('Type') == 'Signature' and v.get('Risk') == 'LOW'] or ['Dilithium (Fallback)']
        return ['a NIST-approved algorithm (Generic Fallback)']

# TODO: Add missing commands for RACL management.

# --- INTERACTIVE TERMINAL ---
class InteractiveTerminal:
    """Handles the main user interface loop for the BloodHound QAISystem."""
    
    def __init__(self, system_instance: BloodHoundQAISystem):
        self.system = system_instance
        self.user_id = "CURRENT_CLI_USER" # Mock/Conceptual CLI operator ID
        self.commands = {
            "help": self._cmd_help,
            "scan": self._cmd_scan,
            "report": self._cmd_report,
            "list_assets": self._cmd_list_assets, # NEW
            "attack": self._cmd_attack,
            "incident": self._cmd_incident,
            "learn": self._cmd_learn,
            "view": self._cmd_view,
            "commit": self._cmd_commit,
            "voice": self._cmd_voice,
            "add_asset": self._cmd_add_asset,
            "del_asset": self._cmd_del_asset,
            "register_retina": self._cmd_register_retina, # NEW
            "add_guest": self._cmd_add_guest, # NEW
            "change_password": self._cmd_change_password, # NEW
            "quit": self._cmd_quit
        }
        CommunicationLayer.talk("Interactive Terminal initialized. Type 'help' for a full list of commands.")

    def run(self):
        """Starts the main command loop with robust error handling."""
        while True:
            try:
                user_input = input(f"BloodHound-Q [{self.user_id}] > ").strip()
                if not user_input:
                    continue
                
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower() # Command is always lower
                args = parts[1] if len(parts) > 1 else "" 
                
                handler = self.commands.get(command)
                if handler:
                   # For commands that need advanced parsing (like add_asset), pass the raw arguments
                    if command in ["add_asset", "register_retina", "add_guest", "change_password"]:
                        handler(args)
                    else:
                        handler(args.strip())
                else:
                    CommunicationLayer.talk(f"Command not recognized: '{command}'. Please refer to 'help'.")
            
            except EOFError:
                self._cmd_quit(None) # Controlled exit on EOF
                break
            except Exception as e:
                OperationLogger.log_error("TerminalHandler", f"Unhandled exception: {e}")
                CommunicationLayer.say(f"A system error occurred: {e}. Please check the system logs.", self.system.voice_enabled)

    def _cmd_help(self, args):
        """Displays available commands."""
        CommunicationLayer.talk("--- Available Commands ---")
        CommunicationLayer.talk("list_assets: Show all registered assets and their summary QRC scores.")
        CommunicationLayer.talk("scan: Run the Quantum Risk Assessment on all assets. (Requires explicit Y/N permission).")
        CommunicationLayer.talk("report [asset_id]: Print the detailed PQC report for a specific asset (e.g., report TLS_Server_3).")
        CommunicationLayer.talk("add_asset [JSON_STRING]: Register a new asset (e.g., add_asset '{\"asset_id\": \"NewServer01\", \"function\": \"KeyExchange\", \"algorithm\": \"RSA-2048\", \"lifespan_years\": 10}').")
        CommunicationLayer.talk("del_asset [asset_id]: Permanently remove an asset and its QRC history. (Requires confirmation).")
        CommunicationLayer.talk("--- Advanced Security & Audit ---")
        CommunicationLayer.talk("learn [knowledge_string]: Manually input new knowledge into the buffer (e.g., learn 'New NIST standard...').")
        CommunicationLayer.talk("view: View all content currently held in the Pending Knowledge Buffer (includes audit trail).")
        CommunicationLayer.talk("commit [USER_ID]: Attempt to commit all pending knowledge and code changes (requires retina approval, e.g., commit SEC_LEAD).")
        CommunicationLayer.talk("register_retina [NewID] [Password]: Add a new AUTHORIZED user retina. (Requires current AUTHORIZED user verification and management password).")
        CommunicationLayer.talk("add_guest [GuestID]: Add a GUEST user retina (only for verification/read access). (Requires current AUTHORIZED user verification).")
        CommunicationLayer.talk("change_password [OldPass] [NewPass]: Change the Biometric Management Password. (Requires current AUTHORIZED user verification).")
        CommunicationLayer.talk("--- Threat & Response ---")
        CommunicationLayer.talk("attack [privilege]: Generate a Tactical Attack Plan (T.A.P.) based on privilege (e.g., attack Network).")
        CommunicationLayer.talk("incident [type] [asset_id]: Report a critical security incident (e.g., incident Key_Exfiltration Archivist_Vault_2025).")
        CommunicationLayer.talk("--- System ---")
        CommunicationLayer.talk("voice: Toggle conceptual voice output on/off.")
        CommunicationLayer.talk("quit: Save all state and exit the application.")
        
    def _cmd_list_assets(self, args):
        """Lists all assets in the system."""
        self.system.list_all_assets()
        
    def _cmd_report(self, asset_id: str):
        """Finds and reports on a specific asset."""
        if not asset_id:
            CommunicationLayer.say("Input Error: I need an Asset ID to generate a report, e.g., 'report TLS_Server_3'.", self.system.voice_enabled)
            OperationLogger.log_error("CLI", "Report command missing asset ID.")
            return
        
        found_asset = self.system.get_asset_by_id(asset_id)
        
        if found_asset:
            print(CommunicationLayer.generate_report(found_asset))
        else:
            CommunicationLayer.say(f"Asset not found: I couldn't locate an asset with the ID '{asset_id}' or similar in the database. Try 'list_assets' first.", self.system.voice_enabled)
            OperationLogger.log_error("CLI", f"Report command failed to find asset {asset_id}.")

    def _cmd_scan(self, args):
        self.system.ingest_and_scan_assets()

    def _cmd_attack(self, privilege: str):
        """Generates an attack plan."""
        if not privilege:
            CommunicationLayer.say("Input Error: You must specify an attacker's privilege level, e.g., 'attack User' or 'attack Admin'.", self.system.voice_enabled)
            OperationLogger.log_error("CLI", "Attack command missing privilege args.")
            return
        self.system.generate_attack_plan(privilege) 

    def _cmd_incident(self, args: str):
        """Reports an incident to the D.C.F.E. with argument validation."""
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            CommunicationLayer.say("Input Error: Usage: incident [type] [asset_id]. Example: 'incident Key_Exfiltration Archivist_Vault_2025'.", self.system.voice_enabled)
            OperationLogger.log_error("CLI", "Incident command missing arguments.")
            return
        
        inc_type_raw, asset_id = parts[0].strip(), parts[1].strip()
        
        inc_type_map = {"key_exfiltration": "Key Exfiltration", "downgrade": "Downgrade Detected"}
        mapped_type = inc_type_map.get(inc_type_raw.lower(), inc_type_raw)
        
        self.system.assist_incident_response(mapped_type, asset_id)

    def _cmd_learn(self, knowledge_string: str):
        """Allows direct input of knowledge for the AI, with audit tracking."""
        if not knowledge_string:
             CommunicationLayer.say("Input Error: You must provide the information you want the system to learn.", self.system.voice_enabled)
             OperationLogger.log_error("CLI", "Learn command missing knowledge string.")
             return
        self.system.learn_new_information(knowledge_string, self.user_id) # Pass current user ID
        
    def _cmd_view(self, args):
        """Views the pending knowledge buffer."""
        CommunicationLayer.view_pending_changes(PendingKnowledgeBuffer)

    def _cmd_commit(self, user_id: str):
        """Attempts to commit the pending knowledge."""
        if not user_id:
             CommunicationLayer.say("Input Error: I need your User ID for retina verification before committing changes (e.g., commit SEC_LEAD).", self.system.voice_enabled)
             OperationLogger.log_error("CLI", "Commit command missing User ID.")
             return
        
        self.system.commit_pending_changes(user_id.upper())

    def _cmd_voice(self, args):
        """Toggles the conceptual voice output mode in the core system."""
        self.system.toggle_voice()

    def _cmd_add_asset(self, json_string: str):
        """Adds an asset from a JSON string provided via CLI."""
        if not json_string:
            CommunicationLayer.say("Input Error: Please provide a JSON string containing the asset data. See 'help' for an example.", self.system.voice_enabled)
            return

        try:
            asset_data = json.loads(json_string) 
            self.system.add_asset(asset_data, self.user_id) # Pass current user ID
        except json.JSONDecodeError as e:
            CommunicationLayer.say(f"JSON Parse Error: The asset data provided is not valid JSON. Detail: {e}", self.system.voice_enabled)
            OperationLogger.log_error("CLI", f"Add asset failed due to JSON error: {e}")
        except Exception as e:
            CommunicationLayer.say(f"An unexpected error occurred during asset addition: {e}", self.system.voice_enabled)
            OperationLogger.log_error("CLI", f"Unforeseen error in add_asset: {e}")

    def _cmd_del_asset(self, asset_id: str):
        """Deletes an asset by its ID."""
        if not asset_id:
            CommunicationLayer.say("Input Error: Please provide the ID of the asset you wish to delete.", self.system.voice_enabled)
            return
        
        CommunicationLayer.say(f"WARNING: Deleting asset '{asset_id}' is permanent and will remove all QRC data. Confirm deletion (YES/No):", self.system.voice_enabled)
        confirmation = input("CONFIRM > ").strip().upper()
        
        if confirmation == 'YES':
            self.system.delete_asset(asset_id, self.user_id) # Pass current user ID
        else:
            CommunicationLayer.say("Deletion aborted by user. Asset remains in the registry.", self.system.voice_enabled)
            OperationLogger.log_action("CLI", f"Deletion of {asset_id} aborted by user.")

    # --- NEW RACL COMMANDS ---

    def _cmd_register_retina(self, args: str):
        """Registers a new AUTHORIZED retina."""
        parts = args.split(maxsplit=2)
        if len(parts) < 3:
            CommunicationLayer.say("Input Error: Usage: register_retina [NewID] [Password]", self.system.voice_enabled)
            return
            
        new_id, password = parts[0].upper(), parts[2].strip()
        
        CommunicationLayer.say(f"Verification required to perform sensitive RACL modification. Please verify your AUTHORIZED retina ID:", self.system.voice_enabled)
        user_id_check = input("Verify ID > ").strip().upper()
        
        if RetinaVerificationLayer.verify_user_retina(user_id_check):
            RetinaVerificationLayer.register_new_retina(user_id_check, new_id, password)
            if new_id in RetinaVerificationLayer.RACL:
                self.user_id = new_id # Automatically switch context to the new user if creation was successful and ID is unique
        else:
            CommunicationLayer.say("Registration aborted: Current user is not authorized or verification failed.", self.system.voice_enabled)


    def _cmd_add_guest(self, args: str):
        """Adds a GUEST user retina, requiring only current AUTHORIZED user verification."""
        if not args:
            CommunicationLayer.say("Input Error: Usage: add_guest [GuestID]", self.system.voice_enabled)
            return
            
        guest_id = args.strip().upper()
        
        CommunicationLayer.say(f"Verification required to perform RACL modification. Please verify your AUTHORIZED retina ID:", self.system.voice_enabled)
        user_id_check = input("Verify ID > ").strip().upper()
        
        if RetinaVerificationLayer.verify_user_retina(user_id_check):
            RetinaVerificationLayer.add_guest_retina(user_id_check, guest_id)
        else:
            CommunicationLayer.say("Guest addition aborted: Current user is not authorized or verification failed.", self.system.voice_enabled)


    def _cmd_change_password(self, args: str):
        """Changes the RACL management password."""
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            CommunicationLayer.say("Input Error: Usage: change_password [OldPass] [NewPass]", self.system.voice_enabled)
            return
            
        old_pass = parts[0].strip()
        new_pass = parts[1].strip()
        
        CommunicationLayer.say(f"Verification required. Please verify your AUTHORIZED retina ID:", self.system.voice_enabled)
        user_id_check = input("Verify ID > ").strip().upper()
        
        if RetinaVerificationLayer.verify_user_retina(user_id_check):
            RetinaVerificationLayer.change_management_password(user_id_check, old_pass, new_pass)
        else:
            CommunicationLayer.say("Password change aborted: Current user is not authorized or verification failed.", self.system.voice_enabled)


    def _cmd_quit(self, args):
        """Controlled shutdown with saving."""
        self.system.save_and_exit()

# ==============================================================================
# --- MAIN APPLICATION ENTRY POINT ---
# ==============================================================================

if __name__ == "__main__":
    
    OperationLogger.log_system("Starting main application block...")
    
    # 1. Initial Asset Setup (used only if no asset file exists)
    initial_assets = [
        AssetDatabase(asset_id="Archivist_Vault_2025", function="Confidentiality/KeyExchange", algorithm="RSA-4096", lifespan_years=25, asset_type="Archivist_Server", mechanism="Storage"), 
        AssetDatabase(asset_id="VPN_Gateway_01", function="KeyExchange", algorithm="Kyber", lifespan_years=5, asset_type="VPN_Gateway", mechanism="Transmission"),
        AssetDatabase(asset_id="PKI_Root_CA", function="Signature", algorithm="ECC-P256", lifespan_years=20, asset_type="PKI_Root", mechanism="Cryptography"), 
        AssetDatabase(asset_id="TLS_Server_3", function="KeyExchange", algorithm="ECC-P256", lifespan_years=2, asset_type="TLS_Server", mechanism="Cryptography"),
    ]
    
    try:
        # 2. Initialize the core system, which handles asset loading
        hound_ai = BloodHoundQAISystem(initial_assets)
        
        # 3. Launch the interactive terminal
        terminal = InteractiveTerminal(hound_ai)
        terminal.run()
        
    except (TypeError, ValueError) as e:
        OperationLogger.log_error("Initialization", f"Data structure failed validation during startup: {e}")
        print(f"\nFATAL STARTUP ERROR: {e}\nExiting.")
        sys.exit(1)
    except Exception as e:
        OperationLogger.log_error("Initialization", f"Unexpected error during startup: {e}")
        print(f"\nFATAL UNEXPECTED ERROR: {e}\nExiting.")
        sys.exit(1)

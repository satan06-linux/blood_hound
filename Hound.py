import time

# --- PQC and STANDARDS (External Knowledge Base) ---
# Simulates the AI's core, live knowledge base.
PQC_STANDARDS = {
    "Kyber": {"Type": "KeyExchange", "Security": "Level III", "Risk": "LOW"},
    "Dilithium": {"Type": "Signature", "Security": "Level III", "Risk": "LOW"},
    "RSA-4096": {"Type": "KeyExchange", "Security": "Pre-Quantum", "Risk": "HIGH"},
    "ECC-P256": {"Type": "Signature", "Security": "Pre-Quantum", "Risk": "HIGH_MEDIUM"}
}

VULNERABILITY_REPORT = {
    "VULN_001": {"asset_id": "Archivist_Vault_2025", "type": "LateralMovement", "privilege_needed": "User", "target_key": "PQC Key Store", "risk_score": 95},
    "VULN_002": {"asset_id": "TLS_Server_3", "type": "WeakHashFunction", "privilege_needed": "LocalAdmin", "target_key": "Session Key", "risk_score": 50},
}

class AssetDatabase:
    """Represents a component in the system and stores the AI's analysis over time."""
    def __init__(self, asset_id, function, algorithm, lifespan_years, access_paths=None):
        self.asset_id = asset_id
        self.function = function
        self.algorithm = algorithm
        self.lifespan_years = lifespan_years
        self.access_paths = access_paths or []
        self.qrc_score = 0
        self.ai_recommendation = ""
        self.last_scanned = time.time()

class RetinaVerificationLayer:
    """Mock authorization system for all critical changes."""
    is_verified = False
    
    @classmethod
    def verify_user_retina(cls, user_id):
        """Simulates the biometrical verification process."""
        CommunicationLayer.talk(f"Retina Verification initiated for user ID: {user_id}...")
        
        if user_id in ["AUTHORIZED_User_01", "HACKERAI_ADMIN"]: 
            cls.is_verified = True
            CommunicationLayer.talk("ACCESS GRANTED. The AI is now authorized for knowledge updates.")
            return True
        else:
            cls.is_verified = False
            CommunicationLayer.talk("ACCESS DENIED. Knowledge and code modification is forbidden until a verified user approves.")
            return False

class PendingKnowledgeBuffer:
    new_knowledge = {}
    new_code_snippets = []
    
    @classmethod
    def store_pending_change(cls, change_type, content, source):
        """Stores a change that the AI has 'learned' but not yet integrated."""
        if change_type == 'knowledge':
            key = f"K_PENDING_{len(cls.new_knowledge)}"
            cls.new_knowledge[key] = {"content": content, "source": source}
        elif change_type == 'code':
            cls.new_code_snippets.append({"content": content, "source": source})
        
        CommunicationLayer.talk("New information has been securely placed in the **Pending Knowledge Buffer** awaiting Retina Verification.")

    @classmethod
    def view_pending_changes(cls):
        """Allows the user to see what is waiting for approval."""
        if cls.new_knowledge or cls.new_code_snippets:
            CommunicationLayer.talk(f"--- Pending Changes Requiring Retina Approval ---")
            CommunicationLayer.talk(f"New Knowledge Items: {len(cls.new_knowledge)}")
            CommunicationLayer.talk(f"New Code/Logic Changes: {len(cls.new_code_snippets)}")
        else:
            CommunicationLayer.talk("The Pending Knowledge Buffer is currently empty.")

class CommunicationLayer:
    """Handles all output, ensuring the AI 'speaks' naturally."""

    @staticmethod
    def talk(message):
        """Standardized output method for the AI's voice."""
        print(f"[{time.strftime('%H:%M:%S', time.localtime())} HackerAI]: {message}")

    @staticmethod
    def generate_report(asset: AssetDatabase):
        """Provides a detailed technical report."""
        report = (
            f"\n--- Technical Assessment Report for {asset.asset_id} ---\n"
            f"  > Function: {asset.function}\n"
            f"  > Algorithm: {asset.algorithm} (Lifespan: {asset.lifespan_years} yrs)\n"
            f"  > **Quantum Risk Score (0-100): {asset.qrc_score}**\n"
            f"  > High-Level Conclusion: {asset.ai_recommendation}\n"
        )
        return report



class BloodHoundQAISystem:
    
    CRQC_TIMELINE = 15
    LONG_TERM_MEM = {} 
    
    def __init__(self, initial_assets):
        self.assets = initial_assets
        CommunicationLayer.talk("Project BloodHound-Q Initializing. Welcome, authorized user. Beginning asset ingestion.")

    def ingest_and_scan_assets(self):
        assets_needing_attention = 0
        
        for asset in self.assets:
            # QRC Resilience Engine Logic
            if asset.algorithm in PQC_STANDARDS and PQC_STANDARDS[asset.algorithm]['Risk'] == "HIGH":
                future_vulnerable_years = self.CRQC_TIMELINE - asset.lifespan_years
                if future_vulnerable_years >= 0:
                    asset.qrc_score = 90 + (future_vulnerable_years * 2)
                    asset.ai_recommendation = f"CRITICAL. Immediate migration to {self._get_pqc_target(asset.function)} is mandatory."
                    assets_needing_attention += 1
                else:
                    asset.qrc_score = 10
                    asset.ai_recommendation = "Low PQC risk due to a short lifespan. Monitor only."
            else:
                asset.qrc_score = 5
                asset.ai_recommendation = "Quantum-Safe or non-vulnerable algorithm currently in use."
            
            self.LONG_TERM_MEM[asset.asset_id] = {
                "creation_time": asset.last_scanned,
                "lifespan": asset.lifespan_years,
                "initial_algorithm": asset.algorithm,
                "latest_qrc_score": asset.qrc_score
            }
        
        CommunicationLayer.talk(f"Asset ingestion complete. I have evaluated {len(self.assets)} assets.")
        if assets_needing_attention > 0:
            CommunicationLayer.talk(f"Attention! I have identified {assets_needing_attention} critical assets with HIGH quantum risk. We must prioritize their migration.")
        else:
            CommunicationLayer.talk("Assessment shows low-risk across the board for now.")
            
    # --- Tactical Attack Planner (T.A.P.) ---
    def generate_attack_plan(self, user_privileges: str):
        """Generates a sequential attack plan when the user asks 'How to attack'."""
        CommunicationLayer.talk(f"\nUnderstood. Initiating Tactical Attack Planner (T.A.P.) to model an attack from a '{user_privileges}' perspective.")
        
        accessible_threats = [v for v in VULNERABILITY_REPORT.values() 
                              if v["privilege_needed"] in [user_privileges, "User"]]
        
        if not accessible_threats:
            return CommunicationLayer.talk(f"I found no entry points for a '{user_privileges}' user. Reconnaissance should be expanded.")
        
        accessible_threats.sort(key=lambda x: x["risk_score"], reverse=True)
        
        CommunicationLayer.talk("Generating a prioritized attack sequence...")
        
        for i, threat in enumerate(accessible_threats):
            if threat["type"] == "LateralMovement":
                CommunicationLayer.talk(
                    f"STEP {i+1}: Critical Lateral Movement Pivot. Exploit VULN_001. "
                    f"Action: Use the pre-mapped path of least resistance to pivot toward the key store. "
                    f"Objective: Compromise the integrity of the crucial QRC transition process."
                )
            else:
                CommunicationLayer.talk(
                    f"STEP {i+1}: Medium-Risk Exploit. Exploit {threat['type']} on {threat['asset_id']}. "
                    f"Action: Use a custom payload to gain higher access. "
                    f"Objective: Search for administrative credentials or configuration flaws."
                )

    # --- Damage Control & Forensics Engine (D.C.F.E.) ---
    def assist_incident_response(self, ioc_type: str, source_asset_id: str):
        """Assists when the user reports 'The system is damaged'."""
        CommunicationLayer.talk(f"\nActivating Damage Control & Forensics Engine (D.C.F.E.) for IoC: '{ioc_type}' on '{source_asset_id}'.")
        
        historical_data = self.LONG_TERM_MEM.get(source_asset_id)
        if historical_data:
            CommunicationLayer.talk(f"Consulting Q-Trace Memory... The asset cryptographic risk was {historical_data['latest_qrc_score']} pre-incident.")

        if source_asset_id == "Archivist_Vault_2025" and ioc_type == "Key Exfiltration":
            CommunicationLayer.talk(
                "Risk Correlation: This matches the lateral pivot attack (VULN_001) I mapped earlier. "
                "Immediate Action: **BLOCK ALL LATERAL TRAFFIC** on the mapped pivot pathway. This is the attacker's exfiltration route."
            )
            CommunicationLayer.talk(
                "Final Remediation: Since the key is compromised, the old pre-quantum algorithm MUST be retired. "
                "Begin the recommended **Kyber/Dilithium Hybrid Migration** on the replacement system immediately."
            )

    # --- Secure Learning & Commit ---
    def learn_new_information(self, knowledge_point: str, is_code_change: bool = False):
        """Simulates the AI gaining new knowledge, placing it in the buffer."""
        source = "Automated Monitoring"
        change_type = 'code' if is_code_change else 'knowledge'
        PendingKnowledgeBuffer.store_pending_change(change_type, knowledge_point, source)

    def commit_pending_changes(self, user_id):
        """Commits all waiting changes to the live system after Retina Verification."""
        CommunicationLayer.talk(f"\nUser '{user_id}' is attempting to commit pending changes...")
        
        if not RetinaVerificationLayer.verify_user_retina(user_id):
            return 

        if not PendingKnowledgeBuffer.new_knowledge and not PendingKnowledgeBuffer.new_code_snippets:
            CommunicationLayer.talk("Commit successful, but the buffer was empty. No changes applied.")
            return

        # Commit logic (simulated)
        if PendingKnowledgeBuffer.new_knowledge:
            CommunicationLayer.talk(f"Applying {len(PendingKnowledgeBuffer.new_knowledge)} new knowledge items to the live database (PQC_STANDARDS, etc.)...")
            PendingKnowledgeBuffer.new_knowledge = {} 

        if PendingKnowledgeBuffer.new_code_snippets:
            CommunicationLayer.talk(f"Applying {len(PendingKnowledgeBuffer.new_code_snippets)} code modifications to the live system logic (QRC Engine, etc.)...")
            PendingKnowledgeBuffer.new_code_snippets = [] 
        
        CommunicationLayer.talk("Knowledge update complete. All committed changes are now active in the system's live logic.")


    # --- Utility Function ---
    def _get_pqc_target(self, function):
        if 'KeyExchange' in function: return 'Kyber'
        if 'Signature' in function: return 'Dilithium'
        return 'a NIST-approved algorithm'

# ==============================================================================
# --- FINAL EXECUTION AND INTERACTION ---
# ==============================================================================

if __name__ == "__main__":
    
    # 1. Setup and Initial Scan
    initial_assets = [
        AssetDatabase("Archivist_Vault_2025", "Confidentiality/KeyExchange", "RSA-4096", 25),
        AssetDatabase("TLS_Server_3", "KeyExchange", "ECC-P256", 2),
    ]
    hound_ai = BloodHoundQAISystem(initial_assets)
    hound_ai.ingest_and_scan_assets()

    # 2. AI Gathers New Knowledge (Placed in Buffer)
    hound_ai.learn_new_information("The NIST PQC Finalist 'Sphinx' has been revoked due to a new side-channel attack.", is_code_change=True)
    
    # 3. Unauthorized User Attempts to Commit (Fails)
    CommunicationLayer.talk("\nUser: 'Try to commit those new learnings now.'")
    hound_ai.commit_pending_changes("ROGUE_USER_99") 
    
    # 4. Authorized User Commits (Success)
    CommunicationLayer.talk("\nUser: 'I'll handle the verification. Commit changes.'")
    hound_ai.commit_pending_changes("AUTHORIZED_User_01")
    
    # 5. User Requests an Attack Plan
    hound_ai.generate_attack_plan(user_privileges="User")
    
    # 6. User Reports an Incident
    CommunicationLayer.talk("\nUser: 'We have an incident. A key on the Archivist Vault was exfiltrated. The system is damaged.'")
    hound_ai.assist_incident_response("Key Exfiltration", "Archivist_Vault_2025")

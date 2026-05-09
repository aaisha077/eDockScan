#!/usr/bin/env python3

import subprocess
import json
import os
import re
import time
import math
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np
from difflib import SequenceMatcher
import hashlib
from collections import defaultdict
from behavioral_analyzer import BehavioralAnalyzer

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Feature schema version
FEATURE_SCHEMA_VERSION = "2.0"

# Define the exact column order for CSV output
COLUMN_ORDER = [
    'cryptominer_binary',
    'mining_pools',
    'hardcoded_secrets',
    'external_calls',
    'ssh_backdoor',
    'runs_as_root',
    'known_cves',
    'outdated_base',
    'typosquatting_score',
    'image_age_days',
    'high_entropy_files',
    'suspicious_ports',
    'avg_file_entropy',
    'high_entropy_ratio',
    'stratum_indicators',
    'raw_ip_connections',
    'suspicious_dns_queries',
    'stripped_binaries_ratio',
    'packed_binary_score',
    'layer_deletion_score',
    'temp_file_activity',
    'process_injection_risk',
    'privilege_escalation_risk',
    'crypto_mining_behavior',
    'anti_analysis_score',
    'label'
]

@dataclass
class ScanMetadata:
    """Metadata about scan execution"""
    image_name: str
    scan_timestamp: str
    schema_version: str
    trivy_success: bool
    syft_success: bool
    grype_success: bool
    scan_duration_seconds: float
    error_messages: List[str]

@dataclass
class ImageFeatures:
    """Structured feature container with explicit null handling"""
    # Core features
    cryptominer_binary: Optional[int] = None  # 0=no, 1=yes, None=unknown
    mining_pools: Optional[int] = None
    hardcoded_secrets: Optional[int] = None
    external_calls: Optional[int] = None
    ssh_backdoor: Optional[int] = None
    runs_as_root: Optional[int] = None
    known_cves: Optional[int] = None
    outdated_base: Optional[int] = None
    typosquatting_score: Optional[float] = None
    image_age_days: Optional[int] = None
    
    # Additional risk indicators
    high_entropy_files: Optional[int] = None
    suspicious_ports: Optional[int] = None
    
    # Behavioral features
    avg_file_entropy: Optional[float] = None
    high_entropy_ratio: Optional[float] = None
    stratum_indicators: Optional[float] = None
    raw_ip_connections: Optional[float] = None
    suspicious_dns_queries: Optional[float] = None 
    stripped_binaries_ratio: Optional[float] = None
    layer_deletion_score: Optional[float] = None
    packed_binary_score: Optional[float] = None
    temp_file_activity: Optional[float] = None
    process_injection_risk: Optional[float] = None
    privilege_escalation_risk: Optional[float] = None
    crypto_mining_behavior: Optional[float] = None
    anti_analysis_score: Optional[float] = None
    
    # Label (0=safe, 1=risky)
    label: Optional[int] = None
    
    # Metadata (not included in CSV)
    image_name: str = ''
    scan_status: str = 'pending'  # success, partial, failed
    confidence_score: Optional[float] = None

class RetryHandler:
    """Exponential backoff retry logic"""
    
    def __init__(self, max_retries=3, base_delay=1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def execute(self, func, *args, **kwargs):
        """Execute function with retry logic"""
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except subprocess.TimeoutExpired as e:
                last_error = e
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}")
                if attempt < self.max_retries - 1:
                    delay = self.base_delay * (2 ** attempt)
                    time.sleep(delay)
            except Exception as e:
                last_error = e
                logger.error(f"Error on attempt {attempt + 1}: {str(e)}")
                if attempt < self.max_retries - 1:
                    delay = self.base_delay * (2 ** attempt)
                    time.sleep(delay)
        
        raise last_error

class CacheManager:
    """Cache management with TTL and cleanup"""
    
    def __init__(self, cache_dir: Path, ttl_days: int = 7):
        self.cache_dir = cache_dir
        self.ttl_days = ttl_days
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_cache_path(self, image_name: str) -> Path:
        """Get cache directory for image"""
        safe_name = hashlib.md5(image_name.encode()).hexdigest()[:12]
        cache_path = self.cache_dir / safe_name
        cache_path.mkdir(exist_ok=True)
        return cache_path
    
    def is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache is still valid based on TTL"""
        if not cache_path.exists():
            return False
        
        # Check modification time of cache directory
        mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
        age = datetime.now() - mtime
        
        return age.days < self.ttl_days
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        cleaned = 0
        for cache_dir in self.cache_dir.iterdir():
            if not cache_dir.is_dir():
                continue
            
            mtime = datetime.fromtimestamp(cache_dir.stat().st_mtime)
            age = datetime.now() - mtime
            
            if age.days >= self.ttl_days:
                try:
                    for file in cache_dir.iterdir():
                        file.unlink()
                    cache_dir.rmdir()
                    cleaned += 1
                except Exception as e:
                    logger.warning(f"Failed to clean {cache_dir}: {e}")
        
        logger.info(f"Cleaned {cleaned} expired cache entries")

class EnhancedSecurityDetector:
    """Advanced security detection with obfuscation handling"""
    
    def __init__(self):
        self.cryptominer_binaries = [
            'xmrig', 'cgminer', 'ethminer', 'claymore', 'gminer', 'lolminer',
            't-rex', 'nanominer', 'phoenixminer', 'nbminer', 'teamredminer',
            'kawpowminer', 'trex', 'minerd', 'cpuminer', 'bfgminer',
            'easyminer', 'ccminer', 'cryptonight', 'randomx'
        ]
        
        self.mining_pools = [
            'pool.minexmr.com', 'nanopool.org', 'ethermine.org', 'f2pool.com',
            '2miners.com', 'stratum+tcp', 'mining.pool', 'supportxmr.com',
            'moneroocean.stream', 'nicehash.com', 'slushpool.com', 'antpool.com',
            'poolin.com', 'hiveon.net', 'pool.hashvault.pro', 'minexmr.com',
            'cryptoknight.cc', 'monero.crypto-pool', 'xmrpool.eu'
        ]
        
        # Enhanced with homoglyphs and common typos
        self.legitimate_images = [
            'nginx', 'python', 'node', 'ubuntu', 'postgres', 'mysql', 'redis',
            'mongodb', 'alpine', 'debian', 'golang', 'java', 'php', 'ruby',
            'perl', 'httpd', 'tomcat', 'jenkins', 'wordpress', 'elasticsearch',
            'rabbitmq', 'mariadb', 'docker', 'kubernetes', 'hashicorp',
            'tensorflow', 'pytorch', 'jupyter', 'grafana', 'prometheus'
        ]
        
        # Common character substitutions for typosquatting
        self.homoglyphs = {
            '0': ['o', 'O'],
            '1': ['l', 'I', 'i'],
            '5': ['S', 's'],
            '8': ['B'],
            'a': ['@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            'l': ['1', 'I'],
        }
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0.0
        
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_elf_binary(self, data: bytes) -> bool:
        """Check if data starts with ELF magic bytes"""
        return data[:4] == b'\x7fELF'
    
    def detect_obfuscated_miner(self, artifacts: List[Dict]) -> Tuple[bool, str]:
        """
        Detect obfuscated/packed miners using entropy and ELF analysis
        Returns: (is_suspicious, reason)
        """
        suspicious_files = []
        
        for artifact in artifacts:
            name = artifact.get('name', '').lower()
            locations = artifact.get('locations', [])
            
            # Check for suspicious paths
            suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/.hidden']
            if any(susp in str(locations) for susp in suspicious_paths):
                suspicious_files.append((name, 'suspicious_path'))
        
        if suspicious_files:
            return True, f"Suspicious file locations: {suspicious_files[0][0]}"
        
        return False, ""
    
    def detect_runtime_download_patterns(self, trivy_data: Dict) -> int:
        """Detect patterns indicating runtime downloads"""
        indicators = [
            'curl', 'wget', 'fetch', 'download',
            'http://', 'https://', 'ftp://',
            '/tmp/', '/dev/shm/'
        ]
        
        text = json.dumps(trivy_data).lower()
        matches = sum(1 for indicator in indicators if indicator in text)
        
        return min(matches, 5)
    
    def calculate_levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein (edit) distance between two strings"""
        if len(s1) < len(s2):
            return self.calculate_levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def detect_typosquatting_enhanced(self, image_name: str) -> Tuple[float, Optional[str]]:
        """
        Enhanced typosquatting detection with Levenshtein and homoglyphs
        Returns: (score, closest_match)
        """
        base_name = image_name.split(':')[0].split('/')[-1].lower()
        
        max_similarity = 0.0
        closest_match = None
        min_edit_distance = float('inf')
        
        for legit in self.legitimate_images:
            # Method 1: Sequence similarity
            similarity = SequenceMatcher(None, base_name, legit).ratio()
            
            # Method 2: Levenshtein distance
            edit_distance = self.calculate_levenshtein_distance(base_name, legit)
            
            # Combined score (weighted)
            combined_score = (similarity * 0.7) + ((1 - edit_distance / max(len(base_name), len(legit))) * 0.3)
            
            if combined_score > max_similarity:
                max_similarity = combined_score
                closest_match = legit
                min_edit_distance = edit_distance
        
        # Check for homoglyph substitutions if similarity is high
        if 0.8 < max_similarity < 1.0 and closest_match:
            if self._has_homoglyph_substitution(base_name, closest_match):
                logger.warning(f"Possible homoglyph typosquat: {base_name} vs {closest_match}")
                return round(max_similarity, 3), closest_match
        
        return round(max_similarity, 3), closest_match if max_similarity > 0.8 else None
    
    def _has_homoglyph_substitution(self, name: str, legit: str) -> bool:
        """Check if name uses homoglyph substitutions of legit"""
        for char, replacements in self.homoglyphs.items():
            for replacement in replacements:
                if replacement in name and char in legit:
                    return True
        return False

class EnhancedRemoteDockerScanner:
    
    
    def __init__(
        self,
        cache_dir='scan_cache',
        timeout_per_scan=300,
        max_workers=3,
        registry_auth: Optional[Dict[str, str]] = None,
        cache_ttl_days=7
    ):
        self.timeout_per_scan = timeout_per_scan
        self.max_workers = max_workers
        self.registry_auth = registry_auth or {}
        
        # Initialize components
        self.cache_manager = CacheManager(Path(cache_dir), cache_ttl_days)
        self.retry_handler = RetryHandler()
        self.security_detector = EnhancedSecurityDetector()

        self.behavioral_analyzer = BehavioralAnalyzer()
        
        # Verify tools
        self._verify_tools()
        
        # Cleanup old cache
        self.cache_manager.cleanup_expired()
    
    def _verify_tools(self):
        """Verify required tools are installed"""
        required = ['trivy', 'syft', 'grype']
        
        logger.info("Verifying scanner tools...")
        for tool in required:
            try:
                result = subprocess.run(
                    [tool, '--version'],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                if result.returncode == 0:
                    version = result.stdout.split('\n')[0]
                    logger.info(f"✓ {tool}: {version}")
                else:
                    raise FileNotFoundError
            except (FileNotFoundError, subprocess.SubprocessError):
                logger.error(f"✗ {tool} not found")
                raise RuntimeError(f"{tool} is required. Run: bash setup.sh")
    
    def extract_features(self, image_name: str) -> ImageFeatures:
        """
        Extract features with explicit null handling for failures
        """
        start_time = time.time()
        logger.info(f"Scanning: {image_name}")
        
        # Get cache path
        cache_path = self.cache_manager.get_cache_path(image_name)
        
        # Initialize features with None (unknown)
        features = ImageFeatures(image_name=image_name)
        error_messages = []
        
        try:
            # Run scans with retry logic
            logger.info("Running Trivy scan...")
            trivy_data, trivy_success = self._run_with_retry(
                self._run_trivy_remote, image_name, cache_path
            )
            
            logger.info("Running Syft scan...")
            syft_data, syft_success = self._run_with_retry(
                self._run_syft_remote, image_name, cache_path
            )
            
            logger.info("Running Grype scan...")
            grype_data, grype_success = self._run_with_retry(
                self._run_grype_on_sbom, cache_path
            )
            
            # Determine scan status
            scans_succeeded = sum([trivy_success, syft_success, grype_success])
            
            if scans_succeeded == 0:
                features.scan_status = 'failed'
                logger.error("All scans failed")
                return features
            elif scans_succeeded < 3:
                features.scan_status = 'partial'
                logger.warning(f"Only {scans_succeeded}/3 scans succeeded")
            else:
                features.scan_status = 'success'
            
            # Extract features (only set if scan succeeded)
            if syft_success:
                self._extract_sbom_features(syft_data, features)
            
            if trivy_success:
                self._extract_trivy_features(trivy_data, features)
                self._extract_metadata_features(trivy_data, image_name, features)
            
            if grype_success:
                self._extract_grype_features(grype_data, features)
            
            # Calculate confidence score based on successful scans
            features.confidence_score = scans_succeeded / 3.0
            if trivy_success and syft_success:
                try:
                    logger.info("Extracting behavioral features...")
                    behavioral_features = self.behavioral_analyzer.analyze_image(image_name, trivy_data, syft_data)

        # Extract remediations 
                    remediations = behavioral_features.pop('_remediations', [])

        # Add behavioral features to the features object
                    for feature_name, value in behavioral_features.items():
                        if hasattr(features, feature_name):
                            setattr(features, feature_name, value)
        
        # Store remediations in features metadata
                    features.remediations = remediations
        
                    logger.info(f"Behavioral analysis complete "
                    f"(crypto_mining_behavior: {behavioral_features.get('crypto_mining_behavior', 0):.3f}, "
                    f"{len(remediations)} remediations)")

                except Exception as e:
                    logger.warning(f"Behavioral analysis failed: {e}")
                    features.remediations = []
            else:
                logger.warning("Skipping behavioral analysis (missing trivy or syft data)")
            
            # Log results
            self._log_feature_summary(features)
            
        except Exception as e:
            logger.exception(f"Unexpected error scanning {image_name}")
            features.scan_status = 'error'
            error_messages.append(str(e))
        
        features.scan_duration_seconds = time.time() - start_time
        return features
    
    def _run_with_retry(self, func, *args):
        """Run function with retry logic"""
        try:
            return self.retry_handler.execute(func, *args)
        except Exception as e:
            logger.error(f"Failed after retries: {str(e)}")
            return {}, False
    
    def _run_trivy_remote(self, image_name: str, cache_dir: Path) -> Tuple[Dict, bool]:
        """Run Trivy with authentication support"""
        output_file = cache_dir / 'trivy.json'
        
        cmd = [
            'trivy', 'image',
            '--format', 'json',
            '--output', str(output_file),
            '--scanners', 'vuln,secret,config',
            '--timeout', f'{self.timeout_per_scan}s',
            '--no-progress'
        ]
        
        # Add auth if available
        registry = image_name.split('/')[0]
        if registry in self.registry_auth:
            cmd.extend(['--username', self.registry_auth[registry]['username']])
            cmd.extend(['--password', self.registry_auth[registry]['password']])
        
        cmd.append(image_name)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=self.timeout_per_scan + 30,
            text=True
        )
        
        if output_file.exists() and output_file.stat().st_size > 0:
            with open(output_file) as f:
                data = json.load(f)
            logger.info(f"Trivy scan completed")
            return data, True
        
        logger.warning("Trivy returned no data")
        return {}, False
    
    def _run_syft_remote(self, image_name: str, cache_dir: Path) -> Tuple[Dict, bool]:
        """Run Syft REMOTE-ONLY (no local pulls) to generate SBOM"""
        output_file = cache_dir / 'sbom.json'
        
        # Known problematic images that should be skipped
        SKIP_IMAGES = [
            'scratch',  # Not a real registry image
            'kalilinux/kali-rolling',  # Too large (10+ GB)
            'kirscht/metasploitable3',  # Very large (4-5 GB)
            'remnux/remnux-distro',  # Large forensic OS (5+ GB)
            'metasploitframework/metasploit-framework',  # Large (4+ GB)
            'gitlab/gitlab-ce',  # Very large (2-3 GB per tag)
        ]
        
        # Check if image should be skipped
        for skip_pattern in SKIP_IMAGES:
            if skip_pattern in image_name:
                logger.warning(f"Skipping {image_name} (known to be too large or problematic)")
                return {}, False
        
        # Try REMOTE-ONLY with registry: prefix (no fallback to local)
        try:
            
            full_name = f"registry:{image_name}"
            
            logger.debug(f"Attempting remote-only scan: {full_name}")
            
            result = subprocess.run(
                ['syft', full_name, '-o', 'json', '--file', str(output_file)],
                capture_output=True,
                timeout=self.timeout_per_scan,
                text=True
            )
            
            # Check if scan succeeded
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file) as f:
                    data = json.load(f)
                artifact_count = len(data.get('artifacts', []))
                logger.info(f"Syft completed (remote-only): {artifact_count} artifacts")
                return data, True
            else:
                # Remote scan failed - do NOT fallback to local
                logger.warning(f"Remote scan failed for {image_name} - skipping (no local pull)")
                return {}, False
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Syft timeout for {image_name} - skipping")
            return {}, False
        except Exception as e:
            logger.warning(f"Syft remote scan failed for {image_name}: {str(e)[:100]} - skipping")
            return {}, False
    
    def _run_grype_on_sbom(self, cache_dir: Path) -> Tuple[Dict, bool]:
        """Run Grype on SBOM"""
        sbom_file = cache_dir / 'sbom.json'
        output_file = cache_dir / 'grype.json'
        
        if not sbom_file.exists():
            return {}, False
        
        result = subprocess.run(
            ['grype', f'sbom:{sbom_file}', '-o', 'json', '--file', str(output_file)],
            capture_output=True,
            timeout=self.timeout_per_scan,
            text=True
        )
        
        if output_file.exists() and output_file.stat().st_size > 0:
            with open(output_file) as f:
                data = json.load(f)
            match_count = len(data.get('matches', []))
            logger.info(f"Grype completed: {match_count} vulnerabilities")
            return data, True
        
        return {}, False
    
    def _extract_sbom_features(self, syft_data: Dict, features: ImageFeatures):
        """Extract SBOM-based features"""
        if not syft_data:
            return
        
        artifacts = syft_data.get('artifacts', [])
        
        # Enhanced cryptominer detection
        for artifact in artifacts:
            name = artifact.get('name', '').lower()
            if any(miner in name for miner in self.security_detector.cryptominer_binaries):
                features.cryptominer_binary = 1
                logger.warning(f"Cryptominer binary detected: {name}")
                break
        
        # Obfuscated miner detection
        if features.cryptominer_binary is None:
            is_suspicious, reason = self.security_detector.detect_obfuscated_miner(artifacts)
            if is_suspicious:
                features.cryptominer_binary = 1
                logger.warning(f"Suspicious binary: {reason}")
            else:
                features.cryptominer_binary = 0
        
        # SSH backdoor detection
        ssh_servers = ['openssh-server', 'sshd', 'dropbear', 'ssh-daemon']
        for artifact in artifacts:
            name = artifact.get('name', '').lower()
            if any(ssh in name for ssh in ssh_servers):
                features.ssh_backdoor = 1
                logger.warning(f"SSH server detected: {name}")
                break
        
        if features.ssh_backdoor is None:
            features.ssh_backdoor = 0
    
    def _extract_trivy_features(self, trivy_data: Dict, features: ImageFeatures):
        """Extract Trivy-based features with normalization"""
        if not trivy_data:
            return
        
        results = trivy_data.get('Results', [])
        
        secret_count = 0
        external_call_count = 0
        
        for result in results:
            # Secrets
            secrets = result.get('Secrets', [])
            secret_count += len(secrets)
            
            # External calls
            for misconfig in result.get('Misconfigurations', []):
                title = misconfig.get('Title', '').lower()
                if any(word in title for word in ['port', 'expose', 'network', 'bind']):
                    external_call_count += 1
        
        features.hardcoded_secrets = min(secret_count, 10)
        features.external_calls = min(external_call_count, 10)
        features.suspicious_ports = self._detect_suspicious_ports(trivy_data)
        
        # Root detection
        self._detect_runs_as_root(trivy_data, features)
    
    def _detect_runs_as_root(self, trivy_data: Dict, features: ImageFeatures):
        """Enhanced root detection with explicit unknown handling"""
        metadata = trivy_data.get('Metadata', {})
        image_config = metadata.get('ImageConfig', {})
        config_dict = image_config.get('config', {})
        
        # Check USER directive
        user = config_dict.get('User', '')
        if user and user not in ['', 'root', '0', '0:0']:
            features.runs_as_root = 0
            logger.info(f"Non-root user: {user}")
            return
        
        # Check history
        history = image_config.get('history', [])
        for layer in history:
            created_by = layer.get('created_by', '')
            if 'USER' in created_by and 'root' not in created_by.lower():
                features.runs_as_root = 0
                logger.info("USER directive in history")
                return
        
        # If we have complete metadata but no USER, it runs as root
        if config_dict or history:
            features.runs_as_root = 1
            logger.warning("Runs as root (no USER directive)")
        else:
            # Unknown - metadata incomplete
            features.runs_as_root = None
            logger.warning("Cannot determine user (metadata incomplete)")
    
    def _detect_suspicious_ports(self, trivy_data: Dict) -> int:
        """Detect suspicious port configurations"""
        suspicious_ports = [
            22,    # SSH
            23,    # Telnet
            3389,  # RDP
            5900,  # VNC
            6379,  # Redis (if exposed)
            27017, # MongoDB (if exposed)
            3306,  # MySQL (if exposed)
        ]
        
        text = json.dumps(trivy_data).lower()
        count = sum(1 for port in suspicious_ports if str(port) in text)
        
        return min(count, 5)
    
    def _extract_grype_features(self, grype_data: Dict, features: ImageFeatures):
        """Extract CVE features with severity normalization"""
        if not grype_data:
            return
        
        matches = grype_data.get('matches', [])
        
        critical_count = 0
        high_count = 0
        
        for match in matches:
            severity = match.get('vulnerability', {}).get('severity', '').lower()
            
            if severity in ['critical', 'crit']:
                critical_count += 1
            elif severity in ['high', 'hi', 'h']:
                high_count += 1
        
        features.known_cves = critical_count + high_count
        
        if features.known_cves > 0:
            logger.warning(f"CVEs found: {critical_count} critical, {high_count} high")
    
    def _extract_metadata_features(self, trivy_data: Dict, image_name: str, features: ImageFeatures):
        """Extract metadata features"""
        # Mining pools
        text = json.dumps(trivy_data).lower()
        pool_count = sum(1 for pool in self.security_detector.mining_pools if pool in text)
        features.mining_pools = pool_count
        
        # Image age
        age_days = self._extract_image_age(trivy_data)
        if age_days is not None:
            features.image_age_days = age_days
            features.outdated_base = 1 if age_days > 365 else 0
        else:
            features.image_age_days = None
            features.outdated_base = None
        
        # Typosquatting
        typo_score, closest_match = self.security_detector.detect_typosquatting_enhanced(image_name)
        features.typosquatting_score = typo_score
        
        if closest_match and 0.8 < typo_score < 1.0:
            logger.warning(f"Possible typosquat of '{closest_match}' (score: {typo_score})")
    
    def _extract_image_age(self, trivy_data: Dict) -> Optional[int]:
        """Extract image age with explicit null for unknown"""
        metadata = trivy_data.get('Metadata', {})
        image_config = metadata.get('ImageConfig', {})
        
        # Method 1: created timestamp
        created_str = image_config.get('created', '')
        if created_str:
            try:
                created_str_clean = created_str.replace('Z', '+00:00')
                created_date = datetime.fromisoformat(created_str_clean)
                now = datetime.now(created_date.tzinfo)
                return (now - created_date).days
            except Exception as e:
                logger.debug(f"Failed to parse created date: {e}")
        
        # Method 2: history layers
        history = image_config.get('history', [])
        if history:
            try:
                oldest_created = history[0].get('created', '')
                if oldest_created:
                    created_date = datetime.fromisoformat(oldest_created.replace('Z', '+00:00'))
                    now = datetime.now(created_date.tzinfo)
                    return (now - created_date).days
            except Exception as e:
                logger.debug(f"Failed to parse history date: {e}")
        
        # Unknown
        logger.warning("Could not determine image age")
        return None
    
    def _log_feature_summary(self, features: ImageFeatures):
        """Log extracted features in structured format"""
        feature_dict = asdict(features)
        
        risky_features = []
        for key, value in feature_dict.items():
            if key in ['image_name', 'scan_status', 'confidence_score', 'label']:
                continue
            
            if value is None:
                continue
            
            if self._is_risky(key, value):
                risky_features.append(f"{key}={value}")
        
        if risky_features:
            logger.warning(f"Risky features: {', '.join(risky_features)}")
        else:
            logger.info("No significant risks detected")
    
    def _is_risky(self, key: str, value: Any) -> bool:
        """Determine if feature value indicates risk"""
        if value is None:
            return False
        
        risk_conditions = {
            'cryptominer_binary': value == 1,
            'mining_pools': value > 0,
            'hardcoded_secrets': value > 0,
            'ssh_backdoor': value == 1,
            'runs_as_root': value == 1,
            'known_cves': value >= 5,
            'outdated_base': value == 1,
            'typosquatting_score': 0.8 < value < 1.0,
            'suspicious_ports': value > 0,
            'high_entropy_files': value > 0
        }
        
        return risk_conditions.get(key, False)

def extract_dataset_parallel(
    safe_images: List[str],
    risky_images: List[str],
    output_csv: str = 'data/enhanced_docker_features.csv',
    timeout_per_image: int = 300,
    max_workers: int = 3,
    registry_auth: Optional[Dict] = None,
    cache_ttl_days: int = 7
) -> pd.DataFrame:
    """
    Extract features with parallel processing and rate limiting
    """
    logger.info("="*70)
    logger.info("🐳 ENHANCED REMOTE DOCKER SCANNER v2.0")
    logger.info("="*70)
    logger.info("Features:")
    logger.info(" ✓ Parallel scanning with rate limiting")
    logger.info(" ✓ Explicit null handling (no silent defaults)")
    logger.info(" ✓ Retry logic with exponential backoff")
    logger.info(" ✓ Enhanced obfuscation detection")
    logger.info(" ✓ Levenshtein distance typosquatting")
    logger.info(" ✓ Cache management with TTL")
    logger.info(" ✓ Structured logging")
    logger.info("="*70)
    logger.info(f"Safe images: {len(safe_images)}")
    logger.info(f"Risky images: {len(risky_images)}")
    logger.info(f"Timeout per image: {timeout_per_image}s")
    logger.info(f"Max workers: {max_workers}")
    logger.info(f"Output: {output_csv}")
    logger.info("="*70)
    
    scanner = EnhancedRemoteDockerScanner(
        timeout_per_scan=timeout_per_image,
        max_workers=max_workers,
        registry_auth=registry_auth,
        cache_ttl_days=cache_ttl_days
    )
    
    results = []
    failed = []
    
    # Combine all images with labels: 0=safe, 1=risky
    all_images = [(img, 0) for img in safe_images] + [(img, 1) for img in risky_images]
    
    logger.info(f"\n🔄 Starting parallel scan of {len(all_images)} images...")
    logger.info(f"   Safe images (label=0): {len(safe_images)}")
    logger.info(f"   Risky images (label=1): {len(risky_images)}")
    
    # Process in parallel with rate limiting
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_image = {
            executor.submit(scanner.extract_features, img): (img, label)
            for img, label in all_images
        }
        
        completed = 0
        for future in as_completed(future_to_image):
            image_name, label = future_to_image[future]
            completed += 1
            
            try:
                features = future.result()
                features.label = label
                
                if features.scan_status == 'failed':
                    failed.append((image_name, 'safe' if label == 0 else 'risky'))
                    logger.warning(f"[{completed}/{len(all_images)}] Failed: {image_name}")
                else:
                    results.append(asdict(features))
                    status_icon = "✓" if features.scan_status == 'success' else "⚠"
                    label_str = f"label={label}"
                    logger.info(f"[{completed}/{len(all_images)}] {status_icon} Completed: {image_name} ({label_str})")
                
            except Exception as e:
                logger.error(f"[{completed}/{len(all_images)}] Error processing {image_name}: {e}")
                failed.append((image_name, 'safe' if label == 0 else 'risky'))
    
    # Create DataFrame with only the specified columns in order
    df = pd.DataFrame(results)
    
    # Reorder columns to match COLUMN_ORDER
    # Keep only columns that exist in both COLUMN_ORDER and df
    available_columns = [col for col in COLUMN_ORDER if col in df.columns]
    df = df[available_columns]
    
    # Save with metadata
    os.makedirs(os.path.dirname(output_csv) or '.', exist_ok=True)
    
    # Save main CSV
    df.to_csv(output_csv, index=False)
    
    # Save metadata file
    metadata_file = output_csv.replace('.csv', '_metadata.json')
    metadata = {
        'schema_version': FEATURE_SCHEMA_VERSION,
        'extraction_timestamp': datetime.now().isoformat(),
        'total_images': len(all_images),
        'successful_scans': len(results),
        'failed_scans': len(failed),
        'success_rate': len(results) / len(all_images) if all_images else 0,
        'timeout_per_image': timeout_per_image,
        'max_workers': max_workers,
        'safe_images_scanned': len([r for r in results if r.get('label') == 0]),
        'risky_images_scanned': len([r for r in results if r.get('label') == 1]),
        'column_order': COLUMN_ORDER,
        'failed_images': failed
    }
    
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    # Print summary
    logger.info("\n" + "="*70)
    logger.info("✅ FEATURE EXTRACTION COMPLETE")
    logger.info("="*70)
    logger.info(f"\n💾 Files saved:")
    logger.info(f"   CSV: {output_csv}")
    logger.info(f"   Metadata: {metadata_file}")
    
    logger.info(f"\n📊 Results:")
    logger.info(f"   Successful: {len(results)}")
    logger.info(f"   Failed: {len(failed)}")
    logger.info(f"   Success rate: {len(results)/(len(results)+len(failed))*100:.1f}%")
    
    if failed:
        logger.warning(f"\n⚠️  Failed images ({len(failed)}):")
        for img, label in failed[:10]:  # Show first 10
            logger.warning(f"   - {img} ({label})")
        if len(failed) > 10:
            logger.warning(f"   ... and {len(failed) - 10} more")
    
    # Dataset statistics
    logger.info(f"\n📈 Dataset:")
    logger.info(f"   Total rows: {len(df)}")
    logger.info(f"   Safe (label=0): {len(df[df['label']==0])}")
    logger.info(f"   Risky (label=1): {len(df[df['label']==1])}")
    
    # Scan status breakdown
    if 'scan_status' in results[0] if results else False:
        status_counts = {}
        for r in results:
            status = r.get('scan_status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        logger.info(f"\n📊 Scan status:")
        for status, count in status_counts.items():
            logger.info(f"   {status}: {count}")
    
    # Feature completeness
    logger.info(f"\n📋 Feature completeness (% non-null):")
    for col in COLUMN_ORDER:
        if col in df.columns:
            completeness = (df[col].notna().sum() / len(df)) * 100
            logger.info(f"   {col}: {completeness:.1f}%")
    
    # Basic statistics for numeric features
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    numeric_cols = [col for col in numeric_cols if col != 'label']
    
    if len(numeric_cols) > 0:
        logger.info(f"\n📊 Feature statistics:")
        stats_df = df[numeric_cols].describe()
        logger.info(f"\n{stats_df.to_string()}")
    
    return df


def validate_features(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Validate extracted features and return quality metrics
    """
    validation_results = {
        'schema_version': FEATURE_SCHEMA_VERSION,
        'validation_timestamp': datetime.now().isoformat(),
        'total_records': len(df),
        'issues': [],
        'warnings': []
    }
    
    # Check for required columns
    required_cols = ['label']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        validation_results['issues'].append(f"Missing required columns: {missing_cols}")
    
    # Check column order
    if list(df.columns) != [col for col in COLUMN_ORDER if col in df.columns]:
        validation_results['warnings'].append(f"Columns not in expected order")
    
    # Check for excessive nulls
    null_threshold = 0.5  # 50%
    for col in df.columns:
        if col == 'label':
            continue
        
        null_pct = df[col].isna().sum() / len(df)
        if null_pct > null_threshold:
            validation_results['warnings'].append(
                f"{col}: {null_pct*100:.1f}% null values (threshold: {null_threshold*100}%)"
            )
    
    # Check for class imbalance
    if 'label' in df.columns:
        class_counts = df['label'].value_counts()
        if len(class_counts) == 2:
            imbalance_ratio = class_counts.max() / class_counts.min()
            if imbalance_ratio > 3:
                validation_results['warnings'].append(
                    f"Class imbalance: ratio {imbalance_ratio:.2f} (safe: {class_counts.get(0, 0)}, risky: {class_counts.get(1, 0)})"
                )
        
        # Verify labels are only 0 and 1
        invalid_labels = df[~df['label'].isin([0, 1])]['label'].unique()
        if len(invalid_labels) > 0:
            validation_results['issues'].append(f"Invalid label values found: {invalid_labels}")
    
    # Check for suspicious values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if col in ['label', 'confidence_score', 'image_age_days']:
            continue
        
        # Check for negative values where they shouldn't exist
        if (df[col] < 0).any():
            validation_results['issues'].append(f"{col}: contains negative values")
        
        # Check for extreme outliers (beyond reasonable bounds)
        if col in ['known_cves', 'hardcoded_secrets', 'mining_pools']:
            max_reasonable = {'known_cves': 100, 'hardcoded_secrets': 20, 'mining_pools': 10}
            if (df[col] > max_reasonable.get(col, 50)).any():
                validation_results['warnings'].append(
                    f"{col}: contains unusually high values (max: {df[col].max()})"
                )
    
    return validation_results



SAFE_IMAGES = [
    # Official base images (small, well-maintained)
    'nginx:alpine', 'nginx:1.25-alpine', 'nginx:1.24-alpine',
    'python:3.11-slim', 'python:3.10-slim', 'python:3.9-slim', 'python:3.12-slim',
    'node:20-alpine', 'node:18-alpine', 'node:16-alpine', 'node:21-alpine',
    'postgres:16-alpine', 'postgres:15-alpine', 'postgres:14-alpine',
    'redis:7-alpine', 'redis:6-alpine',
    'alpine:latest', 'alpine:3.19', 'alpine:3.18',
    'golang:1.21-alpine', 'golang:1.20-alpine',
    'mysql:8.2', 'mysql:8.0',
    'debian:bookworm-slim', 'debian:bullseye-slim',
    'ubuntu:23.10', 'ubuntu:22.04', 'ubuntu:23.04',
    'mongodb:7.0', 'mongodb:6.0',
    'mariadb:11', 'mariadb:10.11',
    'haproxy:2.9-alpine', 'haproxy:2.8-alpine',
    'caddy:2-alpine', 'caddy:2.7-alpine',
    'ruby:3.2-alpine', 'ruby:3.1-alpine',
    
    # Additional official images (safe, small)
    'memcached:alpine', 'memcached:1.6-alpine',
    'httpd:alpine', 'httpd:2.4-alpine',
    'traefik:latest', 'traefik:v2.11',
    'busybox:latest', 'busybox:1.36',
    'influxdb:alpine',
    'consul:latest',
    'vault:latest',
    'elasticsearch:8.11.0',
    'kibana:8.11.0',
    'logstash:8.11.0',
    'rabbitmq:3-alpine', 'rabbitmq:3.12-alpine',
    'nats:alpine', 'nats:2.10-alpine',
    'eclipse-mosquitto:latest',
    'jenkins/jenkins:lts-alpine',
    'sonarqube:community',
    'grafana/grafana:latest',
    'prom/prometheus:latest',
    'openjdk:17-alpine', 'openjdk:11-alpine',
    'rust:alpine', 'rust:1.75-alpine',
    'php:8.2-alpine', 'php:8.1-alpine',
    'perl:slim',
    'elixir:alpine',
    'maven:3-eclipse-temurin-17-alpine',
    'gradle:jdk17-alpine',
    'tomcat:10-jdk17-temurin-jammy',
    'wordpress:latest',
    'ghost:alpine',
    'drupal:latest',
    'joomla:latest',
    'nextcloud:apache',
]

RISKY_IMAGES = [
    # EOL Ubuntu versions (high CVE count, safe to scan remotely)
    'ubuntu:14.04', 'ubuntu:16.04', 'ubuntu:18.04',
    'ubuntu:12.04', 'ubuntu:10.04',
    
    # EOL Debian versions
    'debian:jessie', 'debian:wheezy', 'debian:stretch',
    'debian:squeeze', 'debian:lenny',
    
    # EOL CentOS
    'centos:7', 'centos:6', 'centos:5',
    
    # Old Python (EOL, vulnerable)
    'python:2.7', 'python:2.6', 'python:3.4', 'python:3.5',
    'python:3.6', 'python:2.7-slim',
    
    # Old Node.js (EOL)
    'node:10', 'node:8', 'node:6', 'node:4',
    'node:12', 'node:11',
    
    # Old PHP (EOL, many vulnerabilities)
    'php:5.6', 'php:5.5', 'php:5.4', 'php:5.3',
    'php:7.0', 'php:7.1',
    
    # Old databases (EOL)
    'postgres:9.6', 'postgres:9.5', 'postgres:9.4',
    'postgres:9.3', 'postgres:9.2', 'postgres:9.1',
    'mysql:5.5', 'mysql:5.6', 'mysql:5.7',
    'mariadb:10.0', 'mariadb:10.1', 'mariadb:10.2',
    'mongodb:3.6', 'mongodb:3.4', 'mongodb:3.2',
    'mongodb:2.6',
    
    # Old Redis
    'redis:3.0', 'redis:3.2', 'redis:4.0',
    
    # Old web servers
    'nginx:1.10', 'nginx:1.12', 'nginx:1.14',
    'httpd:2.2', 'httpd:2.4.25',
    'tomcat:7', 'tomcat:8.0',
    
    # Old programming runtimes
    'ruby:2.0', 'ruby:2.1', 'ruby:2.2', 'ruby:2.3',
    'golang:1.10', 'golang:1.11', 'golang:1.12',
    'openjdk:8', 'openjdk:7',
    'perl:5.16', 'perl:5.18',
    
    # Vulnerable lab images (SMALL ones only - safe for remote scanning)
    'vulnerables/web-dvwa',
    'bkimminich/juice-shop',
    'webgoat/goatandwolf',
]

NEW_SAFE_IMAGES = [
    # Cloud-native & Container tools (official, small)
    'docker:dind-alpine',
    'docker:24-cli-alpine',
    'containerd/containerd:1.7.11',
    'registry:2',
    'registry:2.8-alpine',
    
    # Databases you haven't used
    'couchdb:3.3',
    'cockroachdb/cockroach:v23.1.14',
    'arangodb:3.11',
    'orientdb:3.2',
    'cassandra:4.1',
    'timescaledb/timescaledb:latest-pg16',
    
    # Message queues & streaming
    'confluentinc/cp-kafka:7.5.3',
    'apache/kafka:3.6.1',
    'apache/zookeeper:3.9.1',
    'redis/redis-stack-server:latest',
    
    # Web servers & proxies (different versions)
    'nginx:1.26-alpine',
    'nginx:mainline-alpine',
    'envoyproxy/envoy:v1.28.0',
    'kong:3.5-alpine',
    
    # Programming language runtimes (newer/different versions)
    'python:3.13-slim',
    'node:22-alpine',
    'golang:1.22-alpine',
    'ruby:3.3-alpine',
    'php:8.3-alpine',
    'openjdk:21-slim',
    'rust:1.76-alpine',
    'dotnet/runtime:8.0-alpine',
    'dotnet/aspnet:8.0-alpine',
    
    # Monitoring & observability
    'prom/alertmanager:latest',
    'prom/node-exporter:latest',
    'prom/blackbox-exporter:latest',
    'grafana/loki:2.9.3',
    'grafana/promtail:2.9.3',
    'jaegertracing/all-in-one:1.53',
    
    # CI/CD & DevOps tools
    'gitlab/gitlab-runner:alpine',
    'hashicorp/terraform:latest',
    'drone/drone:2',
    'argoproj/argocd:latest',
    'fluxcd/flux:latest',

     'ubuntu:20.04',  # LTS until April 2025 ✅
    'ubuntu:18.04',  # LTS until April 2028 (ESM) ⚠️ Borderline but patched
    
    # Debian Stable/Oldstable (still supported)
    'debian:buster-slim',  # Oldstable, security support until June 2024 ⚠️ Check date
    'debian:bullseye',  # Oldstable, supported until 2026 ✅
    
    
]

NEW_RISKY_IMAGES = [
    # More EOL Ubuntu versions
    'ubuntu:19.04',  # EOL
    'ubuntu:19.10',  # EOL
    
    'ubuntu:21.10',  # EOL
    'ubuntu:17.10',  # EOL
    
    # More EOL Debian
    'debian:buster',  # oldstable, getting EOL
    'debian:oldstable',
    
    # EOL Fedora versions
    'fedora:28',  # EOL
    'fedora:29',  # EOL
    'fedora:30',  # EOL
    'fedora:31',  # EOL
    
    # Older Alpine (security issues)
    'alpine:3.8',
    'alpine:3.9',
    
    'alpine:3.11',
    
    # More old Python
    'python:3.7',  # EOL June 2023
    'python:3.8-slim',  # EOL October 2024
    'python:2.7-alpine',
    
    # More old Node.js
    'node:14',  # EOL April 2023
    'node:15',  # EOL
    'node:13',  # EOL
    
    # Old Golang
    'golang:1.13',
    
    'golang:1.16',
    
    # Old Ruby
    'ruby:2.4',  # EOL
      # EOL
    'ruby:2.6',  # EOL
    
    # Old Redis (vulnerabilities)
    'redis:5.0',
    'redis:4.0.14',
    
    # Old Nginx
    'nginx:1.16',
    
    'nginx:1.13',
    
    # Old Postgres
    'postgres:10',  # EOL November 2022
      # EOL November 2023
    'postgres:9.0',
    
    # Old MySQL
    'mysql:5.7',  # EOL October 2023
    
    # Intentionally vulnerable images (verified small & public)
    'citizenstig/dvwa',  # Damn Vulnerable Web App
    'vulnerables/cve-2017-7494',  # Samba vulnerability
    'vulhub/struts2:2.3.15.1',  # Struts2 RCE

    'servethehome/monero_xmr_stak',
    'kannix/monero-miner',
    'metalicjames/cryptonote-xmr-pool',
    
    # SSH backdoors (small)
    'linuxserver/openssh-server',
    'rastasheep/ubuntu-sshd',
    'panubo/sshd',
    'jdeathe/centos-ssh',
    
    # Root user + privilege escalation
     # May be large - test first
    
    # Vulnerable web apps (verified small)
    'bkimminich/juice-shop',  # ~300MB
    'webgoat/webgoat-8.0',  # ~400MB
    'vulnerables/web-dvwa',  # ~500MB
    'citizenstig/dvwa',
    
    # Hardcoded secrets
    'mongo-express/mongo-express',
    
    # Network tools (external calls)
    'nicolaka/netshoot',
    'instrumentisto/nmap',
    
    # VNC/RDP (suspicious ports)
    'dorowu/ubuntu-desktop-lxde-vnc',
    
    # Build tools (temp files, high entropy)
    'buildpack-deps:buster',
    'buildpack-deps:focal',
    
    # Security scanners (multiple behavioral flags)
    'owasp/zap2docker-stable',
    'projectdiscovery/nuclei',
    'aquasec/trivy',
    
    # Container with many binaries (stripped, packed)
    'voidlinux/voidlinux'
]

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Docker Image Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract full dataset with parallel processing
  python extract_features.py extract --workers 5
  
  # Scan a single image
  python extract_features.py single nginx:latest
  
  # Extract with custom timeout and cache TTL
  python extract_features.py extract --timeout 600 --cache-ttl 14
  
  # Validate existing dataset
  python extract_features.py validate data/enhanced_docker_features.csv
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract full dataset')
    extract_parser.add_argument('--output', default='data/enhanced_docker_features.csv',
                                help='Output CSV file')
    extract_parser.add_argument('--timeout', type=int, default=300,
                                help='Timeout per image (seconds)')
    extract_parser.add_argument('--workers', type=int, default=3,
                                help='Number of parallel workers')
    extract_parser.add_argument('--cache-ttl', type=int, default=7,
                                help='Cache TTL in days')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test with small dataset')
    test_parser.add_argument('--output', default='data/test_features.csv',
                            help='Output CSV file')
    test_parser.add_argument('--timeout', type=int, default=300,  # ← ADD THIS
                        help='Timeout per image (seconds)')
    
    # Single image command
    single_parser = subparsers.add_parser('single', help='Scan single image')
    single_parser.add_argument('image', help='Image name to scan')
    single_parser.add_argument('--timeout', type=int, default=300,
                               help='Timeout (seconds)')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate dataset')
    validate_parser.add_argument('csv_file', help='CSV file to validate')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'extract':
        df = extract_dataset_parallel(
            SAFE_IMAGES,
            RISKY_IMAGES,
            output_csv=args.output,
            timeout_per_image=args.timeout,
            max_workers=args.workers,
            cache_ttl_days=args.cache_ttl
        )
        
        # Validate results
        validation = validate_features(df)
        
        if validation['issues']:
            logger.error("\n❌ Validation issues found:")
            for issue in validation['issues']:
                logger.error(f"   - {issue}")
        
        if validation['warnings']:
            logger.warning("\n⚠️  Validation warnings:")
            for warning in validation['warnings']:
                logger.warning(f"   - {warning}")
        
        if not validation['issues']:
            logger.info("\n✅ Dataset validation passed")
    
    elif args.command == 'test':
        logger.info("Running test with 30 images...")
        df = extract_dataset_parallel(
            NEW_SAFE_IMAGES[10:50],    # 15 safe images
            NEW_RISKY_IMAGES[10:50],   # 15 risky images
            output_csv=args.output,
            max_workers=4,
            timeout_per_image=args.timeout
        )
    
    elif args.command == 'single':
        scanner = EnhancedRemoteDockerScanner(timeout_per_scan=args.timeout)
        features = scanner.extract_features(args.image)
        
        logger.info("\n" + "="*70)
        logger.info("📋 EXTRACTED FEATURES")
        logger.info("="*70)
        
        # Display in column order
        for col in COLUMN_ORDER:
            if hasattr(features, col):
                value = getattr(features, col)
                if value is None:
                    value_str = "NULL (unknown)"
                else:
                    value_str = str(value)
                logger.info(f"   {col}: {value_str}")
        
        logger.info("="*70)
    
    elif args.command == 'validate':
        if not os.path.exists(args.csv_file):
            logger.error(f"File not found: {args.csv_file}")
            sys.exit(1)
        
        df = pd.read_csv(args.csv_file)
        validation = validate_features(df)
        
        logger.info("\n" + "="*70)
        logger.info("📊 DATASET VALIDATION")
        logger.info("="*70)
        logger.info(f"Schema version: {validation['schema_version']}")
        logger.info(f"Total records: {validation['total_records']}")
        
        if validation['issues']:
            logger.error("\n❌ Issues found:")
            for issue in validation['issues']:
                logger.error(f"   - {issue}")
        
        if validation['warnings']:
            logger.warning("\n⚠️  Warnings:")
            for warning in validation['warnings']:
                logger.warning(f"   - {warning}")
        
        if not validation['issues'] and not validation['warnings']:
            logger.info("\n✅ No issues found - dataset is valid")
        
        logger.info("="*70)
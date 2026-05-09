// src/utils/featureExplanations.js

export const featureExplanations = {
    // Malware & Threats
    cryptominer_binary: {
        title: "Cryptominer Binary",
        description: "Detects known cryptocurrency mining software like XMRig, cgminer, or ethminer. These programs secretly use your CPU/GPU to mine cryptocurrency.",
        impact: "Critical security threat - consumes resources and may indicate compromise",
        good: "0 (No miners detected)",
        bad: "1 (Miner detected)"
    },

    mining_pools: {
        title: "Mining Pool Connections",
        description: "Detects connections to cryptocurrency mining pools (stratum+tcp://, pool.minexmr.com, etc.). Miners connect to pools to share mining rewards.",
        impact: "Strong indicator of cryptomining malware",
        good: "0 (No pool connections)",
        bad: "1+ (Pool connections found)"
    },

    ssh_backdoor: {
        title: "SSH Backdoor",
        description: "Detects SSH server installed in the container. While sometimes legitimate, SSH in containers often indicates a backdoor for unauthorized access.",
        impact: "High risk - provides remote shell access",
        good: "0 (No SSH server)",
        bad: "1 (SSH server detected)",
        fix: "Use 'docker exec' for debugging instead of SSH"
    },

    hardcoded_secrets: {
        title: "Hardcoded Secrets",
        description: "Detects API keys, passwords, or tokens embedded in the image. These can be extracted by anyone with image access.",
        impact: "Critical - exposes credentials to attackers",
        good: "0 (No secrets found)",
        bad: "1+ (Secrets detected)",
        fix: "Use environment variables or Docker secrets"
    },

    // Vulnerabilities
    known_cves: {
        title: "Known CVEs",
        description: "Count of Common Vulnerabilities and Exposures (CVEs) found in installed packages. Each CVE is a publicly disclosed security flaw.",
        impact: "Direct security risk - attackers can exploit these flaws",
        good: "0-5 (Minimal vulnerabilities)",
        bad: "50+ (Highly vulnerable)",
        fix: "Update base image and packages regularly"
    },

    outdated_base: {
        title: "Outdated Base Image",
        description: "Image uses an end-of-life (EOL) base distribution like Ubuntu 14.04 or Debian Jessie that no longer receives security updates.",
        impact: "High risk - no security patches available",
        good: "0 (Modern base image)",
        bad: "1 (EOL base image)",
        fix: "Migrate to Ubuntu 22.04, Debian Bookworm, or Alpine"
    },

    // Access Control
    runs_as_root: {
        title: "Runs as Root",
        description: "Container runs with root (UID 0) privileges. If an attacker compromises the app, they have full system access.",
        impact: "High risk - enables privilege escalation",
        good: "0 (Non-root user)",
        bad: "1 (Runs as root)",
        fix: "Add: RUN adduser -D appuser && USER appuser"
    },

    privilege_escalation_risk: {
        title: "Privilege Escalation Risk",
        description: "Detects patterns that enable privilege escalation: setuid binaries, sudo access, or root password changes.",
        impact: "Allows attackers to gain elevated privileges",
        good: "0.0-0.3 (Low risk)",
        bad: "0.7+ (High risk)",
        fix: "Remove sudo, avoid setuid binaries"
    },

    // Network Security
    external_calls: {
        title: "External Network Calls",
        description: "Count of curl, wget, or HTTP connections in Dockerfile commands. High values may indicate downloading malicious payloads.",
        impact: "Medium risk - depends on what's being downloaded",
        good: "0-2 (Minimal downloads)",
        bad: "10+ (Excessive network activity)",
        fix: "Use trusted package managers instead of curl/wget"
    },

    raw_ip_connections: {
        title: "Raw IP Connections",
        description: "Detects connections to IP addresses (1.2.3.4) instead of domain names. Often used to evade domain blocking.",
        impact: "Suspicious - may indicate malware C2 communication",
        good: "0.0 (No raw IPs)",
        bad: "0.5+ (Raw IPs detected)"
    },

    suspicious_ports: {
        title: "Suspicious Ports",
        description: "Detects unusual port exposures (not 80, 443, 8080). May indicate hidden services or backdoors.",
        impact: "Medium risk - depends on context",
        good: "0 (Standard ports only)",
        bad: "2+ (Multiple unusual ports)",
        examples: "Port 22 (SSH), 4444 (Metasploit), 6667 (IRC)"
    },

    suspicious_dns_queries: {
        title: "Suspicious DNS Queries",
        description: "Detects DNS queries to free/suspicious TLDs (.tk, .ml, .ga) often used by malware for command & control.",
        impact: "Medium-high risk - indicator of malware",
        good: "0.0 (No suspicious queries)",
        bad: "0.5+ (Suspicious domains detected)"
    },

    // Behavioral Analysis
    image_age_days: {
        title: "Image Age",
        description: "Days since the base image was last updated. Older images miss critical security patches.",
        impact: "Risk increases with age",
        good: "0-180 days (Recently updated)",
        bad: "730+ days (2+ years old)",
        fix: "Rebuild with latest base image"
    },

    layer_deletion_score: {
        title: "Layer Deletion Activity",
        description: "Measures how often files are created then deleted in subsequent layers. Common anti-forensics technique.",
        impact: "Medium risk - may hide malicious activity",
        good: "0.0-0.2 (Normal cleanup)",
        bad: "0.7+ (Excessive deletion)",
        pattern: "RUN wget malware.sh && ./malware.sh && rm malware.sh"
    },

    temp_file_activity: {
        title: "Temporary File Activity",
        description: "Detects excessive use of /tmp, /var/tmp, or /dev/shm for storing files. May indicate malware staging area.",
        impact: "Medium risk - common malware behavior",
        good: "0.0-0.3 (Minimal temp usage)",
        bad: "0.7+ (Heavy temp file usage)"
    },

    anti_analysis_score: {
        title: "Anti-Analysis Techniques",
        description: "Detects evasion tactics: clearing bash history, base64 encoding, eval obfuscation, or log deletion.",
        impact: "High risk - indicates intentional hiding",
        good: "0.0-0.2 (Normal)",
        bad: "0.6+ (Active evasion)",
        examples: "history -c, echo <base64> | base64 -d | bash"
    },

    crypto_mining_behavior: {
        title: "Cryptomining Behavior Pattern",
        description: "Composite score combining miner binaries, pool connections, stratum protocols, and mining commands.",
        impact: "Critical if detected - resource theft",
        good: "0.0 (No mining activity)",
        bad: "0.5+ (Mining patterns detected)"
    },

    process_injection_risk: {
        title: "Process Injection Risk",
        description: "Detects tools for code injection: ptrace, LD_PRELOAD, /proc/*/mem access. Used to hijack running processes.",
        impact: "High risk - advanced attack technique",
        good: "0.0 (No injection tools)",
        bad: "0.5+ (Injection capabilities present)"
    },

    // File Analysis
    high_entropy_files: {
        title: "High Entropy Files",
        description: "Count of files with high randomness (encrypted, compressed, or obfuscated). Malware often encrypts itself to evade detection.",
        impact: "Medium risk - may be legitimate compression or malware",
        good: "0-5 (Few high-entropy files)",
        bad: "20+ (Many suspicious files)"
    },

    avg_file_entropy: {
        title: "Average File Entropy",
        description: "Average randomness across all files (0.0-8.0). Higher values suggest more encryption/compression.",
        impact: "Contextual - high entropy may be normal",
        good: "3.0-5.0 (Normal text/binaries)",
        bad: "7.0+ (Highly compressed/encrypted)"
    },

    high_entropy_ratio: {
        title: "High Entropy Ratio",
        description: "Percentage of files with suspiciously high entropy. Normal images have ~5-15%.",
        impact: "Medium risk if ratio is extreme",
        good: "0.05-0.15 (5-15%)",
        bad: "0.5+ (50%+ high entropy)"
    },

    stripped_binaries_ratio: {
        title: "Stripped Binaries",
        description: "Percentage of binaries with debug symbols removed. Stripping is normal for production but may hide malware analysis.",
        impact: "Low-medium risk - depends on context",
        good: "0.7-0.9 (Most binaries stripped)",
        bad: "1.0 (All stripped - may hinder forensics)"
    },

    packed_binary_score: {
        title: "Packed Binaries",
        description: "Detects compressed/packed executables (UPX, etc.). Packing is legitimate for size reduction but also hides malware.",
        impact: "Medium risk - common in both malware and legitimate software",
        good: "0.0-0.2 (Few packed binaries)",
        bad: "0.6+ (Many packed binaries)"
    },

    // Reputation
    typosquatting_score: {
        title: "Typosquatting Score",
        description: "Similarity to legitimate image names. Attackers create fake images with names like 'ngnix' (nginx) or 'ubunto' (ubuntu).",
        impact: "High risk if score is high - likely malicious impersonation",
        good: "0.0-0.3 (Legitimate or unique name)",
        bad: "0.7+ (Suspicious similarity)",
        examples: "ngnix, ubuntuu, pyt0n"
    },

    stratum_indicators: {
        title: "Stratum Protocol Indicators",
        description: "Detects 'stratum+tcp://' protocol used exclusively by cryptocurrency miners to connect to mining pools.",
        impact: "Critical - definitive mining indicator",
        good: "0.0 (No stratum)",
        bad: "1.0 (Stratum detected)"
    }
};

// Helper function to get risk level color
export const getRiskLevelColor = (feature, value) => {
    const explanations = featureExplanations[feature];
    if (!explanations) return 'text-slate-400';

    // Binary features (0 or 1)
    if (value === 0) return 'text-green-400';
    if (value === 1 && ['cryptominer_binary', 'ssh_backdoor', 'hardcoded_secrets', 'runs_as_root', 'outdated_base'].includes(feature)) {
        return 'text-red-400';
    }

    // Numeric ranges
    if (feature === 'known_cves') {
        if (value < 5) return 'text-green-400';
        if (value < 20) return 'text-yellow-400';
        if (value < 50) return 'text-orange-400';
        return 'text-red-400';
    }

    if (feature === 'image_age_days') {
        if (value < 180) return 'text-green-400';
        if (value < 365) return 'text-yellow-400';
        if (value < 730) return 'text-orange-400';
        return 'text-red-400';
    }

    // Score-based (0.0-1.0)
    if (typeof value === 'number' && value <= 1.0) {
        if (value < 0.3) return 'text-green-400';
        if (value < 0.5) return 'text-yellow-400';
        if (value < 0.7) return 'text-orange-400';
        return 'text-red-400';
    }

    return 'text-slate-400';
};
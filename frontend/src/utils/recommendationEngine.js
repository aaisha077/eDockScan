// src/utils/recommendationEngine.js

export const generateRecommendations = (scanResult) => {
    const recommendations = [];
    const features = scanResult.all_features || {};

   
    if (features.cryptominer_binary === 1) {
        recommendations.push({
            id: 'cryptominer',
            priority: 'CRITICAL',
            score: 100,
            category: 'Malware',
            icon: '⛏️',
            title: 'Cryptomining Malware Detected',
            problem: 'This image contains cryptocurrency mining software that will consume CPU/GPU resources to mine coins for attackers.',
            impact: '• Extreme resource consumption (100% CPU usage)\n• Increased cloud costs\n• Degraded application performance\n• Data exfiltration risk',
            solution: 'Do NOT use this image',
            actions: [
                {
                    type: 'immediate',
                    text: 'Stop all containers using this image immediately',
                    command: `docker ps | grep ${scanResult.image} | awk '{print $1}' | xargs docker stop`
                },
                {
                    type: 'replace',
                    text: 'Use official image from trusted registry',
                    command: 'docker pull nginx:alpine  # example'
                },
                {
                    type: 'investigate',
                    text: 'Check who added this image to your environment'
                }
            ],
            references: [
                'https://www.crowdstrike.com/cybersecurity-101/cryptocurrency-mining-malware/',
                'https://owasp.org/www-community/attacks/Cryptojacking'
            ]
        });
    }

    if (features.ssh_backdoor === 1) {
        recommendations.push({
            id: 'ssh_backdoor',
            priority: 'CRITICAL',
            score: 90,
            category: 'Backdoor',
            icon: '🚪',
            title: 'SSH Backdoor Detected',
            problem: 'SSH server is installed, providing remote shell access. Containers should be immutable and not require SSH.',
            impact: '• Unauthorized remote access\n• Privilege escalation vector\n• Persistent backdoor\n• Bypasses container isolation',
            solution: 'Remove SSH server and use docker exec for debugging',
            actions: [
                {
                    type: 'fix',
                    text: 'Remove SSH from Dockerfile',
                    command: '# Remove lines containing:\n# apt-get install openssh-server\n# apk add openssh'
                },
                {
                    type: 'alternative',
                    text: 'Use docker exec for debugging instead',
                    command: 'docker exec -it <container-id> /bin/sh'
                },
                {
                    type: 'alternative',
                    text: 'For production debugging, use ephemeral debug containers',
                    command: 'kubectl debug pod/<name> --image=busybox'
                }
            ],
            dockerfile: `# ❌ REMOVE THIS:\nRUN apt-get install -y openssh-server\n\n# ✅ USE THIS INSTEAD:\n# Use docker exec for debugging\n# No changes needed to Dockerfile`
        });
    }

    if (features.hardcoded_secrets === 1) {
        recommendations.push({
            id: 'secrets',
            priority: 'CRITICAL',
            score: 85,
            category: 'Secrets',
            icon: '🔑',
            title: 'Hardcoded Secrets Found',
            problem: 'API keys, passwords, or tokens are embedded in the image. Anyone with image access can extract them.',
            impact: '• Full account compromise\n• Data breach\n• Lateral movement in infrastructure\n• Compliance violations (PCI-DSS, SOC2)',
            solution: 'Use environment variables or secret management systems',
            actions: [
                {
                    type: 'fix',
                    text: 'Remove secrets from Dockerfile and config files',
                    command: '# Search for secrets:\ngrep -r "password\\|api_key\\|token" .'
                },
                {
                    type: 'replace',
                    text: 'Use environment variables',
                    command: 'docker run -e API_KEY=$API_KEY myimage'
                },
                {
                    type: 'replace',
                    text: 'Use Docker secrets (Swarm/Kubernetes)',
                    command: 'echo "my_secret" | docker secret create api_key -'
                }
            ],
            dockerfile: `# ❌ DON'T DO THIS:\nENV API_KEY="sk-1234567890abcdef"\nRUN echo "password123" > /app/.env\n\n# ✅ DO THIS INSTEAD:\n# Pass secrets at runtime:\n# docker run -e API_KEY=$API_KEY myimage\n\n# Or use Docker secrets:\nRUN --mount=type=secret,id=api_key \\
    export API_KEY=$(cat /run/secrets/api_key)`
        });
    }

    // ========================================
    // HIGH PRIORITY SECURITY
    // ========================================

    if (features.runs_as_root === 1) {
        recommendations.push({
            id: 'root_user',
            priority: 'HIGH',
            score: 75,
            category: 'Access Control',
            icon: '👤',
            title: 'Container Runs as Root',
            problem: 'Container runs with root privileges (UID 0). If compromised, attacker has full system control.',
            impact: '• Privilege escalation\n• Host system compromise\n• Container breakout potential\n• Violates least-privilege principle',
            solution: 'Create and use a non-root user',
            actions: [
                {
                    type: 'fix',
                    text: 'Add non-root user to Dockerfile',
                    command: null
                },
                {
                    type: 'verify',
                    text: 'Verify user is not root',
                    command: 'docker run myimage whoami  # should NOT output "root"'
                }
            ],
            dockerfile: `# Add this to your Dockerfile:\n\n# For Alpine-based images:\nRUN addgroup -g 1000 appuser && \\\n    adduser -u 1000 -G appuser -D appuser\n\n# For Debian/Ubuntu images:\nRUN groupadd -g 1000 appuser && \\\n    useradd -u 1000 -g appuser -m appuser\n\n# Switch to non-root user\nUSER appuser\n\n# Set working directory with proper permissions\nWORKDIR /app\nCOPY --chown=appuser:appuser . .`
        });
    }

    if (features.known_cves > 50) {
        recommendations.push({
            id: 'high_cves',
            priority: 'HIGH',
            score: 70,
            category: 'Vulnerabilities',
            icon: '🐛',
            title: `${features.known_cves} Known Vulnerabilities`,
            problem: `Image contains ${features.known_cves} CVEs. Each is a potential entry point for attackers.`,
            impact: '• Remote code execution\n• Data exfiltration\n• Denial of service\n• Privilege escalation',
            solution: 'Update base image and migrate to Alpine',
            actions: [
                {
                    type: 'immediate',
                    text: 'Update to latest base image version',
                    command: `# If using: FROM ubuntu:18.04\n# Update to: FROM ubuntu:22.04\n\n# Rebuild:\ndocker build -t myimage:latest .`
                },
                {
                    type: 'optimize',
                    text: `Switch to Alpine to reduce CVEs by ~${Math.round(features.known_cves * 0.65)}`,
                    command: null
                }
            ],
            dockerfile: `# ❌ CURRENT (${features.known_cves} CVEs):\nFROM node:18\n\n# ✅ RECOMMENDED (~${Math.round(features.known_cves * 0.35)} CVEs):\nFROM node:18-alpine\n\n# Or use distroless for even fewer CVEs:\nFROM gcr.io/distroless/nodejs:18`
        });
    }

    if (features.outdated_base === 1) {
        recommendations.push({
            id: 'outdated_base',
            priority: 'HIGH',
            score: 70,
            category: 'Base Image',
            icon: '📅',
            title: 'End-of-Life Base Image',
            problem: 'Using EOL distribution that no longer receives security updates.',
            impact: '• No security patches available\n• Known exploits won\'t be fixed\n• Compliance failures\n• Increasing CVE count over time',
            solution: 'Migrate to supported base image',
            actions: [
                {
                    type: 'migrate',
                    text: 'Update to current LTS version',
                    command: null
                }
            ],
            dockerfile: `# Migration guide:\n\n# Ubuntu 14.04 → Ubuntu 22.04 LTS\nFROM ubuntu:22.04\n\n# Debian Jessie → Debian Bookworm\nFROM debian:bookworm-slim\n\n# CentOS 6/7 → Rocky Linux 9\nFROM rockylinux:9\n\n# Python 2.7 → Python 3.12\nFROM python:3.12-slim\n\n# Node 10 → Node 20 LTS\nFROM node:20-alpine`
        });
    }

    if (features.privilege_escalation_risk > 0.6) {
        recommendations.push({
            id: 'priv_esc',
            priority: 'HIGH',
            score: 65,
            category: 'Security',
            icon: '⬆️',
            title: 'Privilege Escalation Risk',
            problem: 'Image contains setuid binaries, sudo, or other privilege escalation vectors.',
            impact: '• Attackers can gain root access\n• Container escape potential\n• Bypasses security controls',
            solution: 'Remove setuid bits and sudo',
            actions: [
                {
                    type: 'fix',
                    text: 'Remove setuid/setgid bits from binaries',
                    command: 'RUN find / -perm /6000 -type f -exec chmod a-s {} \\; || true'
                },
                {
                    type: 'fix',
                    text: 'Remove sudo if installed',
                    command: 'RUN apt-get purge -y sudo'
                }
            ]
        });
    }

    // ========================================
    // MEDIUM PRIORITY OPTIMIZATIONS
    // ========================================

    if (features.image_age_days > 365 && features.image_age_days < 730) {
        recommendations.push({
            id: 'old_image',
            priority: 'MEDIUM',
            score: 50,
            category: 'Maintenance',
            icon: '🕐',
            title: `Image is ${Math.round(features.image_age_days / 30)} Months Old`,
            problem: `Base image hasn't been updated in ${Math.round(features.image_age_days / 30)} months. Missing ${Math.round(features.image_age_days / 30 * 2)} months of security patches.`,
            impact: '• Accumulating vulnerabilities\n• Missing performance improvements\n• Compatibility issues with newer tools',
            solution: 'Rebuild with latest base image',
            actions: [
                {
                    type: 'update',
                    text: 'Pull latest base image and rebuild',
                    command: 'docker pull <base-image>:latest\ndocker build --no-cache -t myimage:latest .'
                },
                {
                    type: 'automate',
                    text: 'Set up automated rebuilds (monthly)',
                    command: '# Use CI/CD to rebuild monthly:\n# GitHub Actions, GitLab CI, etc.'
                }
            ]
        });
    }

    if (features.known_cves > 20 && features.known_cves <= 50 && !scanResult.image.includes('alpine')) {
        recommendations.push({
            id: 'alpine_migration',
            priority: 'MEDIUM',
            score: 55,
            category: 'Optimization',
            icon: '🏔️',
            title: 'Consider Alpine Linux',
            problem: `Current image has ${features.known_cves} CVEs. Alpine-based images typically have 60-80% fewer vulnerabilities.`,
            impact: `• Reduce CVEs from ${features.known_cves} to ~${Math.round(features.known_cves * 0.3)}\n• Smaller image size (~10MB vs ~100MB)\n• Faster deployments\n• Lower attack surface`,
            solution: 'Migrate to Alpine variant',
            actions: [
                {
                    type: 'migrate',
                    text: 'Switch to Alpine-based image',
                    command: null
                }
            ],
            dockerfile: `# Common Alpine migrations:\n\n# nginx:latest → nginx:alpine\nFROM nginx:alpine\n\n# python:3.11 → python:3.11-alpine\nFROM python:3.11-alpine\n\n# node:18 → node:18-alpine\nFROM node:18-alpine\n\n# Note: May need to install additional packages:\nRUN apk add --no-cache gcc musl-dev`
        });
    }

    if (features.external_calls > 5) {
        recommendations.push({
            id: 'external_calls',
            priority: 'MEDIUM',
            score: 45,
            category: 'Network',
            icon: '🌐',
            title: `${features.external_calls} External Network Calls`,
            problem: 'Excessive use of curl/wget in Dockerfile. Each download is a potential supply chain attack vector.',
            impact: '• Supply chain attacks\n• Man-in-the-middle risks\n• Build reproducibility issues\n• Slower builds',
            solution: 'Use official package managers instead',
            actions: [
                {
                    type: 'replace',
                    text: 'Use apt/apk instead of curl/wget when possible',
                    command: null
                },
                {
                    type: 'verify',
                    text: 'Verify downloads with checksums',
                    command: 'RUN curl -fsSL https://example.com/file -o file && \\\n    echo "expected_sha256  file" | sha256sum -c -'
                }
            ],
            dockerfile: `# ❌ AVOID:\nRUN curl https://random-site.com/install.sh | bash\nRUN wget http://untrusted.com/binary\n\n# ✅ PREFER:\nRUN apt-get update && apt-get install -y package\nRUN apk add --no-cache package\n\n# If you must download:\nRUN curl -fsSL https://trusted.com/file -o file && \\\n    echo "sha256_hash  file" | sha256sum -c - && \\\n    chmod +x file`
        });
    }

    if (features.temp_file_activity > 0.5) {
        recommendations.push({
            id: 'temp_files',
            priority: 'MEDIUM',
            score: 40,
            category: 'Best Practices',
            icon: '🗑️',
            title: 'Excessive Temporary Files',
            problem: 'Heavy use of /tmp and temporary directories. May leave sensitive data in image layers.',
            impact: '• Larger image size\n• Potential data leaks in layers\n• Build cache inefficiency',
            solution: 'Clean up temporary files in same layer',
            actions: [
                {
                    type: 'fix',
                    text: 'Combine commands to clean up in same layer',
                    command: null
                }
            ],
            dockerfile: `# ❌ DON'T:\nRUN wget https://example.com/file.tar.gz\nRUN tar -xzf file.tar.gz\nRUN rm file.tar.gz  # Too late - already in previous layer!\n\n# ✅ DO:\nRUN wget https://example.com/file.tar.gz && \\\n    tar -xzf file.tar.gz && \\\n    rm file.tar.gz  # Cleaned up in same layer`
        });
    }

    if (features.anti_analysis_score > 0.5) {
        recommendations.push({
            id: 'anti_analysis',
            priority: 'HIGH',
            score: 75,
            category: 'Suspicious',
            icon: '🕵️',
            title: 'Anti-Analysis Techniques Detected',
            problem: 'Image uses obfuscation or evasion tactics: base64 encoding, clearing history, or log deletion.',
            impact: '• May indicate malicious intent\n• Hinders security auditing\n• Violates security policies',
            solution: 'Review image for malicious code',
            actions: [
                {
                    type: 'investigate',
                    text: 'Manually review Dockerfile for suspicious commands',
                    command: 'docker history --no-trunc ' + scanResult.image
                },
                {
                    type: 'replace',
                    text: 'If unsure, use official image instead',
                    command: 'docker pull <official-alternative>'
                }
            ]
        });
    }

    // ========================================
    // LOW PRIORITY / BEST PRACTICES
    // ========================================

    if (features.suspicious_ports > 1) {
        recommendations.push({
            id: 'ports',
            priority: 'LOW',
            score: 30,
            category: 'Network',
            icon: '🔌',
            title: 'Unusual Port Exposures',
            problem: 'Image exposes uncommon ports that may not be necessary.',
            impact: '• Increased attack surface\n• May indicate hidden services',
            solution: 'Review and minimize exposed ports',
            actions: [
                {
                    type: 'review',
                    text: 'List exposed ports',
                    command: 'docker inspect ' + scanResult.image + ' | grep ExposedPorts'
                },
                {
                    type: 'fix',
                    text: 'Only EXPOSE necessary ports',
                    command: 'EXPOSE 8080  # Only expose what you need'
                }
            ]
        });
    }

    // Sort by priority score (highest first)
    return recommendations.sort((a, b) => b.score - a.score);
};

// Helper function to get priority color
export const getPriorityColor = (priority) => {
    const colors = {
        CRITICAL: 'bg-red-500 border-red-600',
        HIGH: 'bg-orange-500 border-orange-600',
        MEDIUM: 'bg-yellow-500 border-yellow-600',
        LOW: 'bg-blue-500 border-blue-600'
    };
    return colors[priority] || 'bg-gray-500 border-gray-600';
};

export const getPriorityTextColor = (priority) => {
    const colors = {
        CRITICAL: 'text-red-400 border-red-500',
        HIGH: 'text-orange-400 border-orange-500',
        MEDIUM: 'text-yellow-400 border-yellow-500',
        LOW: 'text-blue-400 border-blue-500'
    };
    return colors[priority] || 'text-gray-400 border-gray-500';
};
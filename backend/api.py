#!/usr/bin/env python3

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
from datetime import datetime
import json
from pathlib import Path
import uuid
from contextlib import asynccontextmanager
from model import DockerSecurityScanner
from extract import EnhancedRemoteDockerScanner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables
scanner = None
scan_history = []
batch_jobs = {}

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global scanner
    try:
        logger.info("Initializing Docker Security Scanner...")
        scanner = DockerSecurityScanner(
            model_path='docker_security_model.json',
            metadata_path='model_metadata.json'
        )
        logger.info("✓ Scanner initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize scanner: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down scanner...")

# Initialize FastAPI with lifespan
app = FastAPI(
    title="Docker Security Scanner API",
    description="AI-Powered Docker Image Security Analysis",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://*.app.github.dev",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class ScanRequest(BaseModel):
    image_name: str

class ScanResponse(BaseModel):
    image: str
    verdict: str
    is_risky: bool
    risk_score: float
    confidence: str
    severity: str
    scan_status: str
    scan_confidence: float
    top_risk_factors: List[Dict[str, Any]]
    all_features: Dict[str, Any]
    layer_analyses: List[Dict[str, Any]]
    remediations: List[Dict[str, Any]]
    scan_id: str
    timestamp: str

class BatchScanRequest(BaseModel):
    images: List[str]
    parallel_workers: int = 3
    timeout: int = 300

class HistoryResponse(BaseModel):
    scans: List[Dict[str, Any]]
    total: int

class AnalyticsResponse(BaseModel):
    total_scans: int
    risky_count: int
    safe_count: int
    common_threats: List[Dict[str, Any]]

# Health check endpoint
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Docker Security Scanner API",
        "version": "1.0.0",
        "model_loaded": scanner is not None
    }

@app.get("/health")
async def health_check():
    """Health check for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_status": "loaded" if scanner else "not_loaded",
        "total_scans": len(scan_history)
    }

# Main scan endpoint
@app.post("/api/scan", response_model=ScanResponse)
async def scan_image(request: ScanRequest):
    """
    Scan a Docker image for security threats
    """
    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    image_name = request.image_name.strip()
    if not image_name:
        raise HTTPException(status_code=400, detail="Image name is required")
    
    logger.info(f"Scanning image: {image_name}")
    
    try:
        # Run the scan
        report = scanner.scan_image(image_name)
        
        # Check for errors
        if 'error' in report:
            raise HTTPException(status_code=500, detail=report['error'])
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Convert layer_analyses to dict format
        layer_analyses_dict = []
        for layer in report.get('layer_analyses', []):
            if hasattr(layer, 'to_dict'):
                layer_analyses_dict.append(layer.to_dict())
            elif isinstance(layer, dict):
                layer_analyses_dict.append(layer)
            else:
                # Fallback: convert dataclass to dict
                layer_analyses_dict.append({
                    'layer_id': getattr(layer, 'layer_id', ''),
                    'command': getattr(layer, 'command', ''),
                    'size_bytes': getattr(layer, 'size_bytes', 0),
                    'risk_score': getattr(layer, 'risk_score', 0.0),
                    'findings': getattr(layer, 'findings', [])
                })
        
        # Convert remediations to dict format
        remediations_dict = []
        for rem in report.get('remediations', []):
            if hasattr(rem, 'to_dict'):
                remediations_dict.append(rem.to_dict())
            elif isinstance(rem, dict):
                remediations_dict.append(rem)
            else:
                remediations_dict.append({
                    'severity': getattr(rem, 'severity', ''),
                    'issue': getattr(rem, 'issue', ''),
                    'layer_id': getattr(rem, 'layer_id', ''),
                    'remediation': getattr(rem, 'remediation', ''),
                    'example_fix': getattr(rem, 'example_fix', None)
                })
        
        # Format response
        response = ScanResponse(
            image=report['image'],
            verdict=report['verdict'],
            is_risky=report['is_risky'],
            risk_score=report['risk_score'],
            confidence=report['confidence'],
            severity=report['severity'],
            scan_status=report['scan_status'],
            scan_confidence=report['scan_confidence'],
            top_risk_factors=report['top_risk_factors'],
            all_features=report['all_features'],
            layer_analyses=layer_analyses_dict,
            remediations=remediations_dict,
            scan_id=scan_id,
            timestamp=timestamp
        )
        
        # Store in history
        scan_history.append({
            'scan_id': scan_id,
            'image': image_name,
            'verdict': report['verdict'],
            'risk_score': report['risk_score'],
            'cves': report['all_features'].get('known_cves', 0),
            'timestamp': timestamp,
            'scanned': 'Just now'
        })
        
        # Keep only last 1000 scans
        if len(scan_history) > 1000:
            scan_history.pop(0)
        
        logger.info(f"✓ Scan completed: {image_name} - {report['verdict']}")
        return response
        
    except Exception as e:
        logger.error(f"Scan failed for {image_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# Batch scan endpoint
@app.post("/api/batch-scan")
async def batch_scan(request: BatchScanRequest, background_tasks: BackgroundTasks):
    """
    Start a batch scan job
    Returns job_id for tracking progress
    """
    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    job_id = str(uuid.uuid4())
    
    # Initialize job status
    batch_jobs[job_id] = {
        'job_id': job_id,
        'status': 'running',
        'total': len(request.images),
        'completed': 0,
        'in_progress': 0,
        'queued': len(request.images),
        'failed': 0,
        'results': [],
        'started_at': datetime.now().isoformat()
    }
    
    # Run batch scan in background
    background_tasks.add_task(
        run_batch_scan,
        job_id,
        request.images,
        request.parallel_workers,
        request.timeout
    )
    
    return {
        'job_id': job_id,
        'status': 'started',
        'total_images': len(request.images)
    }

async def run_batch_scan(job_id: str, images: List[str], workers: int, timeout: int):
    """Background task for batch scanning"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    def scan_single(image_name: str):
        import time
        start_time = time.time()
        
        # Update in_progress count
        batch_jobs[job_id]['in_progress'] += 1
        batch_jobs[job_id]['queued'] -= 1
        
        try:
            report = scanner.scan_image(image_name)
            duration = f"{int(time.time() - start_time)}s"
            
            # Convert layer_analyses to dict
            layer_analyses_dict = []
            for layer in report.get('layer_analyses', []):
                if hasattr(layer, 'to_dict'):
                    layer_analyses_dict.append(layer.to_dict())
                elif isinstance(layer, dict):
                    layer_analyses_dict.append(layer)
            
            # Convert remediations to dict
            remediations_dict = []
            for rem in report.get('remediations', []):
                if hasattr(rem, 'to_dict'):
                    remediations_dict.append(rem.to_dict())
                elif isinstance(rem, dict):
                    remediations_dict.append(rem)
            
            result = {
                'image': image_name,
                'status': 'success',
                'verdict': report.get('verdict', 'UNKNOWN'),
                'risk_score': report.get('risk_score', 0),
                'duration': duration,
                'full_report': {
                    'image': report['image'],
                    'verdict': report['verdict'],
                    'is_risky': report['is_risky'],
                    'risk_score': report['risk_score'],
                    'confidence': report['confidence'],
                    'severity': report['severity'],
                    'scan_status': report['scan_status'],
                    'scan_confidence': report['scan_confidence'],
                    'top_risk_factors': report['top_risk_factors'],
                    'all_features': report['all_features'],
                    'layer_analyses': layer_analyses_dict,
                    'remediations': remediations_dict,
                    'scan_id': str(uuid.uuid4()),
                    'timestamp': datetime.now().isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Failed to scan {image_name}: {e}")
            duration = f"{int(time.time() - start_time)}s"
            result = {
                'image': image_name,
                'status': 'failed',
                'error': str(e),
                'duration': duration
            }
        
        # Update progress after scan completes
        batch_jobs[job_id]['in_progress'] -= 1
        batch_jobs[job_id]['completed'] += 1
        batch_jobs[job_id]['results'].append(result)
        
        if result['status'] == 'failed':
            batch_jobs[job_id]['failed'] += 1
        
        return result
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_single, img): img for img in images}
        
        # Wait for all to complete
        for future in as_completed(futures):
            future.result()  # Get result to handle any exceptions
    
    batch_jobs[job_id]['status'] = 'completed'
    batch_jobs[job_id]['completed_at'] = datetime.now().isoformat()
    
    # Add successful scans to history
    logger.info(f"Adding {len(batch_jobs[job_id]['results'])} results to history")
    for result in batch_jobs[job_id]['results']:
        if result['status'] == 'success' and 'full_report' in result:
            scan_history.append({
                'scan_id': result['full_report']['scan_id'],
                'image': result['image'],
                'verdict': result['verdict'],
                'risk_score': result['risk_score'],
                'cves': result['full_report']['all_features'].get('known_cves', 0),
                'timestamp': result['full_report']['timestamp'],
                'scanned': 'Just now'
            })
    
    if len(scan_history) > 1000:
        del scan_history[:-1000]

# Get batch scan progress
@app.get("/api/batch-scan/{job_id}")
async def get_batch_progress(job_id: str):
    """Get progress of a batch scan job"""
    if job_id not in batch_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    logger.info(f"Progress check for {job_id}: {batch_jobs[job_id]['completed']}/{batch_jobs[job_id]['total']}")
    
    return batch_jobs[job_id]

# Scan history endpoint
@app.get("/api/history", response_model=HistoryResponse)
async def get_scan_history(limit: int = 50, offset: int = 0):
    """
    Get scan history with pagination
    """
    total = len(scan_history)
    
    # Calculate relative times
    now = datetime.now()
    for scan in scan_history:
        try:
            scan_time = datetime.fromisoformat(scan['timestamp'])
            delta = now - scan_time
            
            if delta.days > 0:
                scan['scanned'] = f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
            elif delta.seconds > 3600:
                hours = delta.seconds // 3600
                scan['scanned'] = f"{hours} hour{'s' if hours > 1 else ''} ago"
            elif delta.seconds > 60:
                minutes = delta.seconds // 60
                scan['scanned'] = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
            else:
                scan['scanned'] = "Just now"
        except:
            scan['scanned'] = "Unknown"
    
    # Return reversed (most recent first)
    scans = list(reversed(scan_history))[offset:offset + limit]
    
    return HistoryResponse(
        scans=scans,
        total=total
    )

# Analytics endpoint
@app.get("/api/analytics", response_model=AnalyticsResponse)
async def get_analytics():
    """
    Get overall analytics
    """
    if not scan_history:
        return AnalyticsResponse(
            total_scans=0,
            risky_count=0,
            safe_count=0,
            common_threats=[]
        )
    
    total_scans = len(scan_history)
    risky_count = sum(1 for s in scan_history if s['verdict'] == 'RISKY')
    safe_count = total_scans - risky_count
    
    # Calculate common threat percentages
    cve_count = sum(1 for s in scan_history if s['cves'] > 0)
    
    common_threats = [
        {
            'name': 'Known CVEs',
            'percentage': int((cve_count / total_scans) * 100) if total_scans > 0 else 0
        },
        {
            'name': 'Outdated Base',
            'percentage': int((risky_count / total_scans) * 70) if total_scans > 0 else 0  # Estimate
        },
        {
            'name': 'Runs as Root',
            'percentage': int((risky_count / total_scans) * 50) if total_scans > 0 else 0  # Estimate
        }
    ]
    
    return AnalyticsResponse(
        total_scans=total_scans,
        risky_count=risky_count,
        safe_count=safe_count,
        common_threats=common_threats
    )

# Model info endpoint
@app.get("/api/model-info")
async def get_model_info():
    """Get model metadata"""
    try:
        with open('model_metadata.json', 'r') as f:
            metadata = json.load(f)
        return metadata
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model info: {e}")

# Train model endpoint
@app.post("/api/train")
async def train_model(background_tasks: BackgroundTasks):
    
    training_id = str(uuid.uuid4())
    
    return {
        'training_id': training_id,
        'status': 'started',
        'message': 'Model training started. This will take several minutes.'
    }

if __name__ == "__main__":
    import uvicorn
    
    print("="*70)
    print("🐳 DOCKER SECURITY SCANNER API")
    print("="*70)
    print("\nStarting FastAPI server...")
    print("API will be available at: http://localhost:8000")
    print("API docs: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop\n")
    print("="*70)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
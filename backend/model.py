import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
import json
import sys
from pathlib import Path
import logging
logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')
from extract import EnhancedRemoteDockerScanner

# ============================================
# STEP 1: TRAIN MODEL WITH COMPREHENSIVE ANALYSIS
# ============================================

def train_and_analyze_model(csv_path='data/merged_docker_features.csv', save_analysis=True):
    """
    Train XGBoost on your dataset with comprehensive analysis
    
    Args:
        csv_path: Path to your CSV file
        save_analysis: Whether to save analysis plots and reports
    
    Returns:
        model, feature_names, analysis_results
    """
    
    print("="*70)
    print("DOCKER SECURITY MODEL TRAINING & ANALYSIS")
    print("="*70)
    
    # Load dataset
    df = pd.read_csv(csv_path)
    
    # Separate features and target
    X = df.drop('label', axis=1)
    y = df['label']
    
    feature_names = X.columns.tolist()
    
    print(f"\n✓ Dataset loaded: {len(df)} images")
    print(f"✓ Features: {len(feature_names)}")
    print(f"\nClass distribution:")
    print(f"  Safe (0):  {(y==0).sum()} images ({(y==0).sum()/len(y)*100:.1f}%)")
    print(f"  Risky (1): {(y==1).sum()} images ({(y==1).sum()/len(y)*100:.1f}%)")
    
    # Check for class imbalance
    imbalance_ratio = max((y==0).sum(), (y==1).sum()) / min((y==0).sum(), (y==1).sum())
    if imbalance_ratio > 2:
        print(f"  ⚠️  Class imbalance detected: {imbalance_ratio:.2f}x")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTrain set: {len(X_train)} images (Safe: {(y_train==0).sum()}, Risky: {(y_train==1).sum()})")
    print(f"Test set:  {len(X_test)} images (Safe: {(y_test==0).sum()}, Risky: {(y_test==1).sum()})")
    
    # Handle class imbalance
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    print(f"\nUsing scale_pos_weight: {scale_pos_weight:.2f}")


    feature_weights = np.ones(len(X_train.columns))

    # Find CVE column index
    cve_idx = X_train.columns.get_loc('known_cves')
    age_idx = X_train.columns.get_loc('image_age_days')

    # Boost CVE importance by 3x
    feature_weights[cve_idx] = 3.0

    # Keep age strong (already 32%)
    feature_weights[age_idx] = 1.0
    
    # Train XGBoost with optimal parameters
    model = xgb.XGBClassifier(
        max_depth=6,
        learning_rate=0.1,
        n_estimators=150,
        objective='binary:logistic',
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        eval_metric='auc',
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=1,
        gamma=0.1,
        feature_weights=feature_weights 
    )
    
    print("\n" + "="*70)
    print("TRAINING MODEL...")
    print("="*70)
    
    # Train with evaluation
    eval_set = [(X_train, y_train), (X_test, y_test)]
    model.fit(
        X_train, y_train,
        eval_set=eval_set,
        verbose=True
    )
    
    # ============================================
    # COMPREHENSIVE MODEL EVALUATION
    # ============================================
    
    print("\n" + "="*70)
    print("MODEL PERFORMANCE EVALUATION")
    print("="*70)
    
    # Predictions
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)
    y_pred_proba_train = model.predict_proba(X_train)[:, 1]
    y_pred_proba_test = model.predict_proba(X_test)[:, 1]
    
    # Training performance
    print("\n📊 TRAINING SET PERFORMANCE:")
    print(classification_report(y_train, y_pred_train, target_names=['Safe', 'Risky']))
    print(f"ROC-AUC Score: {roc_auc_score(y_train, y_pred_proba_train):.4f}")
    
    # Test performance
    print("\n📊 TEST SET PERFORMANCE:")
    print(classification_report(y_test, y_pred_test, target_names=['Safe', 'Risky']))
    test_auc = roc_auc_score(y_test, y_pred_proba_test)
    print(f"ROC-AUC Score: {test_auc:.4f}")
    
    # Confusion matrix analysis
    cm = confusion_matrix(y_test, y_pred_test)
    tn, fp, fn, tp = cm.ravel()
    
    print("\n📊 CONFUSION MATRIX ANALYSIS:")
    print(f"  True Negatives (Correctly identified safe):   {tn:3d}")
    print(f"  False Positives (Safe flagged as risky):      {fp:3d}")
    print(f"  False Negatives (Risky missed):               {fn:3d} ⚠️")
    print(f"  True Positives (Correctly identified risky):  {tp:3d}")
    
    # Calculate metrics
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print(f"\n📈 KEY METRICS:")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision: {precision:.4f} (of images flagged as risky, {precision*100:.1f}% are actually risky)")
    print(f"  Recall:    {recall:.4f} (detects {recall*100:.1f}% of all risky images)")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  FPR:       {false_positive_rate:.4f} ({false_positive_rate*100:.2f}% safe images incorrectly flagged)")
    
    # Check for overfitting
    train_auc = roc_auc_score(y_train, y_pred_proba_train)
    if train_auc - test_auc > 0.1:
        print(f"\n⚠️  WARNING: Possible overfitting detected (train AUC: {train_auc:.4f}, test AUC: {test_auc:.4f})")
    else:
        print(f"\n✓ Model generalizes well (train AUC: {train_auc:.4f}, test AUC: {test_auc:.4f})")
    
    # ============================================
    # FEATURE IMPORTANCE ANALYSIS
    # ============================================
    
    print("\n" + "="*70)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("="*70)
    
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n🔍 TOP 20 MOST IMPORTANT SECURITY INDICATORS:")
    for idx, (_, row) in enumerate(feature_importance.head(20).iterrows(), 1):
        bar = "█" * int(row['importance'] * 50)
        print(f"{idx:2d}. {row['feature']:35s} {row['importance']:.4f} {bar}")
    
    # Low importance features
    low_importance = feature_importance[feature_importance['importance'] < 0.01]
    if len(low_importance) > 0:
        print(f"\n💡 {len(low_importance)} features have very low importance (<0.01):")
        print(f"   {', '.join(low_importance['feature'].tolist()[:10])}")
    
    # ============================================
    # ERROR ANALYSIS
    # ============================================
    
    print("\n" + "="*70)
    print("ERROR ANALYSIS")
    print("="*70)
    
    # False Positives (Safe images flagged as risky)
    fp_indices = (y_test == 0) & (y_pred_test == 1)
    if fp_indices.sum() > 0:
        print(f"\n❌ FALSE POSITIVES ({fp_indices.sum()} safe images incorrectly flagged):")
        fp_features = X_test[fp_indices]
        fp_proba = y_pred_proba_test[fp_indices.values]
        
        # Show top features for false positives
        fp_mean = fp_features.mean()
        top_fp_features = fp_mean.nlargest(5)
        print("   Most common elevated features in false positives:")
        for feat, val in top_fp_features.items():
            print(f"   • {feat}: {val:.3f}")
    
    # False Negatives (Risky images that were missed)
    fn_indices = (y_test == 1) & (y_pred_test == 0)
    if fn_indices.sum() > 0:
        print(f"\n❌ FALSE NEGATIVES ({fn_indices.sum()} risky images MISSED - CRITICAL!):")
        fn_features = X_test[fn_indices]
        fn_proba = y_pred_proba_test[fn_indices.values]
        
        print(f"   Risk scores of missed threats: {fn_proba}")
        print(f"   Average risk score: {fn_proba.mean():.3f} (threshold: 0.5)")
        
        # Show why they were missed
        fn_mean = fn_features.mean()
        print("   Average feature values in missed threats:")
        for feat in feature_importance.head(10)['feature']:
            print(f"   • {feat}: {fn_mean[feat]:.3f}")
    
    # ============================================
    # SAVE MODEL AND ANALYSIS
    # ============================================
    
    model.save_model('docker_security_model.json')
    
    analysis_results = {
        'feature_names': feature_names,
        'feature_importance': feature_importance.to_dict('records'),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'train_auc': float(train_auc),
        'test_auc': float(test_auc),
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'false_positive_rate': float(false_positive_rate),
        'confusion_matrix': {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        },
        'class_distribution': {
            'safe': int((y==0).sum()),
            'risky': int((y==1).sum())
        }
    }
    
    with open('model_metadata.json', 'w') as f:
        json.dump(analysis_results, f, indent=2)
    
    print("\n" + "="*70)
    print("✓ Model saved to 'docker_security_model.json'")
    print("✓ Metadata saved to 'model_metadata.json'")
    print("="*70)
    
    # Create visualizations if requested
    if save_analysis:
        create_visualizations(feature_importance, y_test, y_pred_proba_test, cm)
    
    return model, feature_names, analysis_results


def train_behavioral_scorer(csv_path='data/merged_docker_features.csv'):
    """
    Train a lightweight model to score behavioral patterns
    This replaces hardcoded thresholds in behavioral_analyzer.py
    """
    df = pd.read_csv(csv_path)
    
    # Features that come from behavioral analysis
    behavioral_features = [
        'layer_deletion_score',
        'temp_file_activity', 
        'process_injection_risk',
        'privilege_escalation_risk',
        'anti_analysis_score',
        'crypto_mining_behavior',
        'external_calls'
    ]
    
    X_behavioral = df[behavioral_features]
    y = df['label']
    
    # Train a simple model to learn behavioral weights
    behavioral_model = xgb.XGBRegressor(
        max_depth=3,
        learning_rate=0.1,
        n_estimators=50,
        objective='reg:squarederror'
    )
    
    behavioral_model.fit(X_behavioral, y)
    
    # Get learned weights for each pattern
    learned_weights = {
        feat: float(imp) 
        for feat, imp in zip(behavioral_features, behavioral_model.feature_importances_)
    }
    
    # Save weights
    with open('behavioral_weights.json', 'w') as f:
        json.dump(learned_weights, f, indent=2)
    
    print("\n✅ Learned behavioral weights:")
    for feat, weight in sorted(learned_weights.items(), key=lambda x: x[1], reverse=True):
        print(f"  {feat:35s}: {weight:.4f}")
    
    return learned_weights

def create_visualizations(feature_importance, y_test, y_pred_proba, confusion_matrix):
    """Create and save analysis visualizations"""
    
    try:
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. Feature Importance
        top_features = feature_importance.head(15)
        axes[0, 0].barh(range(len(top_features)), top_features['importance'])
        axes[0, 0].set_yticks(range(len(top_features)))
        axes[0, 0].set_yticklabels(top_features['feature'])
        axes[0, 0].set_xlabel('Importance')
        axes[0, 0].set_title('Top 15 Feature Importance')
        axes[0, 0].invert_yaxis()
        
        # 2. ROC Curve
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        auc_score = roc_auc_score(y_test, y_pred_proba)
        axes[0, 1].plot(fpr, tpr, label=f'AUC = {auc_score:.3f}')
        axes[0, 1].plot([0, 1], [0, 1], 'k--', label='Random')
        axes[0, 1].set_xlabel('False Positive Rate')
        axes[0, 1].set_ylabel('True Positive Rate')
        axes[0, 1].set_title('ROC Curve')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # 3. Confusion Matrix
        sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues', ax=axes[1, 0])
        axes[1, 0].set_xlabel('Predicted')
        axes[1, 0].set_ylabel('Actual')
        axes[1, 0].set_title('Confusion Matrix')
        axes[1, 0].set_xticklabels(['Safe', 'Risky'])
        axes[1, 0].set_yticklabels(['Safe', 'Risky'])
        
        # 4. Prediction Distribution
        axes[1, 1].hist(y_pred_proba[y_test == 0], bins=30, alpha=0.5, label='Safe', color='green')
        axes[1, 1].hist(y_pred_proba[y_test == 1], bins=30, alpha=0.5, label='Risky', color='red')
        axes[1, 1].axvline(0.5, color='black', linestyle='--', label='Threshold')
        axes[1, 1].set_xlabel('Risk Score')
        axes[1, 1].set_ylabel('Count')
        axes[1, 1].set_title('Risk Score Distribution')
        axes[1, 1].legend()
        
        plt.tight_layout()
        plt.savefig('model_analysis.png', dpi=300, bbox_inches='tight')
        print("✓ Visualizations saved to 'model_analysis.png'")
        
    except Exception as e:
        print(f"⚠️  Could not create visualizations: {e}")


# ============================================
# STEP 2: SCAN NEW IMAGES
# ============================================

class DockerSecurityScanner:
    """
    Scan Docker images for security threats using trained model
    """
    
    def __init__(self, model_path='docker_security_model.json', 
                 metadata_path='model_metadata.json'):
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            self.feature_names = metadata['feature_names']
            self.feature_importance = {
                item['feature']: item['importance'] 
                for item in metadata['feature_importance']
            }
        
        # Initialize the feature extractor
        self.extractor = EnhancedRemoteDockerScanner(timeout_per_scan=300)
        
        print(f"✓ Model loaded (AUC: {metadata['test_auc']:.4f})")
        print(f"✓ Using {len(self.feature_names)} features")
    
    def scan_image(self, image_name):
        """
        Scan a Docker image from registry
        
        Args:
            image_name: Docker image name (e.g., 'nginx:latest')
        
        Returns:
            Complete security report with prediction
        """
        
        print(f"\n{'='*70}")
        print(f"SCANNING: {image_name}")
        print(f"{'='*70}")
        
        # Extract features using your existing tool
        print("\n🔍 Extracting features...")
        features = self.extractor.extract_features(image_name)
        
        if features.scan_status == 'failed':
            return {
                'error': 'Feature extraction failed',
                'image': image_name,
                'scan_status': 'failed'
            }
        
        # Convert to dict
        image_features = {
            'cryptominer_binary': features.cryptominer_binary,
            'mining_pools': features.mining_pools,
            'hardcoded_secrets': features.hardcoded_secrets,
            'external_calls': features.external_calls,
            'ssh_backdoor': features.ssh_backdoor,
            'runs_as_root': features.runs_as_root,
            'known_cves': features.known_cves,
            'outdated_base': features.outdated_base,
            'typosquatting_score': features.typosquatting_score,
            'image_age_days': features.image_age_days,
            'suspicious_ports': features.suspicious_ports,
            'avg_file_entropy': features.avg_file_entropy,
            'high_entropy_ratio': features.high_entropy_ratio,
            'stratum_indicators': features.stratum_indicators,
            'raw_ip_connections': features.raw_ip_connections,
            'suspicious_dns_queries': features.suspicious_dns_queries,
            'stripped_binaries_ratio': features.stripped_binaries_ratio,
            'packed_binary_score': features.packed_binary_score,
            'layer_deletion_score': features.layer_deletion_score,
            'temp_file_activity': features.temp_file_activity,
            'process_injection_risk': features.process_injection_risk,
            'privilege_escalation_risk': features.privilege_escalation_risk,
            'crypto_mining_behavior': features.crypto_mining_behavior,
            'anti_analysis_score': features.anti_analysis_score
        }
        
        # Handle None values (replace with 0 for prediction)
        for key in image_features:
            if image_features[key] is None:
                image_features[key] = 0.0
        
        # Validate features
        missing = set(self.feature_names) - set(image_features.keys())
        if missing:
            return {
                'error': f'Missing features: {missing}',
                'image': image_name
            }
        
        # Prepare data
        X = pd.DataFrame([image_features])[self.feature_names]
        
        # Predict
        print("🤖 Running prediction...")
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0, 1]
        
        # Identify risk factors
        risk_factors = []
        for feature, value in image_features.items():
            if value > 0:
                risk_factors.append({
                    'feature': feature,
                    'value': float(value),
                    'importance': self.feature_importance.get(feature, 0)
                })
        
        risk_factors.sort(key=lambda x: x['importance'] * x['value'], reverse=True)
        
        layer_analyses = []
        remediations = []
    
    # Get cached data
        cache_path = self.extractor.cache_manager.get_cache_path(image_name)
        trivy_file = cache_path / 'trivy.json'
        syft_file = cache_path / 'sbom.json'
    
        if trivy_file.exists():
            import json
            with open(trivy_file) as f:
                trivy_data = json.load(f)
                
            syft_data = {}
            if syft_file.exists():
                with open(syft_file) as f:
                    syft_data = json.load(f)
        
        # Re-run behavioral analyzer to get layer analyses
            from behavioral_analyzer import BehavioralAnalyzer
            analyzer = BehavioralAnalyzer()
        
            metadata = trivy_data.get('Metadata', {})
            image_config = metadata.get('ImageConfig', {})
            history = image_config.get('history', [])
        
            if history:
                for idx, layer in enumerate(history):
                    analysis = analyzer._analyze_layer(idx, layer)
                    layer_analyses.append(analysis)
            
                remediations_objects = analyzer._generate_remediations(layer_analyses)
                for rem in remediations_objects:
                    remediations.append({
                        'severity': rem.severity,
                        'issue': rem.issue,
                        'layer_id': rem.layer_id,
                        'remediation': rem.remediation,
                        'example_fix': rem.example_fix
                        })
    
    
       
        # Build report
        report = {
            'image': image_name,
            'verdict': 'RISKY' if prediction == 1 else 'SAFE',
            'is_risky': bool(prediction),
            'risk_score': float(probability),
            'confidence': f"{max(probability, 1-probability)*100:.1f}%",
            'severity': self._get_severity(probability),
            'scan_status': features.scan_status,
            'scan_confidence': features.confidence_score,
            'top_risk_factors': risk_factors[:10],
            'all_features': image_features,
            'layer_analyses': layer_analyses,  # ADD THIS
            'remediations': remediations  
        }
        # Add remediations if available
        
        
        return report
    
    def _get_severity(self, probability):
        """Convert probability to severity level"""
        if probability < 0.3:
            return 'LOW'
        elif probability < 0.6:
            return 'MEDIUM'
        elif probability < 0.8:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def print_report(self, report):
        """Pretty print security report"""
        
        if 'error' in report:
            print(f"\n❌ ERROR: {report['error']}")
            return
        
        print(f"\n{'='*70}")
        print("DOCKER IMAGE SECURITY SCAN REPORT")
        print(f"{'='*70}")
        
        # Overall verdict
        verdict_emoji = "🔴" if report['is_risky'] else "🟢"
        print(f"\n{verdict_emoji} VERDICT: {report['verdict']}")
        print(f"   Risk Score: {report['risk_score']:.1%} ({report['severity']} severity)")
        print(f"   Confidence: {report['confidence']}")
        print(f"   Scan Status: {report['scan_status']}")
        
        # Top risk factors
        print(f"\n{'─'*70}")
        print("TOP SECURITY CONCERNS")
        print(f"{'─'*70}")
        
        if report['top_risk_factors']:
            for i, factor in enumerate(report['top_risk_factors'][:10], 1):
                importance_bar = "█" * int(factor['importance'] * 20)
                print(f"{i:2d}. {factor['feature']:30s} = {factor['value']:8.3f}")
                print(f"    Importance: {factor['importance']:.4f} {importance_bar}")
        else:
            print("   No significant risk factors detected")
        
        # Feature summary
        print(f"\n{'─'*70}")
        print("FEATURE SUMMARY")
        print(f"{'─'*70}")
        
        critical_features = {
            'cryptominer_binary': 'Crypto miner binary',
            'mining_pools': 'Mining pool connections',
            'hardcoded_secrets': 'Hardcoded secrets',
            'ssh_backdoor': 'SSH backdoor',
            'known_cves': 'Known CVEs',
            'runs_as_root': 'Runs as root'
        }
        
        for key, label in critical_features.items():
            value = report['all_features'].get(key, 0)
            status = "❌" if value > 0 else "✓"
            print(f"{status} {label:30s}: {value}")

     
    # Behavioral Analysis Summary
        print(f"\n{'─'*70}")
        print("BEHAVIORAL ANALYSIS (LAYER-BY-LAYER)")
        print(f"{'─'*70}")
    
        behavioral_features = {
            'crypto_mining_behavior': ('Cryptocurrency mining', 0.5),
            'privilege_escalation_risk': ('Privilege escalation', 0.5),
            'layer_deletion_score': ('Temporal anomalies', 0.3),
            'anti_analysis_score': ('Anti-analysis tactics', 0.5),
            'process_injection_risk': ('Process injection', 0.5),
            'temp_file_activity': ('Suspicious temp file usage', 0.3),
            'external_calls': ('External network calls', 3)
            }
    
        has_behavioral_risk = False
        for key, (label, threshold) in behavioral_features.items():
            value = report['all_features'].get(key, 0)
        
        # Determine status based on thresholds
            if key == 'external_calls':
                if value >= 5:
                    status = "🔴 HIGH"
                    has_behavioral_risk = True
                
                elif value >= 3:
                    status = "🟡 MEDIUM"
                    has_behavioral_risk = True
            
                elif value > 0:
                    status = "⚠️  LOW"
                    
                else:
                    status = "✓ CLEAN"
            else:
            # Float features
                if value >= 0.7:
                    status = "🔴 CRITICAL"
                    has_behavioral_risk = True
                elif value >= threshold:
                    status = "🟠 HIGH"
                    has_behavioral_risk = True
                elif value >= 0.1:
                    status = "🟡 MEDIUM"
                    has_behavioral_risk = True
                elif value > 0:
                    status = "⚠️  LOW"
                else:
                    status = "✓ CLEAN"
        
            print(f"{status:15s} {label:35s}: {value:.3f}" if isinstance(value, float) else f"{status:15s} {label:35s}: {value}")
    
        if not has_behavioral_risk:
            print("\n✅ No significant behavioral threats detected")
    
    # CVE Risk Summary
        print(f"\n{'─'*70}")
        print("CVE & METADATA RISKS")
        print(f"{'─'*70}")
    
        cve_features = {
            'known_cves': ('Known vulnerabilities', 5),
            'outdated_base': ('Outdated base image', 0),
            'image_age_days': ('Image age (days)', 365),
            'hardcoded_secrets': ('Hardcoded secrets', 0),
            'suspicious_ports': ('Suspicious ports exposed', 0)
            }
    
        for key, (label, threshold) in cve_features.items():
            value = report['all_features'].get(key, 0)
            
            if key == 'outdated_base':
                status = "❌ YES" if value == 1 else "✓ NO"
                print(f"{status:15s} {label:35s}")
        
            elif key == 'image_age_days':
                if value > 730:
                    status = "🔴 CRITICAL"
                elif value > 365:
                    status = "🟠 HIGH"
                elif value > 180:
                    status = "🟡 MEDIUM"
                else:
                    status = "✓ FRESH"
                print(f"{status:15s} {label:35s}: {value}")
            else:
                if value >= threshold and value > 0:
                    status = "🔴 HIGH"
                elif value > 0:
                    status = "🟡 MEDIUM"
                else:
                    status = "✓ NONE"
                print(f"{status:15s} {label:35s}: {value}")
    
    
        layer_analyses = report.get('layer_analyses', [])
        remediations = report.get('remediations', [])
    
        if layer_analyses:
            print(f"\n{'─'*70}")
            print("DETAILED LAYER-BY-LAYER ANALYSIS")
            print(f"{'─'*70}")
        
        # Calculate overall layer risk
            max_risk = max(la.risk_score for la in layer_analyses)
            avg_risk = sum(la.risk_score for la in layer_analyses) / len(layer_analyses)
            high_risk_count = sum(1 for la in layer_analyses if la.risk_score > 0.5)
        
            overall_score = (max_risk * 0.5) + (avg_risk * 0.3) + (high_risk_count / len(layer_analyses) * 0.2)
        
            if overall_score >= 0.7:
                level = 'CRITICAL'
                emoji = '🔴'
            elif overall_score >= 0.5:
                level = 'HIGH'
                emoji = '🟠'
            elif overall_score >= 0.3:
                level = 'MEDIUM'
                emoji = '🟡'
            else:
                level = 'LOW'
                emoji = '🟢'
        
            print(f"\n{emoji} Overall Layer Risk: {level} ({overall_score:.1%})")
            print(f"   Total Layers: {len(layer_analyses)}")
            print(f"   High-Risk Layers: {high_risk_count}")
            print(f"   Max Layer Risk: {max_risk:.1%}")
        
        # Show high-risk layers
            high_risk_layers = [la for la in layer_analyses if la.risk_score >= 0.3]
        
            if high_risk_layers:
                print(f"\n🔍 High-Risk Layers Detected:")
                for analysis in high_risk_layers[:5]: 
                    risk_emoji = "🔴" if analysis.risk_score >= 0.7 else "🟠" if analysis.risk_score >= 0.5 else "🟡"
                
                    print(f"\n   {risk_emoji} {analysis.layer_id.upper()} (Risk: {analysis.risk_score:.1%})")
                    print(f"      Command: {analysis.command[:80]}...")
                
                    if analysis.findings:
                        print(f"      Findings:")
                        for finding in analysis.findings[:3]:
                            print(f"         • {finding}")
            
                if len(high_risk_layers) > 5:
                    print(f"\n   ... and {len(high_risk_layers) - 5} more high-risk layers")
            else:
                print(f"\n   ✅ No high-risk layers detected")
    
    # Remediation Recommendations
        if remediations:
            print(f"\n{'─'*70}")
            print("🔧 REMEDIATION RECOMMENDATIONS")
            print(f"{'─'*70}")
        
            # Group by severity
            critical = [r for r in remediations if r['severity'] == "CRITICAL"]
            high = [r for r in remediations if r['severity'] == "HIGH"]
            medium = [r for r in remediations if r['severity'] == "MEDIUM"]
        
            for severity, items in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium)]:
                if not items:
                    continue
            
                icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
                print(f"\n{icon} {severity} PRIORITY ({len(items)} issues)")
            
                

                for idx, rem in enumerate(items[:3], 1):  
                    print(f"\n   {idx}. {rem['issue']}")
                    print(f"      Layer: {rem['layer_id']}")
                    print(f"      Fix: {rem['remediation']}")
    
                    if rem['example_fix']:
                        print(f"      Example:")
                        for line in rem['example_fix'].split('\n')[:4]:  
                            if line.strip():
                                print(f"         {line}")
            
                if len(items) > 3:
                    print(f"\n   ... and {len(items) - 3} more {severity} issues")
    
     
        print(f"\n{'='*70}")




# ============================================
# BATCH TESTING
# ============================================

def test_model_on_images(image_list, model_scanner):
    """
    Test the model on a list of images and compare predictions
    
    Args:
        image_list: List of (image_name, expected_label) tuples
        model_scanner: DockerSecurityScanner instance
    
    Returns:
        Test results with accuracy metrics
    """
    
    print("\n" + "="*70)
    print("BATCH IMAGE TESTING")
    print("="*70)
    
    results = []
    correct = 0
    total = 0
    
    for image_name, expected_label in image_list:
        print(f"\n{'─'*70}")
        print(f"Testing: {image_name} (expected: {'RISKY' if expected_label == 1 else 'SAFE'})")
        
        try:
            report = model_scanner.scan_image(image_name)
            
            if 'error' in report:
                print(f"❌ Scan failed: {report['error']}")
                continue
            
            predicted_label = 1 if report['is_risky'] else 0
            is_correct = (predicted_label == expected_label)
            
            if is_correct:
                correct += 1
                print(f"✓ CORRECT: Predicted {report['verdict']} (score: {report['risk_score']:.3f})")
            else:
                print(f"✗ INCORRECT: Predicted {report['verdict']} (score: {report['risk_score']:.3f})")
                print(f"  Expected: {'RISKY' if expected_label == 1 else 'SAFE'}")
            
            total += 1
            
            results.append({
                'image': image_name,
                'expected': expected_label,
                'predicted': predicted_label,
                'risk_score': report['risk_score'],
                'correct': is_correct
            })
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Calculate accuracy
    if total > 0:
        accuracy = correct / total
        print(f"\n{'='*70}")
        print(f"TEST RESULTS: {correct}/{total} correct ({accuracy*100:.1f}% accuracy)")
        print(f"{'='*70}")
    
    return results


# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == "__main__":
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "train":
            # Train the model
            csv_path = sys.argv[2] if len(sys.argv) > 2 else 'data/merged_docker_features.csv'
            print("\n🔄 Step 1: Training behavioral scorer...")
            learned_weights = train_behavioral_scorer(csv_path)
    
            # Then train main model
            print("\n🔄 Step 2: Training main model...")
            train_and_analyze_model(csv_path)
        
        elif command == "scan":
            # Scan a single image
            if len(sys.argv) < 3:
                print("Usage: python enhanced_model.py scan <image_name>")
                sys.exit(1)
            
            image_name = sys.argv[2]
            scanner = DockerSecurityScanner()
            report = scanner.scan_image(image_name)
            scanner.print_report(report)
        
        elif command == "test":
            # Test on multiple images
            scanner = DockerSecurityScanner()
            
            # Test images (modify as needed)
            test_images = [
                ('nginx:alpine', 0),           # Safe
                ('python:3.11-slim', 0),       # Safe
                ('ubuntu:14.04', 1),           # Risky (EOL)
                ('node:20-alpine', 0),         # Safe
                ('debian:jessie', 1),          # Risky (EOL)
            ]
            
            results = test_model_on_images(test_images, scanner)
        
        else:
            print(f"Unknown command: {command}")
            print("\nUsage:")
            print("  python enhanced_model.py train [csv_path]")
            print("  python enhanced_model.py scan <image_name>")
            print("  python enhanced_model.py test")
    
    else:
        # Default: Train model and show example scan
        print("Training model...")
        train_and_analyze_model('data/merged_docker_features.csv')
        
        print("\n\n" + "="*70)
        print("EXAMPLE: Scanning a new image")
        print("="*70)
        
        scanner = DockerSecurityScanner()
        report = scanner.scan_image('ubuntu:14.04')
        scanner.print_report(report)
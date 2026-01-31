import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import logging
from datetime import datetime
import pickle
import os
import warnings

warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, model_path='models/anomaly_model.pkl', threshold=0.85):
        self.model_path = model_path
        self.threshold = threshold
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.feature_names = [
            'payload_size',
            'port_number',
            'protocol_id',
            'ttl',
            'flag_count',
            'packet_rate',
            'entropy'
        ]
        self.is_trained = False
        self.training_samples = []
        self.anomaly_scores = []
        self.pending_training_samples = []
        self.min_training_samples = 50
        self.load_model()
    
    def extract_features(self, packet_data):
        features = []
        
        try:
            features.append(float(packet_data.get('payload_size', 0)))
            features.append(float(packet_data.get('dst_port', 0)))
            
            protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'Other': 0}
            protocol = packet_data.get('protocol', 'Other')
            features.append(float(protocol_map.get(protocol, 0)))
            
            features.append(float(packet_data.get('ttl', 64)))
            
            tcp_flags = packet_data.get('tcp_flags', 0)
            flag_count = bin(tcp_flags).count('1') if isinstance(tcp_flags, int) else 0
            features.append(float(flag_count))
            
            packet_rate = 1.0
            features.append(float(packet_rate))
            
            payload = packet_data.get('payload', b'')
            if payload:
                entropy = self._calculate_entropy(payload)
            else:
                entropy = 0.0
            features.append(float(entropy))
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            features = [0.0] * len(self.feature_names)
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_entropy(self, data):
        if isinstance(data, str):
            data = data.encode()
        
        if len(data) == 0:
            return 0.0
        
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        probabilities = byte_counts / len(data)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        
        return entropy
    
    def train(self, packets_data):
        try:
            if not packets_data:
                logger.warning("No packets provided for training")
                return False
            
            X = []
            for packet in packets_data:
                if isinstance(packet, np.ndarray):
                    X.append(packet)
                else:
                    features = self.extract_features(packet)
                    X.append(features[0])
            
            X = np.array(X)
            
            if X.shape[0] < 10:
                logger.warning("Not enough samples for training (minimum 10)")
                return False
            
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            self.model.fit(X_scaled)
            self.is_trained = True
            self.training_samples = X
            self.pending_training_samples = []
            
            logger.info(f"Anomaly detection model trained with {X.shape[0]} samples")
            self.save_model()
            return True
        
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
            return False
    
    def predict(self, packet_data):
        try:
            features = self.extract_features(packet_data)
            
            if not self.is_trained:
                self.pending_training_samples.append(features[0])
                
                if len(self.pending_training_samples) >= self.min_training_samples:
                    self.train(self.pending_training_samples)
                    logger.info(f"Auto-trained model with {len(self.pending_training_samples)} samples")
                
                return {
                    'is_anomalous': False,
                    'anomaly_score': 0.0,
                    'confidence': 0.0,
                    'timestamp': datetime.utcnow().isoformat(),
                    'training_progress': len(self.pending_training_samples)
                }
            
            try:
                features_scaled = self.scaler.transform(features)
            except:
                logger.warning("Scaling failed, using raw features")
                features_scaled = features
            
            anomaly_label = self.model.predict(features_scaled)[0]
            anomaly_score = -self.model.score_samples(features_scaled)[0]
            
            is_anomalous = anomaly_score > self.threshold
            
            result = {
                'is_anomalous': is_anomalous,
                'anomaly_score': float(anomaly_score),
                'threshold': self.threshold,
                'confidence': min(abs(anomaly_score - self.threshold) / self.threshold, 1.0),
                'timestamp': datetime.utcnow().isoformat(),
                'packet_info': {
                    'src_ip': packet_data.get('src_ip'),
                    'dst_ip': packet_data.get('dst_ip'),
                    'src_port': packet_data.get('src_port'),
                    'dst_port': packet_data.get('dst_port'),
                    'protocol': packet_data.get('protocol'),
                    'payload_size': packet_data.get('payload_size')
                }
            }
            
            self.anomaly_scores.append(anomaly_score)
            
            return result
        
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return {
                'is_anomalous': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }
    
    def predict_batch(self, packets_data):
        results = []
        for packet in packets_data:
            result = self.predict(packet)
            results.append(result)
        return results
    
    def update_threshold(self, new_threshold):
        if 0.0 <= new_threshold <= 1.0:
            self.threshold = new_threshold
            logger.info(f"Anomaly threshold updated to {new_threshold}")
        else:
            logger.error("Threshold must be between 0.0 and 1.0")
    
    def save_model(self):
        try:
            os.makedirs(os.path.dirname(self.model_path) or '.', exist_ok=True)
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'threshold': self.threshold,
                'feature_names': self.feature_names
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def load_model(self):
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                self.model = model_data.get('model', self.model)
                self.scaler = model_data.get('scaler', self.scaler)
                self.threshold = model_data.get('threshold', self.threshold)
                self.is_trained = True
                logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}")
    
    def get_statistics(self):
        stats = {
            'is_trained': self.is_trained,
            'threshold': self.threshold,
            'total_predictions': len(self.anomaly_scores),
            'mean_anomaly_score': float(np.mean(self.anomaly_scores)) if self.anomaly_scores else 0.0,
            'std_anomaly_score': float(np.std(self.anomaly_scores)) if self.anomaly_scores else 0.0,
            'min_anomaly_score': float(np.min(self.anomaly_scores)) if self.anomaly_scores else 0.0,
            'max_anomaly_score': float(np.max(self.anomaly_scores)) if self.anomaly_scores else 0.0,
        }
        return stats

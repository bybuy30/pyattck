import sys
import os
from typing import Dict, Any, List

sys.path.append('C:\Users\Bilal\OneDrive\Desktop\Mitre\pyattck\Mitre_mapper')

from mapper import UEBAMitreMapper

class UEBAmitreIntegration:
    """
    Bridge between your UEBA ML models and MITRE mapper
    """
    
    def __init__(self, rules_config: str = None):
        self.mitre_mapper = UEBAMitreMapper(rules_config)
        self.detection_history = []
    
    def process_ml_outputs(self, 
                         som_results: Dict[str, Any] = None,
                         markov_results: Dict[str, Any] = None,
                         raw_logs: Dict[str, Any] = None) -> List[Dict]:
        """
        Unified processor for all UEBA ML outputs
        """
        all_techniques = []
        
        
        if som_results:
            print("Mapping SOM anomalies to MITRE...")
            som_techniques = self.mitre_mapper.map_som_anomaly(som_results)
            all_techniques.extend(som_techniques)
        
        # Process Markov sequences
        if markov_results:
            print("🔍 Mapping Markov sequences to MITRE...")
            markov_techniques = self.mitre_mapper.map_markov_sequence(markov_results)
            all_techniques.extend(markov_techniques)

        if raw_logs and not all_techniques:
            print("🔍 Classifying raw logs with universal mapper...")
            raw_techniques = self.mitre_mapper.classify_raw_logs(raw_logs)
            all_techniques.extend(raw_techniques)

        unique_techniques = {}
        for tech in all_techniques:
            tech_id = tech['id']
            if tech_id not in unique_techniques or tech['confidence'] > unique_techniques[tech_id]['confidence']:
                unique_techniques[tech_id] = tech
        
        sorted_techniques = sorted(unique_techniques.values(), 
                                 key=lambda x: x['confidence'], reverse=True)

        if sorted_techniques:
            self.detection_history.append({
                'timestamp': __import__('datetime').datetime.now().isoformat(),
                'techniques': sorted_techniques,
                'sources': {
                    'som': bool(som_results),
                    'markov': bool(markov_results),
                    'raw_logs': bool(raw_logs)
                }
            })
        
        return sorted_techniques
    
    def generate_ueba_alert(self, techniques: List[Dict], user_info: Dict = None) -> Dict:
        """
        Format MITRE techniques into UEBA alerts
        """
        alert = {
            'alert_id': f"ueba_mitre_{__import__('uuid').uuid4().hex[:8]}",
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'user': user_info or {},
            'risk_score': self._calculate_risk_score(techniques),
            'mitre_techniques': techniques,
            'summary': {
                'total_techniques': len(techniques),
                'high_risk_techniques': len([t for t in techniques if t.get('confidence', 0) > 0.8]),
                'primary_tactics': list(set([tactic for tech in techniques for tactic in tech.get('tactics', [])]))
            }
        }
        
        return alert
    
    def _calculate_risk_score(self, techniques: List[Dict]) -> float:
        """Calculate overall risk score from MITRE techniques"""
        if not techniques:
            return 0.0

        total_confidence = sum(tech.get('confidence', 0) for tech in techniques)
        max_confidence = len(techniques) 
        
        risk_score = (total_confidence / max_confidence) * 100
        return min(risk_score, 100) 
    
    def get_detection_stats(self) -> Dict:
        """Get statistics about detections"""
        total_detections = len(self.detection_history)
        all_techniques = []
        
        for detection in self.detection_history:
            all_techniques.extend(detection['techniques'])
        
        unique_techniques = {tech['id'] for tech in all_techniques}
        
        return {
            'total_alerts': total_detections,
            'unique_techniques_detected': len(unique_techniques),
            'techniques_by_confidence': {
                'high': len([t for t in all_techniques if t.get('confidence', 0) > 0.8]),
                'medium': len([t for t in all_techniques if 0.5 < t.get('confidence', 0) <= 0.8]),
                'low': len([t for t in all_techniques if t.get('confidence', 0) <= 0.5])
            }
        }

def example_ueba_integration():
    """
    Example of how to integrate with your ML models
    """
    ueba_mitre = UEBAmitreIntegration()

    som_output = {
        'user_id': 'user123',
        'unusual_hours': True,
        'data_access_spike': True,
        'deviations': {
            'login_time': 2.8,
            'data_volume': 3.5
        }
    }

    markov_output = {
        'user_id': 'user123', 
        'actions': ['login', 'access_sensitive', 'compress', 'external_upload'],
        'probability': 0.001
    }

    techniques = ueba_mitre.process_ml_outputs(
        som_results=som_output,
        markov_results=markov_output
    )

    alert = ueba_mitre.generate_ueba_alert(
        techniques=techniques,
        user_info={'id': 'user123', 'department': 'Finance'}
    )
    
    print("🚀 UEBA-MITRE Integration Successful!")
    print(f"📊 Risk Score: {alert['risk_score']}")
    print(f"🎯 Techniques Detected: {len(techniques)}")
    
    return alert


if __name__ == "__main__":
    example_ueba_integration()
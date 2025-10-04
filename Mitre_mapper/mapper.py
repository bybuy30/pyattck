import os
import json
import sys
import argparse
from typing import List, Dict, Any
from pathlib import Path

REPORT_FILE_NAME = "mitre_detection_report.json"

MITRE_MAPPING_RULES = {
    "exfil_killchain": {
        "rule_actions": ["access_sensitive_files", "compress_data", "external_upload"],
        "id": "TA0010", 
        "name": "Exfiltration",
        "confidence": 0.8
    },
}

class UEBAMitreMapper:

    def __init__(self):
        self.rules = MITRE_MAPPING_RULES
        pass

    def map_markov_sequence(self, sequence_data: Dict[str, Any]) -> List[Dict]:
        return self._map_markov_generic(sequence_data)

    def _map_markov_generic(self, sequence_data: Dict[str, Any]) -> List[Dict]:
        techniques = []
        
        sequence_str = sequence_data.get('sequence', '')
        sequence = [a.strip() for a in sequence_str.split('->')] if sequence_str else sequence_data.get('actions', [])
        
        score = sequence_data.get('score')
        anomaly_score = 0.0
        
        if score is not None:
            if score == 0.0:
                anomaly_score = 1.0
            elif score > 0.0:
                anomaly_score = min(1.0, score / 4.0) 
        
        if anomaly_score < 0.9:  
            return techniques
        
        if any('login' in action.lower() for action in sequence):
            techniques.append({
                'id': 'T1078',  
                'name': 'Valid Accounts',
                'confidence': min(0.7, anomaly_score),
                'rule_matched': 'markov_suspicious_login_pattern',
                'description': 'Suspicious login activity detected (Markov)',
                'evidence': {'anomaly_score': anomaly_score, 'source': 'markov'}
            })
        
        if len(sequence) >= 3:
            action_counts = {}
            for action in sequence:
                if action.lower() not in ['auth_login', 'auth_logout', 'sys_windows_event']: 
                    action_counts[action.lower()] = action_counts.get(action.lower(), 0) + 1
            
            for action, count in action_counts.items():
                if count >= len(sequence) * 0.6:
                    techniques.append({
                        'id': 'T1041', 
                        'name': 'Exfiltration Over Command and Control Channel',
                        'confidence': min(0.6, anomaly_score),
                        'rule_matched': 'markov_repetitive_action_pattern',
                        'description': 'Highly repetitive action pattern (Markov)',
                        'evidence': {'anomaly_score': anomaly_score, 'source': 'markov'}
                    })
                    break
        
        if anomaly_score == 1.0 and not techniques:
            techniques.append({
                'id': 'TA0009',  
                'name': 'Collection',
                'confidence': 0.55, 
                'rule_matched': 'markov_max_anomaly_score_fallback',
                'description': 'Sequence had maximum anomaly (score 0.0) but matched no specific pattern.',
                'evidence': {'anomaly_score': anomaly_score, 'source': 'markov'}
            })
        
        return techniques

    def map_som_results(self, som_data: Dict[str, Any]) -> List[Dict]:
        techniques = []
        
        attack_score = som_data.get('attack_score', 0)
        benign_score = som_data.get('benign_score', 0)
        total_epochs = som_data.get('total_epochs', 1)
        
        anomaly_metric = attack_score / total_epochs
        
        if anomaly_metric >= 0.3:
            confidence = min(0.9, 0.5 + anomaly_metric)
            techniques.append({
                'id': 'T1070.004', 
                'name': 'Indicator Removal: File Deletion',
                'confidence': confidence,
                'rule_matched': 'som_high_attack_score',
                'description': f'SOM flagged high attack-like behavior ({anomaly_metric:.2f}) over time.',
                'evidence': {'attack_score': attack_score, 'anomaly_metric': anomaly_metric, 'source': 'som'}
            })

        if som_data.get('flagged_epochs', 0) == total_epochs and attack_score == 0:
             techniques.append({
                'id': 'T1090',  
                'name': 'Proxy',
                'confidence': 0.65,
                'rule_matched': 'som_always_flagged_no_attack_score',
                'description': 'User consistently flagged, but low attack score, suggesting an unusual persistent process.',
                'evidence': {'flagged_epochs': som_data['flagged_epochs'], 'source': 'som'}
            })

        if attack_score > 0 and benign_score > 0 and attack_score > benign_score:
            techniques.append({
                'id': 'T1078',  
                'name': 'Valid Accounts',
                'confidence': min(0.8, 0.5 + anomaly_metric),
                'rule_matched': 'som_mixed_high_attack_score',
                'description': 'Mixed normal and attack activity, hinting at legitimate credential misuse.',
                'evidence': {'attack_score': attack_score, 'benign_score': benign_score, 'source': 'som'}
            })

        return techniques

def calculate_risk_score(sequence_data: Dict[str, Any]) -> float:
    score = sequence_data.get('score')
    if score is None:
        return 0.0
    
    if score == 0.0:
        return 1.0
    elif score > 0.0:
        return min(1.0, score / 4.0)
    return 0.0

def load_existing_report(file_path: str) -> List[Dict]:
    try:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, 'r') as f:
                print(f"Loading existing report: {file_path}")
                return json.load(f)
        return []
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load existing report. Starting new report. Error: {e}")
        return []

def process_markov_file(file_path: str, report_list: List[Dict]):
    mapper = UEBAMitreMapper()
    detections_count = 0
    total_sequences = 0
    
    riskiest_sequences_by_user = {}

    print(f"\n--- Analyzing Markov Sequences for Filtering (Source: {file_path}) ---")
    try:
        with open(file_path, 'r') as f:
            for line in f:
                total_sequences += 1
                try:
                    sequence_data = json.loads(line.strip())
                    user_id = sequence_data.get('user_id')
                    
                    if not user_id:
                        continue
                        
                    current_risk = calculate_risk_score(sequence_data)
                    
                    if user_id not in riskiest_sequences_by_user or current_risk > riskiest_sequences_by_user[user_id]['risk_score']:
                        riskiest_sequences_by_user[user_id] = {
                            'risk_score': current_risk,
                            'data': sequence_data,
                            'original_line_num': total_sequences
                        }

                except json.JSONDecodeError:
                    pass
                
    except FileNotFoundError:
        print(f"Error: Markov file not found at path: {file_path}")
        return
        
    riskiest_count = len(riskiest_sequences_by_user)
    print(f"--- Processing {riskiest_count} Riskiest Sequences (1 per user) ---")

    for i, (user_id, item) in enumerate(riskiest_sequences_by_user.items()):
        sequence_data = item['data']
        sequence_id = f"Markov_User_{i+1}_TopRisk" 
        
        techniques = mapper.map_markov_sequence(sequence_data)
        
        if techniques:
            detections_count += 1
            report_entry = {
                'sequence_id': sequence_id,
                'user_id': user_id,
                'raw_data': sequence_data,
                'source': 'markov', 
                'detected_techniques': techniques
            }
            report_list.append(report_entry)

    print(f"   Markov Summary: {detections_count} new detections out of {riskiest_count} unique users processed.")

def process_som_file(file_path: str, report_list: List[Dict]):
    mapper = UEBAMitreMapper()
    detections_count = 0
    total_sequences = 0

    print(f"\n--- Processing SOM Results (Source: {file_path}) ---")

    try:
        with open(file_path, 'r') as f:
            som_results = json.load(f)
            total_sequences = len(som_results)
            
            for i, som_data in enumerate(som_results):
                
                techniques = mapper.map_som_results(som_data)
                
                if techniques:
                    detections_count += 1
                    report_entry = {
                        'sequence_id': f"SOM_User_{i+1}",
                        'user_id': som_data.get('user_id', 'N/A'),
                        'raw_data': som_data,
                        'source': 'som',
                        'detected_techniques': techniques
                    }
                    report_list.append(report_entry)
            
    except FileNotFoundError:
        print(f"Error: SOM file not found at path: {file_path}")
    except json.JSONDecodeError as e:
        print(f"Error decoding SOM JSON: {e}")
        
    print(f"   SOM Summary: {detections_count} new detections out of {total_sequences} users/entries.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Dynamic MITRE ATT&CK Mapper for Markov and SOM outputs.")
    
    parser.add_argument('--markov-file', type=str, help="Path to the Markov JSONL output file.")
    parser.add_argument('--som-file', type=str, help="Path to the SOM JSON output file.")
    parser.add_argument('--test', action='store_true', help="Run internal tests.")

    args = parser.parse_args()
    
    if not args.markov_file and not args.som_file:
        print("Error: Must provide at least one of --markov-file or --som-file.")
        parser.print_help()
        sys.exit(1)

    final_report = load_existing_report(REPORT_FILE_NAME)
    initial_report_size = len(final_report)

    if args.markov_file:
        process_markov_file(args.markov_file, final_report)

    if args.som_file:
        process_som_file(args.som_file, final_report)
        
    if len(final_report) > initial_report_size:
        try:
            with open(REPORT_FILE_NAME, 'w') as out_f:
                json.dump(final_report, out_f, indent=4)
            print("\n" + "="*50)
            print(f"FINAL MERGED REPORT successfully written to {REPORT_FILE_NAME}")
        except Exception as e:
            print(f"\nError writing final merged report to file: {e}")
            
    print("FINAL ANALYSIS SUMMARY:")
    print(f"   Total entries in merged report: {len(final_report)}")
    print("Analysis and Merging Complete!")
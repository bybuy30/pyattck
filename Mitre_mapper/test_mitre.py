import sys
import os
sys.path.append('C:/Users/Bilal/OneDrive/Desktop/Mitre/pyattck')

def test_pyattck():
    try:
        from pyattck import Attck
        
        print("🚀 Initializing MITRE ATT&CK...")
        attack = Attck()
        print("✅ ATT&CK object created successfully!")
        
        # Test basic attributes
        print(f"📊 Enterprise techniques: {len(attack.enterprise.techniques)}")
        print(f"📊 Enterprise tactics: {len(attack.enterprise.tactics)}")
        
        # Try different method names based on pyattck version
        technique = None
        
        # Method 1: Try get_technique (singular)
        if hasattr(attack, 'get_technique'):
            technique = attack.get_technique(technique_id='T1059.003')
            print("✅ Used attack.get_technique()")
        
        # Method 2: Try direct access
        if technique is None:
            for tech in attack.enterprise.techniques:
                if tech.id == 'T1059.003':
                    technique = tech
                    print("✅ Used direct iteration")
                    break
        
        if technique:
            print(f"🔍 Found: {technique.name}")
            print(f"📝 {technique.description[:150]}...")
            print(f"🎯 Tactics: {[t.name for t in technique.tactics]}")
        else:
            print("❌ Could not find technique T1059.003")
            
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_pyattck()
    if success:
        print("\n🎉 PyATT&CK is working! You can now build your MITRE mapper.")
    else:
        print("\n💡 Check the pyattck version and method names.")
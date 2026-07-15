"""Test dependency CVE scanner and crypto auditor on the code_review_agent repo."""
import os
from dotenv import load_dotenv
load_dotenv()

from agent import CodeReviewAgent
from dependency_scanner import scan_dependencies
from github_fetcher import FileResult

REPO_URL = "https://github.com/Bardiyashavandi/code_review_agent"

def test_dependency_scanner(agent):
    print("\n" + "="*60)
    print("  DEPENDENCY CVE SCANNER")
    print("="*60)

    # Fetch requirements.txt directly
    owner, repo = agent._fetcher.parse_repo_url(REPO_URL)
    import base64
    data = agent._fetcher._get(
        f"{agent._fetcher._base_url}/repos/{owner}/{repo}/contents/requirements.txt"
    )
    content = base64.b64decode(data.get("content", "")).decode("utf-8")
    print(f"\nrequirements.txt:\n{content}")

    print("Querying OSV database...")
    result = scan_dependencies(content)

    print(f"\nPackages checked: {result['packages_checked']}")
    print(f"Vulnerable:       {len(result['vulnerable'])}")
    print(f"Clean:            {len(result['clean'])}")
    print(f"No version:       {len(result['no_version'])}")

    if result['vulnerable']:
        print("\nVULNERABLE PACKAGES:")
        for pkg in result['vulnerable']:
            print(f"\n  ⚠️  {pkg['package']}=={pkg['version']} — {pkg['cve_count']} CVE(s)")
            for cve in pkg['cves']:
                print(f"     [{cve['severity']}] {cve['id']}")
                print(f"     {cve['summary']}")
                if cve['fixed_in']:
                    print(f"     Fix: upgrade to {', '.join(cve['fixed_in'])}")
    else:
        print("\n✓ No known CVEs found in pinned dependencies.")

    if result['no_version']:
        print(f"\n⚠️  Unpinned (can't check): {', '.join(result['no_version'])}")


def test_crypto_auditor(agent):
    print("\n" + "="*60)
    print("  CRYPTO AUDITOR")
    print("="*60)

    # Create a file with intentional crypto weaknesses for testing
    weak_crypto_code = '''
import hashlib
import random
import base64
from Crypto.Cipher import AES

# BAD: MD5 for password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# BAD: random for token generation (not cryptographically secure)
def generate_token():
    return str(random.randint(100000, 999999))

# BAD: base64 as "encryption"
def encrypt_data(data):
    return base64.b64encode(data.encode()).decode()

# BAD: ECB mode + hardcoded key
def encrypt_message(message):
    key = b"hardcoded_key123"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)

# BAD: SHA1 for integrity
def verify_file(content):
    return hashlib.sha1(content).hexdigest()
'''

    test_file = FileResult(
        path="test_weak_crypto.py",
        content=weak_crypto_code,
        sha="", size=len(weak_crypto_code), url=""
    )

    print("\nRunning crypto audit on intentionally weak code...")
    result = agent.generate_crypto_audit([test_file])

    if result.get("parse_error"):
        print("Raw:", result.get("raw", "")[:500])
        return

    findings = result.get("findings", [])
    print(f"\nFindings: {len(findings)}")
    for i, f in enumerate(findings, 1):
        print(f"\n  #{i} [{f.get('severity','?')}] {f.get('pattern','')}")
        print(f"  File: {f.get('path','')}:{f.get('line','')}")
        print(f"  Code: {f.get('current_code','')}")
        print(f"  Why dangerous: {f.get('why_dangerous','')}")
        print(f"  Fix: {f.get('correct_alternative','')}")
        print(f"  Attacker effort: {f.get('attacker_effort','')}")

    print(f"\nSummary: {result.get('summary','')}")


if __name__ == "__main__":
    agent = CodeReviewAgent(
        github_token=os.environ["GITHUB_TOKEN"],
        gemini_api_key=os.environ["GOOGLE_API_KEY"],
    )
    test_dependency_scanner(agent)
    test_crypto_auditor(agent)

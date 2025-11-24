#!/usr/bin/env python3
"""
Phishing Link Scanner
Combines static analysis, VirusTotal reputation check, and LLM semantic analysis
to detect malicious URLs.
"""

import re
import time
import sys
from typing import Dict, Tuple, Optional
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
import os
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Load environment variables
load_dotenv()

# Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()

# VirusTotal API endpoints
VT_API_BASE = "https://www.virustotal.com/api/v3"


class PhishingScanner:
    """Main phishing detection scanner class"""
    
    def __init__(self):
        """Initialize scanner with API clients"""
        self._validate_config()
        self._init_llm_client()
    
    def _validate_config(self):
        """Validate required API keys are present"""
        if not VIRUSTOTAL_API_KEY:
            raise ValueError("❌ VIRUSTOTAL_API_KEY not found in .env file")
        
        if LLM_PROVIDER == "openai" and not OPENAI_API_KEY:
            raise ValueError("❌ OPENAI_API_KEY not found in .env file")
        elif LLM_PROVIDER == "gemini" and not GOOGLE_API_KEY:
            raise ValueError("❌ GOOGLE_API_KEY not found in .env file")
    
    def _init_llm_client(self):
        """Initialize LLM client based on provider"""
        if LLM_PROVIDER == "openai":
            from openai import OpenAI
            self.llm_client = OpenAI(api_key=OPENAI_API_KEY)
            self.llm_model = "gpt-4"
        elif LLM_PROVIDER == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=GOOGLE_API_KEY)
            self.llm_client = genai.GenerativeModel('gemini-pro')
            self.llm_model = "gemini-pro"
        else:
            raise ValueError(f"❌ Unsupported LLM provider: {LLM_PROVIDER}")
    
    # ========== STATIC ANALYSIS ==========
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate URL structure using regex
        Returns: (is_valid, error_message)
        """
        # Basic URL regex pattern
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            return False, "Invalid URL format"
        
        return True, ""
    
    def static_analysis(self, url: str) -> Dict:
        """
        Perform static analysis on URL structure
        Returns: Dictionary with risk indicators
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        suspicious_patterns = {
            "has_ip_address": bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
            "excessive_length": len(url) > 75,
            "excessive_subdomains": domain.count('.') > 3,
            "has_suspicious_tld": any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']),
            "uses_http": parsed.scheme == 'http',
            "has_at_symbol": '@' in url,
            "suspicious_keywords": [],
            "typosquatting_indicators": []
        }
        
        # Check for suspicious keywords
        phishing_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'confirm', 'banking', 'paypal', 'amazon', 'apple', 'microsoft',
            'password', 'suspend', 'locked', 'unusual', 'click'
        ]
        
        for keyword in phishing_keywords:
            if keyword in url.lower():
                suspicious_patterns["suspicious_keywords"].append(keyword)
        
        # Check for typosquatting patterns (common brand misspellings)
        typosquatting_patterns = [
            r'amaz[o0]n', r'g[o0]{2}gle', r'faceb[o0]{2}k', r'micr[o0]s[o0]ft',
            r'paypa[l1]', r'app[l1]e', r'netf[l1]ix', r'tw[i1]tter'
        ]
        
        for pattern in typosquatting_patterns:
            if re.search(pattern, domain.lower()):
                suspicious_patterns["typosquatting_indicators"].append(pattern)
        
        # Calculate risk score
        risk_score = sum([
            suspicious_patterns["has_ip_address"] * 30,
            suspicious_patterns["excessive_length"] * 15,
            suspicious_patterns["excessive_subdomains"] * 20,
            suspicious_patterns["has_suspicious_tld"] * 25,
            suspicious_patterns["uses_http"] * 10,
            suspicious_patterns["has_at_symbol"] * 20,
            len(suspicious_patterns["suspicious_keywords"]) * 5,
            len(suspicious_patterns["typosquatting_indicators"]) * 30
        ])
        
        suspicious_patterns["risk_score"] = min(risk_score, 100)
        
        return suspicious_patterns
    
    # ========== VIRUSTOTAL REPUTATION CHECK ==========
    
    def check_virustotal(self, url: str) -> Dict:
        """
        Check URL reputation using VirusTotal API v3
        Returns: Dictionary with VT analysis results
        """
        print(f"{Fore.BLUE}[VirusTotal] Submitting URL for analysis...{Style.RESET_ALL}")
        
        try:
            # Step 1: Submit URL for scanning
            headers = {
                "accept": "application/json",
                "x-apikey": VIRUSTOTAL_API_KEY,
                "content-type": "application/x-www-form-urlencoded"
            }
            
            submit_response = requests.post(
                f"{VT_API_BASE}/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            
            if submit_response.status_code != 200:
                return {
                    "error": f"VT API error: {submit_response.status_code}",
                    "available": False
                }
            
            analysis_id = submit_response.json()["data"]["id"]
            
            # Step 2: Wait for analysis to complete (with timeout)
            print(f"{Fore.BLUE}[VirusTotal] Waiting for analysis (ID: {analysis_id[:20]}...)...{Style.RESET_ALL}")
            time.sleep(15)  # VirusTotal typically takes 10-20 seconds
            
            # Step 3: Retrieve analysis results
            analysis_response = requests.get(
                f"{VT_API_BASE}/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            
            if analysis_response.status_code != 200:
                return {
                    "error": f"VT Analysis retrieval error: {analysis_response.status_code}",
                    "available": False
                }
            
            data = analysis_response.json()["data"]["attributes"]
            stats = data.get("stats", {})
            
            return {
                "available": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "status": data.get("status", "unknown"),
                "total_engines": sum(stats.values()) if stats else 0
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "error": f"Network error: {str(e)}",
                "available": False
            }
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "available": False
            }
    
    # ========== LLM SEMANTIC ANALYSIS ==========
    
    def llm_analysis(self, url: str, static_results: Dict) -> Dict:
        """
        Use LLM to perform semantic analysis of URL
        Returns: Dictionary with LLM assessment
        """
        print(f"{Fore.BLUE}[LLM] Analyzing URL semantics with {self.llm_model}...{Style.RESET_ALL}")
        
        # Construct prompt for LLM
        prompt = f"""You are a cybersecurity expert specializing in phishing detection. Analyze the following URL for potential phishing indicators.

URL: {url}

Static Analysis Results:
- Risk Score: {static_results['risk_score']}/100
- Has IP Address: {static_results['has_ip_address']}
- Excessive Length: {static_results['excessive_length']}
- Suspicious Keywords: {', '.join(static_results['suspicious_keywords']) if static_results['suspicious_keywords'] else 'None'}
- Typosquatting Indicators: {', '.join(static_results['typosquatting_indicators']) if static_results['typosquatting_indicators'] else 'None'}

Analyze this URL and provide:
1. Is this likely a phishing URL? (YES/NO)
2. Confidence level (0-100%)
3. Key red flags (if any)
4. Reasoning for your assessment

Format your response as:
VERDICT: [YES/NO]
CONFIDENCE: [0-100]%
RED_FLAGS: [List of red flags, or "None"]
REASONING: [Your detailed reasoning]
"""
        
        try:
            if LLM_PROVIDER == "openai":
                response = self.llm_client.chat.completions.create(
                    model=self.llm_model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=500
                )
                llm_response = response.choices[0].message.content
            
            elif LLM_PROVIDER == "gemini":
                response = self.llm_client.generate_content(prompt)
                llm_response = response.text
            
            # Parse LLM response
            verdict_match = re.search(r'VERDICT:\s*(YES|NO)', llm_response, re.IGNORECASE)
            confidence_match = re.search(r'CONFIDENCE:\s*(\d+)', llm_response)
            red_flags_match = re.search(r'RED_FLAGS:\s*(.+?)(?=REASONING:|$)', llm_response, re.DOTALL)
            reasoning_match = re.search(r'REASONING:\s*(.+)', llm_response, re.DOTALL)
            
            return {
                "available": True,
                "is_phishing": verdict_match.group(1).upper() == "YES" if verdict_match else None,
                "confidence": int(confidence_match.group(1)) if confidence_match else 0,
                "red_flags": red_flags_match.group(1).strip() if red_flags_match else "None",
                "reasoning": reasoning_match.group(1).strip() if reasoning_match else llm_response,
                "raw_response": llm_response
            }
            
        except Exception as e:
            return {
                "error": f"LLM analysis failed: {str(e)}",
                "available": False
            }
    
    # ========== MAIN SCAN ORCHESTRATION ==========
    
    def scan(self, url: str) -> Dict:
        """
        Orchestrate complete phishing scan
        Returns: Comprehensive scan report
        """
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔍 PHISHING LINK SCANNER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        # Step 1: Validate URL
        print(f"{Fore.YELLOW}[1/4] Validating URL structure...{Style.RESET_ALL}")
        is_valid, error = self.validate_url(url)
        if not is_valid:
            print(f"{Fore.RED}❌ {error}{Style.RESET_ALL}")
            return {"error": error}
        print(f"{Fore.GREEN}✓ URL structure valid{Style.RESET_ALL}\n")
        
        # Step 2: Static Analysis
        print(f"{Fore.YELLOW}[2/4] Performing static analysis...{Style.RESET_ALL}")
        static_results = self.static_analysis(url)
        print(f"{Fore.GREEN}✓ Static analysis complete (Risk Score: {static_results['risk_score']}/100){Style.RESET_ALL}\n")
        
        # Step 3: VirusTotal Check
        print(f"{Fore.YELLOW}[3/4] Checking VirusTotal reputation...{Style.RESET_ALL}")
        vt_results = self.check_virustotal(url)
        if vt_results.get("available"):
            print(f"{Fore.GREEN}✓ VirusTotal analysis complete{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.YELLOW}⚠ VirusTotal check failed: {vt_results.get('error', 'Unknown error')}{Style.RESET_ALL}\n")
        
        # Step 4: LLM Analysis
        print(f"{Fore.YELLOW}[4/4] Running LLM semantic analysis...{Style.RESET_ALL}")
        llm_results = self.llm_analysis(url, static_results)
        if llm_results.get("available"):
            print(f"{Fore.GREEN}✓ LLM analysis complete{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.YELLOW}⚠ LLM analysis failed: {llm_results.get('error', 'Unknown error')}{Style.RESET_ALL}\n")
        
        # Compile final report
        return {
            "url": url,
            "static_analysis": static_results,
            "virustotal": vt_results,
            "llm_analysis": llm_results
        }
    
    def print_report(self, report: Dict):
        """Print formatted scan report"""
        if "error" in report:
            print(f"{Fore.RED}❌ Scan failed: {report['error']}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 SCAN REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}URL: {report['url']}{Style.RESET_ALL}\n")
        
        # Static Analysis Results
        static = report["static_analysis"]
        print(f"{Fore.YELLOW}▶ STATIC ANALYSIS{Style.RESET_ALL}")
        print(f"  Risk Score: {self._colored_score(static['risk_score'])}/100")
        print(f"  IP Address in URL: {'❌ Yes' if static['has_ip_address'] else '✓ No'}")
        print(f"  Excessive Length: {'⚠ Yes' if static['excessive_length'] else '✓ No'}")
        print(f"  Suspicious TLD: {'⚠ Yes' if static['has_suspicious_tld'] else '✓ No'}")
        print(f"  Uses HTTP (not HTTPS): {'⚠ Yes' if static['uses_http'] else '✓ No'}")
        
        if static['suspicious_keywords']:
            print(f"  Suspicious Keywords: {Fore.RED}{', '.join(static['suspicious_keywords'])}{Style.RESET_ALL}")
        
        if static['typosquatting_indicators']:
            print(f"  Typosquatting Patterns: {Fore.RED}{', '.join(static['typosquatting_indicators'])}{Style.RESET_ALL}")
        
        print()
        
        # VirusTotal Results
        vt = report["virustotal"]
        print(f"{Fore.YELLOW}▶ VIRUSTOTAL REPUTATION{Style.RESET_ALL}")
        if vt.get("available"):
            print(f"  Status: {vt['status']}")
            print(f"  Malicious Detections: {Fore.RED if vt['malicious'] > 0 else Fore.GREEN}{vt['malicious']}/{vt['total_engines']}{Style.RESET_ALL}")
            print(f"  Suspicious Detections: {Fore.YELLOW if vt['suspicious'] > 0 else Fore.GREEN}{vt['suspicious']}/{vt['total_engines']}{Style.RESET_ALL}")
            print(f"  Harmless: {Fore.GREEN}{vt['harmless']}/{vt['total_engines']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}⚠ Not available: {vt.get('error', 'Unknown error')}{Style.RESET_ALL}")
        
        print()
        
        # LLM Analysis Results
        llm = report["llm_analysis"]
        print(f"{Fore.YELLOW}▶ LLM SEMANTIC ANALYSIS ({self.llm_model.upper()}){Style.RESET_ALL}")
        if llm.get("available"):
            verdict_color = Fore.RED if llm.get("is_phishing") else Fore.GREEN
            print(f"  Verdict: {verdict_color}{'PHISHING' if llm.get('is_phishing') else 'LEGITIMATE'}{Style.RESET_ALL}")
            print(f"  Confidence: {llm['confidence']}%")
            print(f"  Red Flags: {llm['red_flags']}")
            print(f"  Reasoning: {llm['reasoning'][:200]}...")
        else:
            print(f"  {Fore.YELLOW}⚠ Not available: {llm.get('error', 'Unknown error')}{Style.RESET_ALL}")
        
        print()
        
        # Final Verdict
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎯 FINAL VERDICT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        final_verdict = self._calculate_final_verdict(report)
        verdict_color = Fore.RED if final_verdict["is_malicious"] else Fore.GREEN
        
        print(f"  Status: {verdict_color}{final_verdict['status']}{Style.RESET_ALL}")
        print(f"  Overall Risk: {self._colored_score(final_verdict['risk_level'])}/100")
        print(f"  Recommendation: {final_verdict['recommendation']}\n")
    
    def _colored_score(self, score: int) -> str:
        """Return colored score based on risk level"""
        if score >= 70:
            return f"{Fore.RED}{score}{Style.RESET_ALL}"
        elif score >= 40:
            return f"{Fore.YELLOW}{score}{Style.RESET_ALL}"
        else:
            return f"{Fore.GREEN}{score}{Style.RESET_ALL}"
    
    def _calculate_final_verdict(self, report: Dict) -> Dict:
        """Calculate final verdict based on all analysis results"""
        static = report["static_analysis"]
        vt = report["virustotal"]
        llm = report["llm_analysis"]
        
        # Weighted risk calculation
        risk_factors = []
        
        # Static analysis (weight: 30%)
        risk_factors.append(static["risk_score"] * 0.3)
        
        # VirusTotal (weight: 40%)
        if vt.get("available") and vt["total_engines"] > 0:
            vt_risk = ((vt["malicious"] + vt["suspicious"] * 0.5) / vt["total_engines"]) * 100
            risk_factors.append(vt_risk * 0.4)
        
        # LLM analysis (weight: 30%)
        if llm.get("available") and llm.get("is_phishing") is not None:
            llm_risk = llm["confidence"] if llm["is_phishing"] else (100 - llm["confidence"])
            risk_factors.append(llm_risk * 0.3)
        
        overall_risk = sum(risk_factors) if risk_factors else static["risk_score"]
        
        # Determine verdict
        if overall_risk >= 70:
            status = "🚨 MALICIOUS - HIGH RISK"
            is_malicious = True
            recommendation = "DO NOT VISIT. This URL shows strong phishing indicators."
        elif overall_risk >= 40:
            status = "⚠️  SUSPICIOUS - MEDIUM RISK"
            is_malicious = True
            recommendation = "Exercise extreme caution. Verify legitimacy before visiting."
        else:
            status = "✅ APPEARS SAFE - LOW RISK"
            is_malicious = False
            recommendation = "URL appears legitimate, but always verify sender authenticity."
        
        return {
            "is_malicious": is_malicious,
            "risk_level": int(overall_risk),
            "status": status,
            "recommendation": recommendation
        }


def main():
    """Main entry point"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🛡️  PHISHING LINK SCANNER v1.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    # Check if URL provided as argument
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        # Interactive mode
        print("Enter URL to scan (or 'quit' to exit):")
        url = input(f"{Fore.GREEN}> {Style.RESET_ALL}").strip()
        
        if url.lower() == 'quit':
            print("Goodbye!")
            return
    
    if not url:
        print(f"{Fore.RED}❌ No URL provided{Style.RESET_ALL}")
        return
    
    try:
        scanner = PhishingScanner()
        report = scanner.scan(url)
        scanner.print_report(report)
    except ValueError as e:
        print(f"{Fore.RED}❌ Configuration Error: {e}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Please ensure your .env file is configured correctly.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}See .env.example for template.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Unexpected Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

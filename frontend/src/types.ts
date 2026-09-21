export interface User {
  id: string;
  email: string;
  role: "user" | "admin";
  is_active: boolean;
  created_at: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface EngineHealth {
  status: string;
  api_active: boolean;
  engine_mode: string;
  gemini_configured: boolean;
  virustotal_configured: boolean;
  urlhaus_configured: boolean;
  version: string;
  message: string;
}

export interface PhishingSignal {
  id: string;
  severity: "low" | "medium" | "high";
  title: string;
  description: string;
}

export interface AnalysisRequest {
  input_type: "url" | "email_text" | "email_header";
  content: string;
  api_key?: string;
}

export interface VirusTotalData {
  malicious_count: number;
  suspicious_count: number;
  reputation_score: number;
  vendors: string[];
  vt_scan_id: string;
  last_scan_date: string;
  categories: Record<string, string>;
}

export interface URLhausData {
  in_database: boolean;
  threat_type: string | null;
  date_added: string;
  malware_families: string[];
}

export interface AnalysisResponse {
  input_type: "url" | "email_text" | "email_header";
  risk_score: number;
  status: "safe" | "warning" | "danger";
  phishing_signals: PhishingSignal[];
  ai_explanation: string;
  details: {
    domain?: string;
    suffix?: string;
    subdomain?: string;
    host?: string;
    is_https?: boolean;
    length?: number;
    is_ip_address?: boolean;
    links_found?: string[];
    links_analysis?: {
      url: string;
      risk_score: number;
      signals_count: number;
    }[];
    keyword_flags_count?: number;
    from?: string;
    return_path?: string;
    subject?: string;
    spf_status?: string;
    dkim_status?: string;
    sender_mismatch?: boolean;
    error?: string;
    [key: string]: any;
  };
  // VirusTotal fields
  virustotal_findings?: VirusTotalData;
  vt_status?: string;
  vt_malicious_vendors?: number;
  vt_reputation?: number;
  // URLhaus fields
  urlhaus_findings?: URLhausData;
  urlhaus_status?: string;
  urlhaus_threat_type?: string;
  urlhaus_in_database?: boolean;
}

export interface ScanHistoryItem {
  id: string;
  user_id?: string | null;
  timestamp: string;
  input_type: "url" | "email_text" | "email_header";
  content: string;
  risk_score: number;
  status: "safe" | "warning" | "danger";
  response?: AnalysisResponse;
}

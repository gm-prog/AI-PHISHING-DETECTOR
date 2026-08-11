export interface MockSample {
  id: string;
  name: string;
  type: "url" | "email_text" | "email_header";
  description: string;
  content: string;
}

export const MOCK_SAMPLES: MockSample[] = [
  {
    id: "legit-url",
    name: "Legitimate URL (GitHub)",
    type: "url",
    description: "A standard official URL with SSL encryption",
    content: "https://github.com/features/security"
  },
  {
    id: "phish-url-typo",
    name: "Typosquatted Phishing URL",
    type: "url",
    description: "Spoofing PayPal using '1' instead of 'l' and a cheap TLD (.xyz)",
    content: "http://secure-paypa1-verification.xyz/signin/index.php?user=temp"
  },
  {
    id: "phish-url-subdomain",
    name: "Deep Subdomain Spoofing URL",
    type: "url",
    description: "Nesting brand name in subdomains on a compromised site",
    content: "https://chase.com.auth.security-update.chasebank.verification-alert.net/login"
  },
  {
    id: "legit-email",
    name: "Legitimate Email Text",
    type: "email_text",
    description: "Standard newsletter email body with typical structure",
    content: "Hi team, this is a reminder that our monthly engineering synchronization is scheduled for tomorrow at 10 AM. We will review our Q3 security goals and pipeline features. You can find the slide deck attached in our shared workspace. Let me know if you have any questions."
  },
  {
    id: "phish-email-urgency",
    name: "Urgent Phishing Email Text",
    type: "email_text",
    description: "Standard social-engineering tactics including fear, urgency, and links",
    content: "DEAR CUSTOMER, URGENT ACTION REQUIRED!\n\nWe detected an unauthorized transaction of $499.00 on your account. For your security, your account has been temporarily suspended.\n\nYou must verify your pin and credentials within 24 hours to lift the suspension, otherwise a permanent lock will apply.\n\nClick the link below immediately to update your billing profile:\nhttp://paypa1-verification-billing.info/restore-account"
  },
  {
    id: "phish-headers",
    name: "Forged Email Headers (SPF Fail)",
    type: "email_header",
    description: "Headers showing From/Return-Path mismatch and SPF authentication failure",
    content: `From: Chase Security <security@chase.com>
To: target-user@gmail.com
Subject: ALERT: Suspicious Activity Detected - Action Required
Return-Path: <malicious-relayer@cheap-bulletproof-host.ru>
Received-SPF: fail (google.com: domain of malicious-relayer@cheap-bulletproof-host.ru does not designate chase.com as permitted sender)
Authentication-Results: mx.google.com; spf=fail (google.com: domain of malicious-relayer@cheap-bulletproof-host.ru does not designate chase.com as permitted sender); dkim=fail`
  },
  {
    id: "legit-headers",
    name: "Validated Email Headers (SPF/DKIM Pass)",
    type: "email_header",
    description: "Legitimate mail headers with matching sender domains and passing SPF/DKIM",
    content: `From: GitHub Security <noreply@github.com>
To: software-engineer@workplace.com
Subject: [GitHub] Security Alert: Personal Access Token Expiring
Return-Path: <noreply@github.com>
Received-SPF: pass (google.com: domain of noreply@github.com designates 192.30.252.203 as permitted sender)
Authentication-Results: mx.google.com; spf=pass (google.com: domain of noreply@github.com designates 192.30.252.203 as permitted sender); dkim=pass (signature verified)`
  }
];

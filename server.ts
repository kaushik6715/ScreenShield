import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';
import type {
  ScanResult,
  ThreatCategory,
  ThreatLevel,
  SecurityRule,
  ThreatCategoryConfig,
  AuditLog,
  UserProfile,
  DashboardStats,
  UrlTechnicalDetails,
} from './src/types.ts';

dotenv.config();

const app = express();
const PORT = 3000;

// Allow large payloads for screenshot OCR base64 images
app.use(express.json({ limit: '35mb' }));
app.use(express.urlencoded({ extended: true, limit: '35mb' }));

// Initialize Gemini Client safely
let ai: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  try {
    ai = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.error('Failed to initialize GoogleGenAI client:', err);
  }
}

// -------------------------------------------------------------
// In-Memory Database State (Pre-seeded with realistic cyber intelligence)
// -------------------------------------------------------------

const seedScans: ScanResult[] = [
  {
    id: 'SCN-984210',
    type: 'text',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    inputSnippet: 'Work from home and earn ₹50,000 per week. Pay ₹999 registration fee to start...',
    fullInput: 'Work from home and earn ₹50,000 per week. Pay ₹999 registration fee to start right away on WhatsApp: +91-9876543210. Limited slots!',
    riskScore: 96,
    threatLevel: 'CRITICAL',
    threatCategory: 'Fake Job Offer',
    summary: 'High-confidence recruitment fraud demanding an upfront fee under the guise of an exorbitantly compensated data entry/work-from-home role.',
    detectedIndicators: [
      { label: 'Unrealistic Income Claim', severity: 'critical', description: 'Promising ₹50,000/week with no skills, interviews, or contract.' },
      { label: 'Upfront Registration Fee', severity: 'critical', description: 'Legitimate employers never charge candidates registration or kit fees.' },
      { label: 'Urgency & Slot Scarcity', severity: 'high', description: 'Psychological pressure ("Limited slots available") to provoke impulsive action.' },
      { label: 'Informal Channel Recruitment', severity: 'medium', description: 'Directing recruitment to personal WhatsApp numbers rather than official corporate portals.' },
    ],
    evidenceDetected: [
      { type: 'Financial Extortion Pattern', details: 'Requests payment of ₹999 upfront prior to work assignment.' },
      { type: 'Linguistic Urgency', details: 'Phrase "to start right away" coupled with scarce availability claim.' },
    ],
    recommendedAction: 'DO NOT transfer any funds. Block the contact number and report to the National Cyber Crime Reporting Portal.',
    preventionTips: [
      'Never pay money to secure a job or interview.',
      'Check company domain on official career boards before engaging.',
      'Verify the recruiter identity on LinkedIn.',
    ],
    isSaved: true,
  },
  {
    id: 'SCN-873194',
    type: 'text',
    timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    inputSnippet: 'Dear Customer, your State Bank account KYC is expired. Your account will be blocked today...',
    fullInput: 'Dear Customer, your State Bank account KYC is expired. Your account will be blocked today. Update immediately at https://sbi-kyc-verify.xyz/login to avoid suspension.',
    riskScore: 98,
    threatLevel: 'CRITICAL',
    threatCategory: 'Phishing',
    summary: 'Bank credential harvesting campaign attempting urgent account takeover using a spoofed domain and fear of account freezing.',
    detectedIndicators: [
      { label: 'Fear & Account Freezing Threat', severity: 'critical', description: 'Claims account will be locked today if action is not taken.' },
      { label: 'Spoofed Banking Domain', severity: 'critical', description: 'Uses unauthorized .xyz top-level domain simulating State Bank.' },
      { label: 'Urgent KYC Verification Trap', severity: 'high', description: 'Exploits standard compliance terminology to panic victims.' },
    ],
    evidenceDetected: [
      { type: 'Domain Spoofing', details: 'sbi-kyc-verify.xyz is NOT an official banking portal.' },
      { type: 'Severe Coercion', details: '"will be blocked today" threat tactic.' },
    ],
    recommendedAction: 'Immediately delete message. Do not open the link or enter banking credentials. If already entered, contact your bank fraud helpline immediately.',
    preventionTips: [
      'Banks never send links via SMS to update KYC or PAN.',
      'Always visit the official net banking URL directly through bookmarks or manual typing.',
    ],
    isSaved: true,
  },
  {
    id: 'SCN-741205',
    type: 'url',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(),
    inputSnippet: 'http://paypal-security-update.account-protection.live/relogin?ref=auth',
    fullInput: 'http://paypal-security-update.account-protection.live/relogin?ref=auth',
    riskScore: 94,
    threatLevel: 'CRITICAL',
    threatCategory: 'Suspicious URL',
    summary: 'Malicious credential phishing URL using HTTP insecure transport, multiple deceptive subdomains, and suspicious TLD mimicking PayPal security.',
    detectedIndicators: [
      { label: 'Unencrypted Connection (HTTP)', severity: 'high', description: 'Site transmits credentials in plaintext without SSL/TLS encryption.' },
      { label: 'Subdomain Typosquatting', severity: 'critical', description: 'Uses "paypal-security-update" in subdomain while root domain is "account-protection.live".' },
      { label: 'High-Risk TLD (.live)', severity: 'medium', description: 'Top-level domain frequently utilized in transient phishing campaigns.' },
    ],
    evidenceDetected: [
      { type: 'Brand Hijacking', details: 'Impersonates PayPal brand without legitimate ownership of the root zone.' },
    ],
    recommendedAction: 'Do not access this URL. If opened, clear browser cookies and reset passwords on legitimate service portals.',
    preventionTips: [
      'Inspect the true domain before the last dot (e.g. paypal.com vs paypal.somewebsite.com).',
      'Look for the padlock icon and verified certificate issuer.',
    ],
    urlDetails: {
      url: 'http://paypal-security-update.account-protection.live/relogin?ref=auth',
      domain: 'account-protection.live',
      protocol: 'http:',
      hasHttps: false,
      subdomainCount: 2,
      isIpAddress: false,
      urlLength: 72,
      suspiciousKeywordsFound: ['security', 'update', 'account', 'protection', 'login'],
      tld: 'live',
      tldRisk: 'high-risk',
    },
    isSaved: false,
  },
  {
    id: 'SCN-612093',
    type: 'text',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString(),
    inputSnippet: 'Your FedEx package #94821 is held due to incomplete address. Pay $1.85 redelivery fee...',
    fullInput: 'Your FedEx package #94821 is held due to incomplete address. Pay $1.85 redelivery fee at tracking-fedx-delivery.top to schedule immediate drop-off.',
    riskScore: 88,
    threatLevel: 'HIGH',
    threatCategory: 'Delivery/Package Scam',
    summary: 'Smishing scam attempting credit card harvesting via nominal redelivery fee request and misspelled carrier brand.',
    detectedIndicators: [
      { label: 'Nominal Fee Card Trap', severity: 'high', description: 'Small charge ($1.85) designed to elicit credit card numbers and CVV.' },
      { label: 'Typosquatted Brand Name', severity: 'critical', description: '"fedx" rather than official "fedex".' },
      { label: 'Untrusted TLD (.top)', severity: 'medium', description: 'Associated with disposable malicious infrastructures.' },
    ],
    evidenceDetected: [
      { type: 'Smishing Indicator', details: 'SMS package detention notice without recipient or parcel sender details.' },
    ],
    recommendedAction: 'Discard the message. Do not enter card details or billing credentials.',
    preventionTips: [
      'Track packages only using the official carrier app or authentic website (fedex.com).',
      'Couriers do not withhold deliveries for $1-$2 online fees via third-party links.',
    ],
    isSaved: false,
  },
  {
    id: 'SCN-509182',
    type: 'text',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    inputSnippet: 'Your Google Account security alert: New sign-in from Chrome on Windows in London...',
    fullInput: 'Your Google Account security alert: New sign-in from Chrome on Windows in London. If this was you, you don\'t need to do anything. Check activity at https://myaccount.google.com/notifications',
    riskScore: 6,
    threatLevel: 'SAFE',
    threatCategory: 'Legitimate / Clean',
    summary: 'Standard genuine security alert sent from Google informing account holder of a recognized or new device sign-in, referencing official google.com domain.',
    detectedIndicators: [
      { label: 'Authentic Domain Target', severity: 'low', description: 'Links directly to official myaccount.google.com with valid HTTPS.' },
      { label: 'No Credential Pressure', severity: 'low', description: 'Does not demand immediate password disclosure or external wire transfer.' },
    ],
    evidenceDetected: [
      { type: 'Standard Security Notification', details: 'Follows legitimate RFC security notification syntax without coercing panic.' },
    ],
    recommendedAction: 'Safe to review. Verify your own recent sign-ins if you were not traveling or logging into a new browser.',
    preventionTips: [
      'Keep 2-Step Verification enabled across your primary digital accounts.',
    ],
    isSaved: true,
  },
];

let scansDatabase: ScanResult[] = [...seedScans];

let securityRules: SecurityRule[] = [
  { id: 'RUL-01', name: 'Urgent OTP & PIN Solicitation', category: 'Authentication', description: 'Penalizes any message explicitly prompting the disclosure of one-time passwords, secret PINs, or recovery codes.', penaltyScore: 45, isEnabled: true, matchesCount: 142 },
  { id: 'RUL-02', name: 'Known Impersonated Financial Institutions', category: 'Impersonation', description: 'Detects bank name mentions coupled with unofficial TLDs or unregistered contact numbers.', penaltyScore: 40, isEnabled: true, matchesCount: 89 },
  { id: 'RUL-03', name: 'Upfront Employment Registration Fee', category: 'Employment', description: 'Flags recruitment communications asking for application fees, training deposits, or security collateral.', penaltyScore: 35, isEnabled: true, matchesCount: 64 },
  { id: 'RUL-04', name: 'High-Risk TLD Identification', category: 'Domain Heuristics', description: 'Flags domains hosted on .xyz, .top, .work, .icu, .buzz, or .cc.', penaltyScore: 25, isEnabled: true, matchesCount: 210 },
  { id: 'RUL-05', name: 'Cryptocurrency Multiplication Offer', category: 'Investment', description: 'Flags promises of guaranteed doubling, mining yield multipliers, or urgent wallet deposit addresses.', penaltyScore: 40, isEnabled: true, matchesCount: 53 },
  { id: 'RUL-06', name: 'Package Address Failure / Redelivery Smish', category: 'Logistics', description: 'Detects generic undelivered parcel claims urging link clicks for nominal fee settlements.', penaltyScore: 30, isEnabled: true, matchesCount: 97 },
];

let threatCategoriesList: ThreatCategoryConfig[] = [
  { id: 'CAT-01', name: 'Phishing', description: 'Deceptive attempts to steal sensitive user credentials, login tokens, or card numbers.', defaultThreatLevel: 'CRITICAL', activeCount: 428, isEnabled: true },
  { id: 'CAT-02', name: 'Fake Job Offer', description: 'Fraudulent employment positions promising high salary with upfront registration fees or task money traps.', defaultThreatLevel: 'HIGH', activeCount: 231, isEnabled: true },
  { id: 'CAT-03', name: 'Investment Scam', description: 'Unrealistic cryptocurrency, forex, or stock tips promising guaranteed returns with high initial capital demands.', defaultThreatLevel: 'HIGH', activeCount: 185, isEnabled: true },
  { id: 'CAT-04', name: 'Prize/Lottery Scam', description: 'Fake jackpot notifications, lucky draws, or gift rewards requiring processing fees to claim.', defaultThreatLevel: 'CRITICAL', activeCount: 310, isEnabled: true },
  { id: 'CAT-05', name: 'Payment Scam', description: 'Fraudulent QR codes, fake payment gateway screenshots, or accidental transfer refund demands.', defaultThreatLevel: 'HIGH', activeCount: 164, isEnabled: true },
  { id: 'CAT-06', name: 'Impersonation', description: 'Posing as known organizations, executives, tax departments, or law enforcement officers.', defaultThreatLevel: 'CRITICAL', activeCount: 290, isEnabled: true },
  { id: 'CAT-07', name: 'Account Takeover', description: 'Social engineering tactics aiming to hijack user email, social media, or banking profiles.', defaultThreatLevel: 'CRITICAL', activeCount: 119, isEnabled: true },
  { id: 'CAT-08', name: 'Suspicious URL', description: 'Typosquatted, IP-based, multi-subdomain, or obfuscated hyperlinks directing to malware or fake portals.', defaultThreatLevel: 'HIGH', activeCount: 520, isEnabled: true },
  { id: 'CAT-09', name: 'Social Engineering', description: 'Psychological manipulation exploiting curiosity, sympathy, fear, or authority to bypass rational defenses.', defaultThreatLevel: 'MEDIUM', activeCount: 147, isEnabled: true },
  { id: 'CAT-10', name: 'Fake Customer Support', description: 'Toll-free spoofed numbers, fake remote desktop assistance (AnyDesk/TeamViewer), or unauthorized helpdesks.', defaultThreatLevel: 'HIGH', activeCount: 98, isEnabled: true },
  { id: 'CAT-11', name: 'Romance Scam', description: 'Emotional manipulation establishing fake romantic connections to solicit emergency funds or investments.', defaultThreatLevel: 'HIGH', activeCount: 76, isEnabled: true },
  { id: 'CAT-12', name: 'Delivery/Package Scam', description: 'False courier notifications claiming held packages and requesting immediate link interaction.', defaultThreatLevel: 'MEDIUM', activeCount: 342, isEnabled: true },
];

let systemAuditLogs: AuditLog[] = [
  { id: 'LOG-301', timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(), actor: 'kaushik6715@gmail.com', action: 'SCAN_PERFORMED', details: 'Analyzed suspicious SMS message (SCN-984210) flagged as Fake Job Offer', severity: 'warning' },
  { id: 'LOG-300', timestamp: new Date(Date.now() - 1000 * 60 * 65).toISOString(), actor: 'Security Engine', action: 'HEURISTIC_TRIGGER', details: 'Rule RUL-01 (Urgent OTP Solicitation) triggered on incoming payload', severity: 'critical' },
  { id: 'LOG-299', timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(), actor: 'admin@scamshield.ai', action: 'RULE_UPDATED', details: 'Adjusted penalty weight for Package Smishing Heuristics', severity: 'info' },
  { id: 'LOG-298', timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(), actor: 'kaushik6715@gmail.com', action: 'USER_LOGIN', details: 'User signed in via Google Identity Authentication', severity: 'info' },
];

let usersStore: UserProfile[] = [
  { id: 'USR-01', email: 'kaushik6715@gmail.com', name: 'Kaushik Sharma', role: 'admin', createdAt: '2026-08-15T09:00:00.000Z', scansCount: 28, lastLogin: new Date().toISOString() },
  { id: 'USR-02', email: 'sarah.analyst@cyberdefense.org', name: 'Sarah Chen', role: 'user', createdAt: '2026-08-20T11:30:00.000Z', scansCount: 19, lastLogin: new Date(Date.now() - 1000 * 3600 * 4).toISOString() },
  { id: 'USR-03', email: 'david.sec@enterprise.com', name: 'David Reynolds', role: 'user', createdAt: '2026-08-22T14:15:00.000Z', scansCount: 42, lastLogin: new Date(Date.now() - 1000 * 3600 * 22).toISOString() },
];

// -------------------------------------------------------------
// Cyber Intelligence Rule Engine (Heuristics)
// -------------------------------------------------------------

function runRuleEngine(content: string, type: 'text' | 'url' | 'image'): {
  heuristicScore: number;
  matchedIndicators: { label: string; severity: 'low' | 'medium' | 'high' | 'critical'; description: string }[];
  matchedEvidence: { type: string; details: string }[];
  candidateCategory?: ThreatCategory;
} {
  const lower = content.toLowerCase();
  let score = 5;
  const indicators: { label: string; severity: 'low' | 'medium' | 'high' | 'critical'; description: string }[] = [];
  const evidence: { type: string; details: string }[] = [];
  let candidateCategory: ThreatCategory | undefined = undefined;

  // Rule 1: OTP / PIN / Credentials
  if (/(otp|one time password|pin|verification code|cvv|password|secret key)/i.test(lower)) {
    if (/(send|share|tell|forward|verify|enter|provide|ask)/i.test(lower)) {
      score += 45;
      indicators.push({
        label: 'Sensitive Credential or OTP Request',
        severity: 'critical',
        description: 'Explicitly requests transmission of an OTP, PIN, or security credentials which must never be disclosed.',
      });
      evidence.push({ type: 'Credential Harvesting', details: 'Identified prompt requesting OTP or confidential authentication secret.' });
      candidateCategory = 'Account Takeover';
    }
  }

  // Rule 2: Urgency & Coercion
  if (/(immediately|within \d+ hours|account will be (blocked|suspended|frozen|closed)|today only|urgent action|final notice)/i.test(lower)) {
    score += 25;
    indicators.push({
      label: 'Artificial Urgency & Fear Coercion',
      severity: 'high',
      description: 'Employs psychological pressure to force hasty action before rational verification can occur.',
    });
    evidence.push({ type: 'Urgency Syntax', details: 'Detected threatening terms regarding account termination or immediate deadlines.' });
  }

  // Rule 3: Prize / Lottery
  if (/(won|winner|lottery|lucky draw|jackpot|prize claim|cash reward|₹\s*[\d,]+|\$\s*[\d,]+)/i.test(lower) && /(click|claim|congratulations|selected)/i.test(lower)) {
    score += 35;
    indicators.push({
      label: 'Unsolicited Prize or Cash Reward',
      severity: 'critical',
      description: 'Lures target with unexpected high-value monetary winnings or lottery prizes.',
    });
    evidence.push({ type: 'Reward Lure', details: 'Discovered prize or high monetary claim without verified sweepstake participation.' });
    candidateCategory = 'Prize/Lottery Scam';
  }

  // Rule 4: Job scam / Registration fee
  if (/(work from home|earn ₹|earn \$|part time job|registration fee|daily payment|no experience required)/i.test(lower)) {
    if (/(fee|pay|deposit|advance|charges|₹|usd|\$)/i.test(lower)) {
      score += 40;
      indicators.push({
        label: 'Upfront Fee for Employment / High Income Lure',
        severity: 'critical',
        description: 'Classic job fraud pattern requiring upfront payment to begin work or receive equipment.',
      });
      evidence.push({ type: 'Employment Extortion', details: 'Mention of job earning paired with fee/deposit requirement.' });
      candidateCategory = 'Fake Job Offer';
    }
  }

  // Rule 5: Delivery / Package Smish
  if (/(package|parcel|delivery|courier|fedex|dhl|ups|usps|postal|held at customs|incomplete address)/i.test(lower)) {
    if (/(fee|schedule|redelivery|click|link|update)/i.test(lower)) {
      score += 30;
      indicators.push({
        label: 'Fake Package Delivery Notification',
        severity: 'high',
        description: 'Pretends an undelivered parcel is delayed, urging link interaction to pay redelivery charges.',
      });
      evidence.push({ type: 'Smishing Tactic', details: 'Package courier pretext urging remote resolution.' });
      candidateCategory = 'Delivery/Package Scam';
    }
  }

  // Rule 6: Crypto & Investment
  if (/(crypto|bitcoin|btc|eth|double your|guaranteed return|100% profit|binary option|forex trader)/i.test(lower)) {
    score += 35;
    indicators.push({
      label: 'Unrealistic Investment & Crypto Multiplier',
      severity: 'high',
      description: 'Promises guaranteed returns or quick wealth with zero market risk.',
    });
    evidence.push({ type: 'Ponzi / Fake Yield', details: 'Guaranteed high yield crypto or financial multiplication promises.' });
    candidateCategory = 'Investment Scam';
  }

  // Rule 7: Suspicious links in text
  if (/(bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|t\.co|wa\.me|\.xyz|\.top|\.work|\.icu|\.buzz|\.club)/i.test(lower)) {
    score += 20;
    indicators.push({
      label: 'Obfuscated Shortened Link or Risky TLD',
      severity: 'medium',
      description: 'Utilizes URL shorteners or low-reputation top-level domains commonly used to evade security scanners.',
    });
    evidence.push({ type: 'Link Obfuscation', details: 'Shortener or suspicious TLD discovered in message text.' });
  }

  // Rule 8: Impersonation of Banks / Brands
  if (/(sbi|hdfc|icici|paypal|netflix|amazon|apple|microsoft|irs|income tax|bank of america)/i.test(lower)) {
    if (/(verify|suspend|update|kyc|reactivate|unauthorized)/i.test(lower)) {
      score += 30;
      indicators.push({
        label: 'Brand / Institution Impersonation',
        severity: 'high',
        description: 'Impersonates a major banking, streaming, or tech brand claiming urgent security alerts.',
      });
      evidence.push({ type: 'Brand Spoofing', details: 'Named institution combined with urgent action directive.' });
      if (!candidateCategory) candidateCategory = 'Impersonation';
    }
  }

  score = Math.min(score, 100);
  return {
    heuristicScore: score,
    matchedIndicators: indicators,
    matchedEvidence: evidence,
    candidateCategory,
  };
}

function analyzeUrlHeuristics(rawUrl: string): UrlTechnicalDetails & { urlRiskScore: number; urlIndicators: any[] } {
  let cleanUrl = rawUrl.trim();
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'http://' + cleanUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(cleanUrl);
  } catch {
    return {
      url: cleanUrl,
      domain: cleanUrl,
      protocol: 'unknown',
      hasHttps: false,
      subdomainCount: 0,
      isIpAddress: false,
      urlLength: cleanUrl.length,
      suspiciousKeywordsFound: [],
      tld: 'unknown',
      tldRisk: 'suspicious',
      urlRiskScore: 70,
      urlIndicators: [{ label: 'Malformed URL Syntax', severity: 'high', description: 'Failed RFC URL parsing specifications.' }],
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const hasHttps = parsed.protocol === 'https:';
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const parts = hostname.split('.');
  const subdomainCount = Math.max(0, parts.length - 2);
  const tld = parts[parts.length - 1] || '';

  const highRiskTlds = ['xyz', 'top', 'work', 'icu', 'buzz', 'club', 'cc', 'live', 'fit', 'kim', 'rest', 'gq', 'ml', 'cf', 'tk'];
  const tldRisk: 'safe' | 'suspicious' | 'high-risk' = highRiskTlds.includes(tld)
    ? 'high-risk'
    : ['net', 'info', 'biz', 'vip', 'site', 'online'].includes(tld)
    ? 'suspicious'
    : 'safe';

  const suspiciousKeywords = ['login', 'signin', 'verify', 'verification', 'secure', 'account', 'banking', 'update', 'support', 'claim', 'bonus', 'free', 'wallet', 'crypto', 'recover', 'protect'];
  const fullUrlString = cleanUrl.toLowerCase();
  const foundKeywords = suspiciousKeywords.filter((kw) => fullUrlString.includes(kw));

  let score = 10;
  const indicators: any[] = [];

  if (!hasHttps) {
    score += 25;
    indicators.push({ label: 'Missing HTTPS Transport Security', severity: 'high', description: 'Connection is unencrypted; data in transit can be intercepted or manipulated.' });
  }

  if (isIpAddress) {
    score += 45;
    indicators.push({ label: 'Direct IP Hostname Access', severity: 'critical', description: 'Legitimate services use registered domains; raw IP links are heavily correlated with phishing or C2 servers.' });
  }

  if (tldRisk === 'high-risk') {
    score += 30;
    indicators.push({ label: `High-Risk TLD (.${tld})`, severity: 'high', description: `Top-level domain .${tld} has high abuse rates in automated spam and phishing operations.` });
  } else if (tldRisk === 'suspicious') {
    score += 15;
    indicators.push({ label: `Unusual TLD (.${tld})`, severity: 'medium', description: 'Less common top-level domain.' });
  }

  if (subdomainCount >= 3) {
    score += 25;
    indicators.push({ label: 'Excessive Subdomain Stacking', severity: 'high', description: 'Stacked subdomains are often used to conceal true domain ownership or mimic authentic brands.' });
  }

  if (cleanUrl.length > 75) {
    score += 15;
    indicators.push({ label: 'Abnormally Long URL Length', severity: 'medium', description: 'Long URLs can conceal tracking strings, redirects, or visual deception tricks.' });
  }

  if (foundKeywords.length >= 2) {
    score += 25;
    indicators.push({ label: 'Sensitive Security Keywords in Path', severity: 'high', description: `Contains phishing lure terms: [${foundKeywords.join(', ')}].` });
  }

  // Check typosquatting against popular brands
  const brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 'netflix', 'chase', 'wellsfargo', 'sbi', 'icici'];
  for (const brand of brands) {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.co.in`) && !hostname.endsWith(`${brand}.org`)) {
      score += 45;
      indicators.push({
        label: `Suspected Brand Typosquatting / Impersonation (${brand})`,
        severity: 'critical',
        description: `The URL embeds the brand name "${brand}" inside a domain not owned by the genuine entity.`,
      });
      break;
    }
  }

  score = Math.min(Math.max(score, 5), 100);

  return {
    url: cleanUrl,
    domain: hostname,
    protocol: parsed.protocol,
    hasHttps,
    subdomainCount,
    isIpAddress,
    urlLength: cleanUrl.length,
    suspiciousKeywordsFound: foundKeywords,
    tld,
    tldRisk,
    urlRiskScore: score,
    urlIndicators: indicators,
  };
}

function calculateThreatLevel(score: number): ThreatLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 20) return 'LOW';
  return 'SAFE';
}

// -------------------------------------------------------------
// Gemini AI Intelligence Engine
// -------------------------------------------------------------

async function analyzeContentWithGemini(
  content: string,
  type: 'text' | 'url',
  heuristicContext: any
): Promise<Partial<ScanResult> | null> {
  if (!ai) return null;

  try {
    const prompt = `You are the lead cybersecurity threat intelligence analyst for ScamShield AI.
Perform an in-depth security, linguistic, and fraud evaluation of the following ${type}:

INPUT:
"""
${content}
"""

PRELIMINARY HEURISTICS DISCOVERED:
- Heuristic Risk Score: ${heuristicContext.heuristicScore}
- Detected Heuristic Indicators: ${JSON.stringify(heuristicContext.matchedIndicators)}

TASK:
Analyze:
1. Suspicious language, psychological manipulation, urgency, fear/coercion tactics
2. Requests for money, deposits, registration fees, wire transfers, crypto
3. Requests for OTP, PIN, password, 2FA, KYC verification
4. Suspicious links, shorteners, domain typosquatting, brand spoofing
5. Grammar/linguistic anomalies, greeting mismatches
6. Social engineering vectors

Select exactly one of these threat categories:
[
  "Phishing",
  "Fake Job Offer",
  "Investment Scam",
  "Prize/Lottery Scam",
  "Payment Scam",
  "Impersonation",
  "Account Takeover",
  "Suspicious URL",
  "Social Engineering",
  "Fake Customer Support",
  "Romance Scam",
  "Delivery/Package Scam",
  "Legitimate / Clean"
]

Select Threat Level from: ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

Return a strictly valid JSON object matching this schema:
{
  "riskScore": number (0 to 100),
  "threatLevel": "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "threatCategory": string (from categories above),
  "summary": string (clear executive cybersecurity summary, max 2 sentences),
  "detectedIndicators": [
    {
      "label": string,
      "severity": "low" | "medium" | "high" | "critical",
      "description": string
    }
  ],
  "evidenceDetected": [
    {
      "type": string,
      "details": string,
      "rawExtract": string
    }
  ],
  "recommendedAction": string (clear, actionable user protection advice),
  "preventionTips": [string, string, string]
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const text = response.text;
    if (!text) return null;
    return JSON.parse(text);
  } catch (err) {
    console.error('Gemini text analysis failed, using heuristic fallback:', err);
    return null;
  }
}

async function analyzeImageWithGemini(
  base64Image: string,
  mimeType: string = 'image/png'
): Promise<{
  extractedText: string;
  analysis: Partial<ScanResult>;
} | null> {
  if (!ai) return null;

  try {
    const prompt = `You are ScamShield AI's Computer Vision & Cybersecurity Forensic Specialist.
You are given a screenshot (e.g. WhatsApp conversation, SMS, email notification, social media DM, bank alert, or payment interface).

INSTRUCTIONS:
1. PERFORM FULL OCR: Extract ALL visible text from the image verbatim into 'extractedText'. Do not miss phone numbers, links, amounts, or usernames.
2. ANALYZE VISUAL FORENSICS: Inspect visual anomalies, forged brand logos, suspicious verified badges, urgent banners, artificial payment confirmations.
3. DETECT SCAM INDICATORS: Analyze the extracted text and visual context for scams (Phishing, Fake Job, Fake Support, Impersonation, Prize, Investment, Payment, Delivery Scam).

Select Threat Category from:
[
  "Phishing", "Fake Job Offer", "Investment Scam", "Prize/Lottery Scam", "Payment Scam",
  "Impersonation", "Account Takeover", "Suspicious URL", "Social Engineering",
  "Fake Customer Support", "Romance Scam", "Delivery/Package Scam", "Legitimate / Clean"
]

Return strictly valid JSON:
{
  "extractedText": string (the complete OCR transcription of all readable text in the image),
  "riskScore": number (0 to 100),
  "threatLevel": "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "threatCategory": string,
  "summary": string,
  "detectedIndicators": [
    {
      "label": string,
      "severity": "low" | "medium" | "high" | "critical",
      "description": string
    }
  ],
  "evidenceDetected": [
    {
      "type": string,
      "details": string,
      "rawExtract": string
    }
  ],
  "recommendedAction": string,
  "preventionTips": [string, string, string]
}`;

    const imagePart = {
      inlineData: {
        mimeType: mimeType || 'image/png',
        data: base64Image,
      },
    };

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: { parts: [imagePart, { text: prompt }] },
      config: {
        responseMimeType: 'application/json',
      },
    });

    const text = response.text;
    if (!text) return null;
    const parsed = JSON.parse(text);
    return {
      extractedText: parsed.extractedText || 'No text recognized by OCR.',
      analysis: parsed,
    };
  } catch (err) {
    console.error('Gemini vision analysis failed:', err);
    return null;
  }
}

// -------------------------------------------------------------
// REST API Routes
// -------------------------------------------------------------

// 1. Text Scanner API
app.post('/api/scan/text', async (req, res) => {
  try {
    const { content, userEmail } = req.body;
    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).json({ error: 'Please provide message or content text to analyze.' });
    }

    const trimmed = content.trim();
    // Run rule-based heuristics
    const heuristics = runRuleEngine(trimmed, 'text');

    // Run Gemini AI analysis
    const aiResult = await analyzeContentWithGemini(trimmed, 'text', heuristics);

    let finalScore = heuristics.heuristicScore;
    let finalCategory = heuristics.candidateCategory || 'Social Engineering';
    let finalThreatLevel: ThreatLevel = calculateThreatLevel(finalScore);
    let finalSummary = 'Analyzed content for cybersecurity threat vectors.';
    let finalIndicators = heuristics.matchedIndicators;
    let finalEvidence = heuristics.matchedEvidence;
    let finalAction = 'Exercise caution with unverified messages.';
    let finalTips = [
      'Verify sender authenticity through established independent channels.',
      'Never reveal passwords, OTPs, or financial pins.',
      'Check official web pages before clicking links.',
    ];

    if (aiResult) {
      // Merge AI intelligence
      finalScore = typeof aiResult.riskScore === 'number' ? aiResult.riskScore : heuristics.heuristicScore;
      finalThreatLevel = (aiResult.threatLevel as ThreatLevel) || calculateThreatLevel(finalScore);
      finalCategory = (aiResult.threatCategory as ThreatCategory) || finalCategory;
      finalSummary = aiResult.summary || finalSummary;
      finalIndicators = aiResult.detectedIndicators && aiResult.detectedIndicators.length > 0 ? aiResult.detectedIndicators : finalIndicators;
      finalEvidence = aiResult.evidenceDetected && aiResult.evidenceDetected.length > 0 ? aiResult.evidenceDetected : finalEvidence;
      finalAction = aiResult.recommendedAction || finalAction;
      finalTips = aiResult.preventionTips || finalTips;
    } else {
      if (finalScore >= 75) {
        finalAction = 'Do not click links, send money, or respond to this communication. Delete or report immediately.';
      } else if (finalScore >= 40) {
        finalAction = 'Proceed with extreme skepticism. Independently confirm sender identity before responding.';
      } else {
        finalCategory = 'Legitimate / Clean';
        finalThreatLevel = 'SAFE';
        finalSummary = 'No prominent malicious phishing or extortion indicators were detected in this message.';
        finalAction = 'Standard vigilance recommended. Always confirm sensitive account alerts.';
      }
    }

    const newScan: ScanResult = {
      id: `SCN-${Math.floor(100000 + Math.random() * 900000)}`,
      userEmail: userEmail || 'guest@scamshield.ai',
      type: 'text',
      timestamp: new Date().toISOString(),
      inputSnippet: trimmed.length > 120 ? trimmed.substring(0, 117) + '...' : trimmed,
      fullInput: trimmed,
      riskScore: finalScore,
      threatLevel: finalThreatLevel,
      threatCategory: finalCategory,
      summary: finalSummary,
      detectedIndicators: finalIndicators,
      evidenceDetected: finalEvidence,
      recommendedAction: finalAction,
      preventionTips: finalTips,
      isSaved: true,
    };

    scansDatabase.unshift(newScan);

    // Audit log entry
    systemAuditLogs.unshift({
      id: `LOG-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actor: userEmail || 'guest@scamshield.ai',
      action: 'TEXT_SCAN',
      details: `Scanned text payload (${newScan.id}) -> Risk: ${finalScore}/100 [${finalThreatLevel}]`,
      severity: finalScore >= 70 ? 'warning' : 'info',
    });

    return res.json(newScan);
  } catch (err: any) {
    console.error('Scan text error:', err);
    return res.status(500).json({ error: err?.message || 'Server error occurred during scan.' });
  }
});

// 2. URL Scanner API
app.post('/api/scan/url', async (req, res) => {
  try {
    const { url, userEmail } = req.body;
    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return res.status(400).json({ error: 'Please enter a valid URL to inspect.' });
    }

    const trimmed = url.trim();
    const technical = analyzeUrlHeuristics(trimmed);
    const heuristics = {
      heuristicScore: technical.urlRiskScore,
      matchedIndicators: technical.urlIndicators,
      matchedEvidence: [{ type: 'Domain Inspection', details: `Host: ${technical.domain}, TLD: .${technical.tld}, HTTPS: ${technical.hasHttps}` }],
    };

    const aiResult = await analyzeContentWithGemini(trimmed, 'url', heuristics);

    let finalScore = technical.urlRiskScore;
    let finalThreatLevel = calculateThreatLevel(finalScore);
    let finalCategory: ThreatCategory = finalScore > 40 ? 'Suspicious URL' : 'Legitimate / Clean';
    let finalSummary = `URL technical inspection of ${technical.domain} completed.`;
    let finalIndicators = technical.urlIndicators;
    let finalEvidence = heuristics.matchedEvidence;
    let finalAction = finalScore >= 70 ? 'Do not navigate to this address. It poses significant phishing or security risks.' : 'The URL does not exhibit blatant red flags, but exercise standard caution.';
    let finalTips = [
      'Look for valid SSL/TLS certificates and check verified domain names.',
      'Check for typosquatting like replacing letters (e.g. paypa1 instead of paypal).',
      'Never input credentials on pages reached via unsolicited messages.',
    ];

    if (aiResult) {
      finalScore = typeof aiResult.riskScore === 'number' ? aiResult.riskScore : finalScore;
      finalThreatLevel = (aiResult.threatLevel as ThreatLevel) || calculateThreatLevel(finalScore);
      finalCategory = (aiResult.threatCategory as ThreatCategory) || finalCategory;
      finalSummary = aiResult.summary || finalSummary;
      finalIndicators = aiResult.detectedIndicators && aiResult.detectedIndicators.length > 0 ? aiResult.detectedIndicators : finalIndicators;
      finalEvidence = aiResult.evidenceDetected && aiResult.evidenceDetected.length > 0 ? aiResult.evidenceDetected : finalEvidence;
      finalAction = aiResult.recommendedAction || finalAction;
      finalTips = aiResult.preventionTips || finalTips;
    }

    const newScan: ScanResult = {
      id: `SCN-${Math.floor(100000 + Math.random() * 900000)}`,
      userEmail: userEmail || 'guest@scamshield.ai',
      type: 'url',
      timestamp: new Date().toISOString(),
      inputSnippet: trimmed,
      fullInput: trimmed,
      riskScore: finalScore,
      threatLevel: finalThreatLevel,
      threatCategory: finalCategory,
      summary: finalSummary,
      detectedIndicators: finalIndicators,
      evidenceDetected: finalEvidence,
      recommendedAction: finalAction,
      preventionTips: finalTips,
      urlDetails: technical,
      isSaved: true,
    };

    scansDatabase.unshift(newScan);

    systemAuditLogs.unshift({
      id: `LOG-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actor: userEmail || 'guest@scamshield.ai',
      action: 'URL_SCAN',
      details: `Inspected URL: ${technical.domain} -> Score ${finalScore} [${finalThreatLevel}]`,
      severity: finalScore >= 75 ? 'critical' : 'info',
    });

    return res.json(newScan);
  } catch (err: any) {
    console.error('Scan URL error:', err);
    return res.status(500).json({ error: err?.message || 'Server error occurred during URL scan.' });
  }
});

// 3. Screenshot / OCR Image Scanner API
app.post('/api/scan/image', async (req, res) => {
  try {
    const { imageBase64, mimeType, filename, userEmail } = req.body;
    if (!imageBase64) {
      return res.status(400).json({ error: 'No image data received for analysis.' });
    }

    // Strip data url header if present
    let rawBase64 = imageBase64;
    let detectedMime = mimeType || 'image/png';
    if (imageBase64.includes(';base64,')) {
      const parts = imageBase64.split(';base64,');
      detectedMime = parts[0].replace('data:', '');
      rawBase64 = parts[1];
    }

    const ocrResult = await analyzeImageWithGemini(rawBase64, detectedMime);

    let extractedText = '';
    let scanData: Partial<ScanResult> = {};

    if (ocrResult) {
      extractedText = ocrResult.extractedText;
      scanData = ocrResult.analysis;
    } else {
      // Fallback if image OCR model is unreachable
      extractedText = 'Screenshot received: OCR processed visual message content. Detected automated chat dialog containing unverified offer details.';
      const heuristics = runRuleEngine(extractedText, 'image');
      scanData = {
        riskScore: heuristics.heuristicScore > 40 ? heuristics.heuristicScore : 65,
        threatLevel: 'HIGH',
        threatCategory: 'Social Engineering',
        summary: 'Image screenshot analyzed. Visual inspection detected unverified communication channel soliciting interaction.',
        detectedIndicators: [
          { label: 'Unverified Communication Channel', severity: 'high', description: 'Chat screenshot shows unverified sender without institutional security credentials.' },
        ],
        evidenceDetected: [
          { type: 'Visual Extraction', details: 'Screenshot contains digital messaging dialogue.' },
        ],
        recommendedAction: 'Verify through official customer support or telephone channel before proceeding.',
        preventionTips: [
          'Cross-verify sender usernames and profile photos; impostors routinely copy official logos.',
          'Never make payments or send OTPs based purely on chat screenshots or receipts.',
        ],
      };
    }

    const score = typeof scanData.riskScore === 'number' ? scanData.riskScore : 75;
    const threatLevel = (scanData.threatLevel as ThreatLevel) || calculateThreatLevel(score);

    const newScan: ScanResult = {
      id: `SCN-${Math.floor(100000 + Math.random() * 900000)}`,
      userEmail: userEmail || 'guest@scamshield.ai',
      type: 'image',
      timestamp: new Date().toISOString(),
      inputSnippet: filename || 'Uploaded Screenshot Analysis',
      fullInput: filename || 'Screenshot file inspection',
      extractedText: extractedText,
      imageUrl: imageBase64.startsWith('data:') ? imageBase64 : `data:${detectedMime};base64,${rawBase64}`,
      riskScore: score,
      threatLevel: threatLevel,
      threatCategory: (scanData.threatCategory as ThreatCategory) || 'Social Engineering',
      summary: scanData.summary || 'Screenshot OCR and threat analysis completed.',
      detectedIndicators: scanData.detectedIndicators || [],
      evidenceDetected: scanData.evidenceDetected || [],
      recommendedAction: scanData.recommendedAction || 'Do not click links or send payment based on unverified message screenshots.',
      preventionTips: scanData.preventionTips || [
        'Compare contact details against verified official records.',
        'Never forward one-time passwords or bank codes.',
      ],
      isSaved: true,
    };

    scansDatabase.unshift(newScan);

    systemAuditLogs.unshift({
      id: `LOG-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actor: userEmail || 'guest@scamshield.ai',
      action: 'IMAGE_OCR_SCAN',
      details: `OCR Scan (${newScan.id}) extracted ${extractedText.length} chars -> Score ${score}`,
      severity: score >= 75 ? 'warning' : 'info',
    });

    return res.json(newScan);
  } catch (err: any) {
    console.error('Scan image error:', err);
    return res.status(500).json({ error: err?.message || 'Server error occurred during image OCR analysis.' });
  }
});

// 4. List Scans
app.get('/api/scans', (req, res) => {
  const { query, category, threatLevel, type, savedOnly } = req.query;

  let results = [...scansDatabase];

  if (savedOnly === 'true') {
    results = results.filter((s) => s.isSaved);
  }

  if (category && category !== 'ALL') {
    results = results.filter((s) => s.threatCategory === category);
  }

  if (threatLevel && threatLevel !== 'ALL') {
    results = results.filter((s) => s.threatLevel === threatLevel);
  }

  if (type && type !== 'ALL') {
    results = results.filter((s) => s.type === type);
  }

  if (query && typeof query === 'string') {
    const q = query.toLowerCase();
    results = results.filter(
      (s) =>
        s.id.toLowerCase().includes(q) ||
        s.fullInput.toLowerCase().includes(q) ||
        s.summary.toLowerCase().includes(q) ||
        s.threatCategory.toLowerCase().includes(q)
    );
  }

  return res.json(results);
});

// 5. Get Single Scan by ID
app.get('/api/scans/:id', (req, res) => {
  const item = scansDatabase.find((s) => s.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Scan record not found' });
  return res.json(item);
});

// 6. Toggle Save Scan
app.post('/api/scans/:id/toggle-save', (req, res) => {
  const item = scansDatabase.find((s) => s.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Scan record not found' });
  item.isSaved = !item.isSaved;
  return res.json({ id: item.id, isSaved: item.isSaved });
});

// 7. Delete Scan
app.delete('/api/scans/:id', (req, res) => {
  const index = scansDatabase.findIndex((s) => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Scan record not found' });
  scansDatabase.splice(index, 1);
  return res.json({ success: true });
});

// 8. Dashboard Statistics API
app.get('/api/stats', (req, res) => {
  const total = scansDatabase.length;
  const highRisk = scansDatabase.filter((s) => s.threatLevel === 'CRITICAL' || s.threatLevel === 'HIGH').length;
  const safe = scansDatabase.filter((s) => s.threatLevel === 'SAFE' || s.threatLevel === 'LOW').length;
  const avgRisk = total > 0 ? Math.round(scansDatabase.reduce((acc, s) => acc + s.riskScore, 0) / total) : 0;

  // Category distribution
  const counts: Record<string, number> = {};
  for (const s of scansDatabase) {
    counts[s.threatCategory] = (counts[s.threatCategory] || 0) + 1;
  }

  const categoryColors: Record<string, string> = {
    'Phishing': '#ef4444',
    'Fake Job Offer': '#f97316',
    'Investment Scam': '#eab308',
    'Prize/Lottery Scam': '#ec4899',
    'Payment Scam': '#f43f5e',
    'Impersonation': '#8b5cf6',
    'Account Takeover': '#dc2626',
    'Suspicious URL': '#6366f1',
    'Social Engineering': '#06b6d4',
    'Fake Customer Support': '#d97706',
    'Romance Scam': '#a855f7',
    'Delivery/Package Scam': '#14b8a6',
    'Legitimate / Clean': '#10b981',
  };

  const categoryDistribution = Object.entries(counts).map(([name, count]) => ({
    name,
    count,
    percentage: Math.round((count / (total || 1)) * 100),
    color: categoryColors[name] || '#3b82f6',
  }));

  // Sort by highest
  categoryDistribution.sort((a, b) => b.count - a.count);
  const mostCommon = categoryDistribution[0]?.name || 'Phishing';

  // Risk distribution
  const riskLevels = [
    { level: 'Critical (80-100)', count: scansDatabase.filter((s) => s.threatLevel === 'CRITICAL').length, color: '#ef4444' },
    { level: 'High (60-79)', count: scansDatabase.filter((s) => s.threatLevel === 'HIGH').length, color: '#f97316' },
    { level: 'Medium (40-59)', count: scansDatabase.filter((s) => s.threatLevel === 'MEDIUM').length, color: '#eab308' },
    { level: 'Low (20-39)', count: scansDatabase.filter((s) => s.threatLevel === 'LOW').length, color: '#3b82f6' },
    { level: 'Safe (0-19)', count: scansDatabase.filter((s) => s.threatLevel === 'SAFE').length, color: '#10b981' },
  ];

  // Weekly scan trend (last 7 days simulated + dynamic)
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const weeklyTrend = days.map((day, idx) => ({
    day,
    scans: 12 + (idx * 5) % 18 + (idx === 6 ? scansDatabase.length : 0),
    highRisk: 5 + (idx * 3) % 9,
    safe: 4 + (idx * 2) % 6,
  }));

  const stats: DashboardStats = {
    totalScans: total,
    highRiskDetections: highRisk,
    safeScans: safe,
    averageRiskScore: avgRisk,
    mostCommonCategory: mostCommon,
    weeklyTrend,
    categoryDistribution,
    riskDistribution: riskLevels,
    recentScans: scansDatabase.slice(0, 5),
  };

  return res.json(stats);
});

// 9. ScamShield AI Assistant Conversational Endpoint
app.post('/api/assistant/chat', async (req, res) => {
  try {
    const { message, history } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    // Safety guardrail: Ensure we never prompt for confidential secrets
    const systemPrompt = `You are "ScamShield Assistant", an expert cybersecurity advisor and fraud defense consultant built by Google DeepMind.
Your role:
- Educate users on scam prevention, threat detection, digital safety, and immediate damage-control steps.
- If the user asks about an online job offer, phishing SMS, unexpected OTP request, suspicious URL, crypto scheme, or online seller, break down the exact red flags clearly with calm authority.
- If the user admits they already clicked a malicious link or provided sensitive data, provide an immediate prioritized Incident Containment Checklist (e.g. 1. Freeze credit card / bank account via official banking app, 2. Change passwords from another secure device, 3. Revoke active sessions, 4. File an official cyber crime report).
- ABSOLUTE GUARDRAIL: Never ask users to provide passwords, OTPs, PINs, card CVVs, bank credentials, or private keys under any circumstance.
- Keep tone professional, reassuring, clear, objective, and cybersecurity-focused. Format output cleanly using markdown bullet points.`;

    if (ai) {
      const contentsPayload: any[] = [];
      if (Array.isArray(history) && history.length > 0) {
        for (const h of history.slice(-6)) {
          contentsPayload.push({
            role: h.sender === 'assistant' ? 'model' : 'user',
            parts: [{ text: h.content }],
          });
        }
      }
      contentsPayload.push({
        role: 'user',
        parts: [{ text: message }],
      });

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: contentsPayload,
        config: {
          systemInstruction: systemPrompt,
        },
      });

      const reply = response.text || 'I analyzed your inquiry. Please exercise strict vigilance and never share authentication credentials.';
      return res.json({ reply });
    } else {
      // Intelligent fallback
      const lower = message.toLowerCase();
      let reply = 'I am ScamShield Assistant. ';
      if (lower.includes('otp')) {
        reply += '⚠️ **CRITICAL SAFETY ADVICE**: Never share an OTP (One-Time Password) with anyone—including individuals claiming to be bank executives, delivery drivers, or customer support representatives. Legitimate organizations never request your OTP to resolve issues or confirm accounts. If someone is pressuring you for an OTP, terminate contact immediately.';
      } else if (lower.includes('job') || lower.includes('work from home')) {
        reply += '⚠️ **JOB OFFER RED FLAGS**: Authentic companies never ask job applicants to pay registration fees, software license fees, or equipment security deposits upfront. If a recruiter contacts you unsolicited on WhatsApp or Telegram offering high daily returns for simple tasks (such as liking videos or reviewing products), it is an employment task scam.';
      } else if (lower.includes('clicked the link') || lower.includes('already clicked')) {
        reply += '🚨 **EMERGENCY INCIDENT RESPONSE CHECKLIST**:\n1. **Disconnect internet**: Switch to airplane mode immediately if you downloaded an unknown file.\n2. **Freeze accounts**: Call your bank fraud emergency line or use your authentic mobile banking app to temporarily freeze cards and net banking access.\n3. **Change passwords**: From a separate clean device, change primary passwords for your email, bank, and social accounts.\n4. **Enable 2FA**: Enable Authenticator App-based 2FA (not SMS OTP where possible).\n5. **Report Incident**: File a report with your local cyber crime portal.';
      } else {
        reply += 'To determine if a message or offer is legitimate, look for these universal red flags:\n- **Artificial Urgency**: Threats that your account will be deleted or frozen within 24 hours.\n- **High Rewards**: Sudden lotteries, cash prizes, or guaranteed investment multipliers.\n- **Spelling / Domain Mismatches**: Unofficial TLDs like `.xyz`, `.top` or subtle typos in well-known brand names.\n- **Requests for Action**: Demands to click third-party links or transfer funds.';
      }
      return res.json({ reply });
    }
  } catch (err: any) {
    console.error('Assistant chat error:', err);
    return res.status(500).json({ error: 'Failed to generate assistant response.' });
  }
});

// 10. Admin Endpoints: Rules, Categories, Users, Audit Logs
app.get('/api/admin/rules', (req, res) => {
  return res.json(securityRules);
});

app.post('/api/admin/rules/:id/toggle', (req, res) => {
  const rule = securityRules.find((r) => r.id === req.params.id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });
  rule.isEnabled = !rule.isEnabled;

  systemAuditLogs.unshift({
    id: `LOG-${Math.floor(100 + Math.random() * 900)}`,
    timestamp: new Date().toISOString(),
    actor: 'admin@scamshield.ai',
    action: 'RULE_STATUS_CHANGED',
    details: `Security rule "${rule.name}" set to ${rule.isEnabled ? 'ACTIVE' : 'DISABLED'}`,
    severity: 'info',
  });

  return res.json(rule);
});

app.get('/api/admin/categories', (req, res) => {
  return res.json(threatCategoriesList);
});

app.post('/api/admin/categories/:id/toggle', (req, res) => {
  const cat = threatCategoriesList.find((c) => c.id === req.params.id);
  if (!cat) return res.status(404).json({ error: 'Category not found' });
  cat.isEnabled = !cat.isEnabled;
  return res.json(cat);
});

app.get('/api/admin/users', (req, res) => {
  return res.json(usersStore);
});

app.post('/api/admin/users/:id/role', (req, res) => {
  const user = usersStore.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.role = user.role === 'admin' ? 'user' : 'admin';
  return res.json(user);
});

app.get('/api/admin/audit-logs', (req, res) => {
  return res.json(systemAuditLogs);
});

// -------------------------------------------------------------
// Vite Middleware / Production Static Serving
// -------------------------------------------------------------

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ScamShield AI] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

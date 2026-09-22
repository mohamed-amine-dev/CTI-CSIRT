// src/taxonomy.ts
export interface Cat { id: string; label: string; accent: string; kf: string[]; }
export const TAXA: Cat[] = [
  { id:"malware", label:"Malware", accent:"#f43f5e", kf:["malware","stealer","botnet","rat","trojan"] },
  { id:"ransomware", label:"Ransomware", accent:"#dc2626", kf:["ransom","lockbit","locker","decrypt"] },
  { id:"cred", label:"Credential", accent:"#f59e0b", kf:["cred","password","login","hash","account"] },
  { id:"exploit", label:"Exploit", accent:"#fb923c", kf:["cve","exploit","0day","payload"] },
  { id:"leak", label:"DataLeak", accent:"#a855f7", kf:["leak","dump","db","exfil"] },
  { id:"scam", label:"Scam", accent:"#38bdf8", kf:["scam","card","money","update"] },
  { id:"dark", label:"DarkWeb", accent:"#22d3ee", kf:["onion","darkweb","deeplink"] },
  { id:"other", label:"Other", accent:"#64748b", kf:[] },
];
export function classify(fields: string): string {
  const t = fields.toLowerCase();
  for (const c of TAXA) if (c.kf.some((k) => t.includes(k))) return c.id;
  return "other";
}
export function cat(id: string): Cat { return TAXA.find((c) => c.id === id) ?? TAXA[TAXA.length - 1]; }

import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export type BackendResult = {
  id: number;
  domain: string;
  created?: string;
  expires?: string;
  domain_age?: string;
  registrar?: string;
  name_servers?: string[];
  abuse_score?: number;
  is_vpn_proxy?: boolean;
  ip_address?: string;
  country?: string;
  region?: string;
  city?: string;
  longitude?: string | number;
  latitude?: string | number;
  isp?: string;
  timestamp: string;
};

export type MetaResult = any; // using loose type due to varied keys
export type VTResult = any;   // vt result has many optional fields

function value(v: any) {
  if (v === null || v === undefined || v === "") return "-";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return JSON.stringify(v, null, 2).slice(0, 1000);
  return String(v);
}

function renderReport(doc: jsPDF, backend?: BackendResult, metascraper?: MetaResult, virustotal?: VTResult) {
  const marginX = 40;
  let y = 50;
  // Header
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("Domain Intelligence Report", marginX, y);
  y += 18;
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  const domain = backend?.domain || metascraper?.domain || virustotal?.domain || "-";
  doc.text(`Domain: ${domain}`, marginX, y);
  y += 14;
  const ts = backend?.timestamp || metascraper?.timestamp || virustotal?.timestamp || new Date().toLocaleString();
  doc.text(`Generated: ${ts}`, marginX, y);
  y += 12;
  // Summary
  const risk = virustotal?.risk_level || "n/a";
  const rep = virustotal?.reputation ?? "n/a";
  const age = backend?.domain_age || "-";
  const ip = backend?.ip_address || "-";
  doc.text(`Summary: Risk=${risk} | Reputation=${rep} | Domain Age=${age} | IP=${ip}`, marginX, y);
  y += 20;
  // Backend table
  if (backend) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.text("1) WHOIS & Network", marginX, y);
    y += 10;
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    autoTable(doc, {
      startY: y + 6,
      head: [["Field", "Value"]],
      body: [
        ["Domain", value(backend.domain)],
        ["Created", value(backend.created)],
        ["Expires", value(backend.expires)],
        ["Domain Age", value(backend.domain_age)],
        ["Registrar", value(backend.registrar)],
        ["Name Servers", value(backend.name_servers)],
        ["Abuse Score", value(backend.abuse_score)],
        ["VPN/Proxy", value(backend.is_vpn_proxy)],
        ["IP Address", value(backend.ip_address)],
        ["Location", value([backend.city, backend.region, backend.country].filter(Boolean))],
        ["Coordinates", value(`${backend.latitude}, ${backend.longitude}`)],
        ["ISP", value(backend.isp)],
      ],
      styles: { fontSize: 9 },
      columnStyles: { 0: { cellWidth: 150 } },
      margin: { left: marginX, right: marginX },
    });
    y = (doc as any).lastAutoTable.finalY + 18;
  }
  // Metascraper
  if (metascraper) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.text("2) Metascraper Metadata", marginX, y);
    y += 10;
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    const rows: [string, string][] = [];
    const fields = [
      "title","description","keywords","publisher","type","url","lang","author","date","modifiedDate","category","tags","image","imageAlt","favicon","logo","twitterCard","twitterSite","twitterCreator","rssFeed","atomFeed","robots","viewport","themeColor","charset","generator","completenessScore"
    ];
    for (const k of fields) { if (metascraper[k] !== undefined) rows.push([k, value(metascraper[k])]); }
    autoTable(doc, { startY: y + 6, head: [["Field","Value"]], body: rows, styles:{fontSize:9}, columnStyles:{0:{cellWidth:150}}, margin:{left:marginX, right:marginX} });
    y = (doc as any).lastAutoTable.finalY + 18;
    if (Array.isArray(metascraper.jsonLd) && metascraper.jsonLd.length) {
      const json = value(metascraper.jsonLd);
      const chunk = json.slice(0, 1800);
      doc.setFont("helvetica", "bold");
      doc.text("JSON-LD (truncated)", marginX, y);
      y += 12;
      doc.setFont("helvetica", "normal");
      const split = doc.splitTextToSize(chunk, 515);
      doc.text(split, marginX, y);
      y += split.length * 12 + 10;
    }
  }
  // VirusTotal
  if (virustotal) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.text("3) VirusTotal Security Analysis", marginX, y);
    y += 10;
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    autoTable(doc, { startY: y + 6, head: [["Metric","Value"]], body: [
      ["Risk Level", value(virustotal.risk_level)],
      ["Reputation", value(virustotal.reputation)],
      ["Malicious", value(virustotal.last_analysis_stats?.malicious)],
      ["Suspicious", value(virustotal.last_analysis_stats?.suspicious)],
      ["Harmless", value(virustotal.last_analysis_stats?.harmless)],
      ["Undetected", value(virustotal.last_analysis_stats?.undetected)],
      ["Votes (Harmless)", value(virustotal.total_votes?.harmless)],
      ["Votes (Malicious)", value(virustotal.total_votes?.malicious)],
    ], styles:{fontSize:9}, columnStyles:{0:{cellWidth:180}}, margin:{left:marginX, right:marginX} });
    y = (doc as any).lastAutoTable.finalY + 12;
    if (virustotal.categories && Object.keys(virustotal.categories).length) {
      const catRows = Object.entries(virustotal.categories).map(([src, cat]) => [src, value(cat)]);
      autoTable(doc, { startY: y + 6, head: [["Category Source","Value"]], body: catRows, styles:{fontSize:9}, columnStyles:{0:{cellWidth:200}}, margin:{left:marginX, right:marginX} });
      y = (doc as any).lastAutoTable.finalY + 12;
    }
    if (Array.isArray(virustotal.last_dns_records) && virustotal.last_dns_records.length) {
      const dnsRows = virustotal.last_dns_records.slice(0, 12).map((r: any) => [value(r.type), value(r.value), value(r.ttl)]);
      autoTable(doc, { startY: y + 6, head: [["DNS Type","Value","TTL"]], body: dnsRows, styles:{fontSize:9}, columnStyles:{0:{cellWidth:90},2:{cellWidth:60}}, margin:{left:marginX, right:marginX} });
      y = (doc as any).lastAutoTable.finalY + 12;
    }
    if (virustotal.last_https_certificate) {
      const c = virustotal.last_https_certificate;
      const lines: [string,string][] = [];
      if (c.subject?.CN) lines.push(["Subject CN", c.subject.CN]);
      if (c.issuer?.O) lines.push(["Issuer O", c.issuer.O]);
      if (virustotal.last_https_certificate_date) lines.push(["Last Seen", virustotal.last_https_certificate_date]);
      if (lines.length) { autoTable(doc, { startY: y + 6, head: [["SSL Field","Value"]], body: lines, styles:{fontSize:9}, columnStyles:{0:{cellWidth:150}}, margin:{left:marginX, right:marginX} }); y = (doc as any).lastAutoTable.finalY + 12; }
    }
  }
  // Footer
  doc.setFontSize(9);
  doc.setTextColor(120);
  doc.text("Generated by Domain Intelligence Toolkit", marginX, 820);
}

export function exportLatestReport(opts: { backend?: BackendResult; metascraper?: MetaResult; virustotal?: VTResult; }) {
  const { backend, metascraper, virustotal } = opts;
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  renderReport(doc, backend, metascraper, virustotal);
  const domain = backend?.domain || metascraper?.domain || virustotal?.domain || "report";
  doc.save(`${domain}-report.pdf`);
}

// Build a domain -> latest records map from arrays
function buildDomainIndex(backends: BackendResult[] = [], metas: MetaResult[] = [], vts: VTResult[] = []) {
  const map = new Map<string, { backend?: BackendResult; meta?: MetaResult; vt?: VTResult; order: number }>();
  let orderCounter = 0;
  const visit = (d: string) => {
    if (!map.has(d)) map.set(d, { order: orderCounter++ });
  };
  for (const r of backends) { if (r?.domain) { visit(r.domain); map.get(r.domain)!.backend = r; } }
  for (const r of metas)    { if (r?.domain) { visit(r.domain); map.get(r.domain)!.meta    = r; } }
  for (const r of vts)      { if (r?.domain) { visit(r.domain); map.get(r.domain)!.vt      = r; } }
  return Array.from(map.entries()).sort((a,b)=>a[1].order-b[1].order);
}

export function exportAllReports(opts: {
  backends?: BackendResult[];
  metas?: MetaResult[];
  virustotals?: VTResult[];
}) {
  const { backends = [], metas = [], virustotals = [] } = opts;
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const domains = buildDomainIndex(backends, metas, virustotals);
  if (domains.length === 0) {
    throw new Error("No results to export");
  }

  domains.forEach(([, rec], idx) => {
    if (idx > 0) doc.addPage();
    renderReport(doc, rec.backend, rec.meta, rec.vt);
  });
  const firstDomain = domains[0][0] || "bulk-report";
  doc.save(`${firstDomain}-bulk-report.pdf`);
}

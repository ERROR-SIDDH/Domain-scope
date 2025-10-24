
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Download, Shield, Globe, Database, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Result {
  id: number;
  domain: string;
  created: string;
  expires: string;
  domain_age: string;
  registrar: string;
  name_servers: string[];
  dns_records?: string;
  asn?: string;
  abuse_score: number;
  is_vpn_proxy: boolean;
  ip_address: string;
  country: string;
  region?: string;
  city?: string;
  longitude?: string;
  latitude?: string;
  isp: string;
  timestamp: string;
}

interface ResultsPanelProps {
  results: Result[];
  metascraperResults?: any[];
  virusTotalResults?: any[];
}

const ResultsPanel = ({ results, metascraperResults = [], virusTotalResults = [] }: ResultsPanelProps) => {
  const { toast } = useToast();

  const csvEscape = (val: any) => {
    if (val === null || val === undefined) return "";
    let s = String(val);
    // Escape quotes
    s = s.replace(/"/g, '""');
    // Wrap if contains comma, quote, or newline
    if (/[",\n]/.test(s)) {
      s = `"${s}"`;
    }
    return s;
  };

  const buildDomainIndex = () => {
    const map = new Map<string, { backend?: any; meta?: any; vt?: any; order: number }>();
    let order = 0;
    const visit = (d?: string) => {
      if (!d) return;
      if (!map.has(d)) map.set(d, { order: order++ });
    };
    for (const r of results) { visit(r?.domain); if (r?.domain) map.get(r.domain)!.backend = r; }
    for (const r of metascraperResults) { visit(r?.domain); if (r?.domain) map.get(r.domain)!.meta = r; }
    for (const r of virusTotalResults) { visit(r?.domain); if (r?.domain) map.get(r.domain)!.vt = r; }
    return Array.from(map.entries()).sort((a,b)=>a[1].order-b[1].order);
  };

  const exportToCsv = () => {
    if (results.length === 0) {
      toast({
        title: "No Data to Export",
        description: "Please run some scans first",
        variant: "destructive",
      });
      return;
    }

    const headers = [
      // Backend
      "domain","created","expires","domain_age","registrar","name_servers","dns_records","asn","abuse_score","is_vpn_proxy","ip_address","country","region","city","longitude","latitude","isp","timestamp",
      // Metascraper
      "ms_title","ms_description","ms_publisher","ms_type","ms_url","ms_lang","ms_author","ms_date","ms_category","ms_tags","ms_image","ms_favicon","ms_completeness",
      // VirusTotal
      "vt_risk_level","vt_reputation","vt_malicious","vt_suspicious","vt_harmless","vt_undetected","vt_votes_harmless","vt_votes_malicious","vt_categories"
    ];

    const domains = buildDomainIndex();
    const rows = domains.map(([, rec]) => {
      const b = rec.backend || {};
      const m = rec.meta || {};
      const v = rec.vt || {};
      const vtStats = v.last_analysis_stats || {};
      const vtVotes = v.total_votes || {};
      const vtCats = v.categories ? Object.entries(v.categories).map(([k, val]) => `${k}:${val}`).join("; ") : "-";
      const row = [
        b.domain,
        b.created,
        b.expires,
        b.domain_age,
        b.registrar,
        Array.isArray(b.name_servers) ? b.name_servers.join("; ") : b.name_servers,
        b.dns_records || "-",
        b.asn || "-",
        b.abuse_score,
        b.is_vpn_proxy,
        b.ip_address,
        b.country,
        b.region || "-",
        b.city || "-",
        b.longitude || "-",
        b.latitude || "-",
        b.isp,
        b.timestamp,
        // metascraper
        m.title,
        m.description,
        m.publisher,
        m.type,
        m.url,
        m.lang,
        m.author,
        m.date,
        m.category,
        Array.isArray(m.tags) ? m.tags.join("; ") : m.tags,
        m.image,
        m.favicon,
        m.completenessScore,
        // virustotal
        v.risk_level,
        v.reputation,
        vtStats.malicious,
        vtStats.suspicious,
        vtStats.harmless,
        vtStats.undetected,
        vtVotes.harmless,
        vtVotes.malicious,
        vtCats,
      ];
      return row.map(csvEscape).join(",");
    });

    const csvContent = [headers.join(","), ...rows].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `domain_intelligence_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);

    toast({
      title: "Export Complete",
      description: `Exported ${results.length} results to CSV`,
    });
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return "bg-gradient-to-r from-red-500 to-red-600";
    if (score >= 50) return "bg-gradient-to-r from-red-400 to-orange-500";
    if (score >= 25) return "bg-gradient-to-r from-yellow-400 to-orange-400";
    return "bg-gradient-to-r from-green-400 to-blue-500";
  };

  const getRiskBadgeColor = (score: number) => {
    if (score >= 75) return "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300";
    if (score >= 50) return "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300";
    if (score >= 25) return "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300";
    return "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300";
  };

  return (
  <Card className="h-fit border-0 shadow-lg bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg max-h-[350px] sm:max-h-[400px] overflow-y-auto">
  <CardHeader className="bg-gradient-to-r from-red-600/10 to-blue-600/10 border-b border-red-200/50 dark:border-blue-800/50 p-2 sm:p-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between space-y-3 sm:space-y-0">
          <CardTitle className="flex items-center space-x-2">
            <div className="p-2 bg-gradient-to-r from-red-600 to-blue-600 rounded-lg">
              <Database className="h-4 w-4 sm:h-5 sm:w-5 text-white" />
            </div>
            <span className="bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent text-lg sm:text-xl">Scan Results</span>
            <Badge className="bg-gradient-to-r from-blue-100 to-red-100 text-slate-700 dark:from-blue-950 dark:to-red-950 dark:text-slate-300 border-0">
              {results.length}
            </Badge>
          </CardTitle>
          {results.length > 0 && (
            <Button 
              onClick={exportToCsv} 
              size="sm" 
              variant="outline"
              className="border-red-200 dark:border-blue-800 hover:bg-gradient-to-r hover:from-red-50 hover:to-blue-50 dark:hover:from-red-950/50 dark:hover:to-blue-950/50 transition-all duration-300 hover:scale-105 w-full sm:w-auto"
            >
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>
          )}
        </div>
      </CardHeader>
  <CardContent className="p-2 sm:p-3">
        {results.length === 0 ? (
          <div className="text-center py-8 sm:py-12 text-slate-500 dark:text-slate-400">
            <div className="bg-gradient-to-r from-red-100 to-blue-100 dark:from-red-950/50 dark:to-blue-950/50 rounded-full w-16 h-16 sm:w-24 sm:h-24 mx-auto mb-4 flex items-center justify-center">
              <Database className="h-8 w-8 sm:h-12 sm:w-12 text-slate-400 dark:text-slate-600" />
            </div>
            <p className="text-base sm:text-lg font-medium mb-2">No results yet</p>
            <p className="text-sm">Start by analyzing a domain or running a bulk scan</p>
          </div>
        ) : (
          <div className="space-y-4 max-h-[400px] sm:max-h-[600px] overflow-y-auto">
            {results.map((result, index) => (
              <div 
                key={result.id} 
                className="border border-red-200/50 dark:border-blue-800/50 rounded-xl p-4 sm:p-6 space-y-4 bg-gradient-to-r from-white to-slate-50 dark:from-slate-900 dark:to-slate-800 hover:shadow-lg transition-all duration-500 hover:scale-[1.01] animate-fade-in"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between space-y-3 sm:space-y-0">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 bg-gradient-to-r from-blue-600 to-red-600 rounded-lg">
                      <Globe className="h-4 w-4 sm:h-5 sm:w-5 text-white" />
                    </div>
                    <h3 className="font-bold text-base sm:text-lg bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent break-all">{result.domain}</h3>
                    {result.is_vpn_proxy && (
                      <Badge className="bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border-0 text-xs hover:scale-105 transition-transform duration-300">
                        <Shield className="h-3 w-3 mr-1" />
                        VPN/Proxy
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className={`w-4 h-4 rounded-full ${getRiskColor(result.abuse_score)} shadow-lg`}></div>
                    <Badge className={`text-xs font-medium border-0 ${getRiskBadgeColor(result.abuse_score)}`}>
                      Risk: {result.abuse_score}/100
                    </Badge>
                  </div>
                </div>

                {/* Details Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-6 text-sm">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-950/30 rounded-lg hover:bg-red-100 dark:hover:bg-red-950/50 transition-colors duration-300">
                      <span className="font-medium text-slate-700 dark:text-slate-300">Age:</span>
                      <span className="text-red-600 dark:text-red-400 font-medium text-right">{result.domain_age}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-blue-50 dark:bg-blue-950/30 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-950/50 transition-colors duration-300">
                      <span className="font-medium text-slate-700 dark:text-slate-300">Registrar:</span>
                      <span className="text-blue-600 dark:text-blue-400 font-medium text-right break-all">{result.registrar}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-950/30 rounded-lg hover:bg-red-100 dark:hover:bg-red-950/50 transition-colors duration-300">
                      <span className="font-medium text-slate-700 dark:text-slate-300">Expires:</span>
                      <span className="text-red-600 dark:text-red-400 font-medium">{result.expires}</span>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 bg-blue-50 dark:bg-blue-950/30 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-950/50 transition-colors duration-300">
                      <span className="font-medium text-slate-700 dark:text-slate-300">IP:</span>
                      <span className="text-blue-600 dark:text-blue-400 font-medium font-mono text-xs sm:text-sm">{result.ip_address}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-red-50 dark:bg-red-950/30 rounded-lg hover:bg-red-100 dark:hover:bg-red-950/50 transition-colors duration-300">
                      <span className="font-medium text-slate-700 dark:text-slate-300">Country:</span>
                      <span className="text-red-600 dark:text-red-400 font-medium text-right">{result.country}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 bg-blue-50 dark:bg-blue-950/30 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-950/50 transition-colors duration-300">
                      <span className="font-medium text-slate-700 dark:text-slate-300">ISP:</span>
                      <span className="text-blue-600 dark:text-blue-400 font-medium text-right break-all">{result.isp}</span>
                    </div>
                  </div>
                </div>

                {/* Timestamp */}
                <div className="text-xs text-slate-500 dark:text-slate-400 border-t border-red-200/50 dark:border-blue-800/50 pt-3 bg-gradient-to-r from-red-50/50 to-blue-50/50 dark:from-red-950/20 dark:to-blue-950/20 rounded-lg p-2">
                  <span className="font-medium">Scanned:</span> {result.timestamp}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ResultsPanel;

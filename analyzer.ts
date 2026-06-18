// 1. Tip Güvenliği için Enum (Sabit Değerler) Tanımlama
enum SeverityLevel {
    LOW = "LOW",
    MEDIUM = "MEDIUM",
    HIGH = "HIGH",
    CRITICAL = "CRITICAL"
}

// 2. Interface Kullanarak Log Nesnesinin Şablonunu Sabitleme (Strict Typing)
interface SecurityLog {
    id: string;
    timestamp: string;
    sourceIp: string;
    eventCode: number;
    severity: SeverityLevel;
    message: string;
}

// 3. Tehdit Analiz Sonuç Şablonu
interface AnalysisResult {
    totalLogsParsed: number;
    criticalAlertsCount: number;
    flaggedIps: string[];
}

// Nesne Yönelimli (OOP) Güvenlik Analiz Sınıfı
class ThreatAnalyzer {
    private logs: SecurityLog[] = [];

    constructor(initialLogs: SecurityLog[]) {
        this.logs = initialLogs;
    }

    // Gelen logları analiz eden fonksiyon
    public auditLogs(): AnalysisResult {
        let criticalCount = 0;
        const maliciousIps: Set<string> = new Set();

        console.log("==================================================");
        console.log("       TYPESCRIPT SECURE LOG AUDIT PIPELINE       ");
        console.log("==================================================");

        this.logs.forEach((log) => {
            // Kritik veya Yüksek tehditleri tespit etme
            if (log.severity === SeverityLevel.CRITICAL || log.severity === SeverityLevel.HIGH) {
                criticalCount++;
                maliciousIps.add(log.sourceIp);
                
                console.log(`[🚨 THREAT TRIGGERED] ID: ${log.id} | Severity: ${log.severity}`);
                console.log(`  └─ Origin IP : ${log.sourceIp}`);
                console.log(`  └─ Message   : ${log.message}\n`);
            }
        });

        return {
            totalLogsParsed: this.logs.length,
            criticalAlertsCount: criticalCount,
            flaggedIps: Array.from(maliciousIps)
        };
    }
}

// --- Test Senaryosu İçin Örnek Mock Log Verisi ---
const serverLogs: SecurityLog[] = [
    {
        id: "LOG-001",
        timestamp: "2026-03-30T10:14:00Z",
        sourceIp: "192.168.1.105",
        eventCode: 4624, // Başarılı Oturum Açma
        severity: SeverityLevel.LOW,
        message: "User 'admin' logged in successfully."
    },
    {
        id: "LOG-002",
        timestamp: "2026-03-30T10:14:22Z",
        sourceIp: "45.227.254.12", // Şüpheli Dış IP
        eventCode: 4625, // Başarısız Oturum Açma
        severity: SeverityLevel.CRITICAL,
        message: "SQL Injection pattern detected in login form parameters."
    },
    {
        id: "LOG-003",
        timestamp: "2026-03-30T10:15:01Z",
        sourceIp: "10.0.0.5",
        eventCode: 1102, // Logların Silinmesi Denemesi
        severity: SeverityLevel.HIGH,
        message: "Audit log clearance command executed by unauthorized sub-process."
    }
];

// Analizörü Başlat
const analyzer = new ThreatAnalyzer(serverLogs);
const report = analyzer.auditLogs();

console.log("--------------------------------------------------");
console.log("                FINAL AUDIT REPORT                ");
console.log("--------------------------------------------------");
console.log(`[+] Total Logs Processed : ${report.totalLogsParsed}`);
console.log(`[+] High/Critical Alerts : ${report.criticalAlertsCount}`);
console.log(`[+] Banned Malicious IPs :`, report.flaggedIps);
console.log("--------------------------------------------------");

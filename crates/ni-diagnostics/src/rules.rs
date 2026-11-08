use crate::{Rule, RuleInfo, RuleStatus, SessionEvidence};
use ni_core::addr::{self, Family, Scope};
use ni_core::endpoint::{Protocol, TcpState};
use ni_core::finding::{
    Category, Confidence, Evidence, Finding, Hypothesis, Observation, Severity,
};
use ni_core::probe::{DnsOutcome, DnsResult, ProbeReport, TcpOutcome, UdpOutcome};
use ni_core::source::DataSource;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub fn implemented() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(CoverageRule),
        Box::new(HandshakeStalled),
        Box::new(ProbeTcp),
        Box::new(ProbeDns),
        Box::new(DnsSpecialAnswers),
        Box::new(ProbeFamilyDifference),
        Box::new(ProbeUdp),
        Box::new(AppVsProbe),
    ]
}

pub fn planned() -> Vec<RuleInfo> {
    let p = |id, category, title, requires| RuleInfo {
        id,
        category,
        title,
        status: RuleStatus::Planned,
        requires,
    };
    vec![
        p(
            "tcp.reset_anomaly",
            Category::TcpReset,
            "Аномальные TCP RST после установления соединения",
            &["etw", "wfp"],
        ),
        p(
            "tls.handshake_disruption",
            Category::TlsHandshake,
            "Обрыв TLS-рукопожатия после ClientHello",
            &["etw", "active_probe_tls"],
        ),
        p(
            "sni.filtering",
            Category::SniFiltering,
            "Различие исходов при разных SNI к одному IP",
            &["active_probe_tls"],
        ),
        p(
            "ip.filtering",
            Category::IpFiltering,
            "Недоступность конкретных IP при доступности соседних",
            &["active_probe", "control_network"],
        ),
        p(
            "udp.response_anomaly",
            Category::Udp,
            "Аномалии ответов UDP (QUIC, голос)",
            &["etw", "wfp"],
        ),
        p(
            "throttling",
            Category::Throttling,
            "Признаки ограничения скорости",
            &["etw_tcp_estats"],
        ),
    ]
}

fn obs(text: impl Into<String>, confidence: Confidence, source: DataSource) -> Observation {
    Observation {
        text: text.into(),
        confidence,
        source,
    }
}

fn hyp(text: impl Into<String>, confidence: Confidence) -> Hypothesis {
    Hypothesis {
        text: text.into(),
        confidence,
    }
}

fn sock(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V6(_) => format!("[{ip}]:{port}"),
        IpAddr::V4(_) => format!("{ip}:{port}"),
    }
}

const SNAPSHOT_LIMIT: &str =
    "Вывод основан на периодических снимках таблицы сокетов, без захвата пакетов.";

// ---------------------------------------------------------------------------

struct CoverageRule;

impl Rule for CoverageRule {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "observability.coverage",
            category: Category::Observability,
            title: "Охват наблюдения",
            status: RuleStatus::Implemented,
            requires: &["system_snapshot"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let c = ev.coverage;
        let mut observations = vec![obs(
            format!(
                "Источник «{}», интервал опроса {} мс: успешных снимков {}, неудачных {}, наибольший промежуток {} мс.",
                c.provider, c.poll_interval_ms, c.snapshots_ok, c.snapshots_failed, c.max_gap_ms
            ),
            Confidence::High,
            DataSource::SystemSnapshot,
        )];
        let mut severity = Severity::Info;
        if c.snapshots_ok == 0 {
            severity = Severity::Problem;
            observations.push(obs(
                format!(
                    "Ни одного успешного снимка. Последняя ошибка: {}",
                    c.last_error.as_deref().unwrap_or("нет данных")
                ),
                Confidence::High,
                DataSource::SystemSnapshot,
            ));
        } else if c.snapshots_failed > 0 {
            severity = Severity::Notice;
        }
        if c.pid_only_identities > 0 {
            severity = severity.max(Severity::Notice);
            observations.push(obs(
                format!(
                    "У {} отслеживаемых процессов не удалось прочитать время создания: идентичность только по PID, повторное использование PID нельзя исключить.",
                    c.pid_only_identities
                ),
                Confidence::High,
                DataSource::SystemSnapshot,
            ));
        }
        if c.max_gap_ms > c.poll_interval_ms.saturating_mul(3) && c.poll_interval_ms > 0 {
            observations.push(obs(
                format!("Промежуток между снимками доходил до {} мс — короткие соединения в это время могли быть пропущены.", c.max_gap_ms),
                Confidence::High,
                DataSource::SystemSnapshot,
            ));
        }
        vec![Finding {
            id: "observability.coverage:session".into(),
            rule: "observability.coverage".into(),
            category: Category::Observability,
            severity,
            title: "Что удалось и что не удалось наблюдать".into(),
            observations,
            evidence: vec![],
            hypotheses: vec![],
            alternative_explanations: vec![],
            confidence: Confidence::High,
            limitations: c.limitations.clone(),
            suggested_checks: vec![
                "Для более полного охвата уменьшите интервал опроса и воспроизведите проблему повторно.".into(),
                "Запуск от имени администратора позволяет прочитать время создания защищённых процессов.".into(),
            ],
        }]
    }
}

// ---------------------------------------------------------------------------

/// TCP endpoints of the application seen in SYN_SENT across several
/// snapshots without ever completing the handshake.
struct HandshakeStalled;

const STALL_MIN_MS: i64 = 3000;

impl Rule for HandshakeStalled {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "tcp.handshake_stalled",
            category: Category::TcpHandshake,
            title: "TCP-рукопожатие приложения не завершается",
            status: RuleStatus::Implemented,
            requires: &["observed_process"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let mut by_target: BTreeMap<(String, u16), Vec<&ni_core::endpoint::EndpointRecord>> =
            BTreeMap::new();
        for e in ev.endpoints {
            if e.key.protocol != Protocol::Tcp {
                continue;
            }
            let (Some(ip), Some(port)) = (e.key.remote_addr, e.key.remote_port) else {
                continue;
            };
            let never_connected = !e
                .states_seen
                .iter()
                .any(|s| s.implies_handshake_completed());
            let syn = e.states_seen.contains(&TcpState::SynSent);
            let in_syn_ms = e.last_seen - e.first_seen;
            if syn && never_connected && e.observations >= 2 && in_syn_ms >= STALL_MIN_MS {
                by_target.entry((ip.to_string(), port)).or_default().push(e);
            }
        }
        by_target
            .into_iter()
            .map(|((ip, port), eps)| {
                let ipa: IpAddr = ip.parse().expect("from IpAddr");
                let longest = eps.iter().map(|e| e.last_seen - e.first_seen).max().unwrap_or(0);
                let attempts: u32 = eps.iter().map(|e| e.episodes).sum();
                let v6 = Family::of(&ipa) == Family::Ipv6;
                let mut alternatives = vec![
                    "Сервер недоступен, перегружен или не слушает этот порт без отправки RST.".to_string(),
                    "Локальный брандмауэр или антивирус блокирует исходящие пакеты приложения.".to_string(),
                    "Проблема маршрутизации, VPN или прокси-клиента.".to_string(),
                ];
                if v6 {
                    alternatives.push("Нет рабочей IPv6-связности: адрес получен, но маршрута нет.".into());
                }
                Finding {
                    id: format!("tcp.handshake_stalled:{}", sock(&ipa, port)),
                    rule: "tcp.handshake_stalled".into(),
                    category: Category::TcpHandshake,
                    severity: Severity::Warning,
                    title: format!("Соединение с {} не устанавливается", sock(&ipa, port)),
                    observations: vec![obs(
                        format!(
                            "Сокет(ы) приложения к {} наблюдались только в состоянии SYN_SENT: {} попыт., дольше всего {:.1} с; ESTABLISHED не наблюдалось.",
                            sock(&ipa, port),
                            attempts,
                            longest as f64 / 1000.0
                        ),
                        Confidence::High,
                        DataSource::ObservedProcess,
                    )],
                    evidence: eps.iter().map(|e| Evidence::Endpoint { endpoint_id: e.id }).collect(),
                    hypotheses: vec![
                        hyp("Ответ SYN-ACK не доходит до компьютера (сервер не отвечает или пакеты теряются по пути).", Confidence::Low),
                        hyp("Фильтрация на пути (по IP или иная, включая возможную DPI). Одного тайм-аута рукопожатия недостаточно, чтобы это утверждать.", Confidence::VeryLow),
                    ],
                    alternative_explanations: alternatives,
                    confidence: Confidence::Low,
                    limitations: vec![
                        SNAPSHOT_LIMIT.into(),
                        "Неизвестно, отправлялись ли повторные SYN и приходили ли ICMP-сообщения.".into(),
                    ],
                    suggested_checks: vec![
                        format!("Выполните TCP-проверку {} в разделе «Диагностика» и сравните результат.", sock(&ipa, port)),
                        "Проверьте другие IP-адреса того же домена и тот же адрес из другой сети.".into(),
                        "Проверьте правила брандмауэра для этого приложения.".into(),
                    ],
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------

struct ProbeTcp;

impl Rule for ProbeTcp {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "probe.tcp_result",
            category: Category::TcpHandshake,
            title: "Результаты TCP-проверок",
            status: RuleStatus::Implemented,
            requires: &["active_probe"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for p in ev.probes {
            let ProbeReport::Tcp {
                target, attempts, ..
            } = &p.report
            else {
                continue;
            };
            for a in attempts {
                let s = sock(&a.addr, a.port);
                let base = |sev,
                            title: String,
                            o: String,
                            hyps: Vec<Hypothesis>,
                            alts: Vec<String>,
                            conf| {
                    Finding {
                    id: format!("probe.tcp_result:{}:{}", p.id, s),
                    rule: "probe.tcp_result".into(),
                    category: Category::TcpHandshake,
                    severity: sev,
                    title,
                    observations: vec![obs(o, Confidence::High, DataSource::ActiveProbe)],
                    evidence: vec![Evidence::Probe { probe_id: p.id.clone() }],
                    hypotheses: hyps,
                    alternative_explanations: alts,
                    confidence: conf,
                    limitations: vec![
                        "Проверку выполнил Network Intelligence, а не анализируемое приложение; результат не означает, что приложение получило тот же исход.".into(),
                    ],
                    suggested_checks: vec![],
                }
                };
                match &a.outcome {
                    TcpOutcome::Connected { .. } => {}
                    TcpOutcome::Refused { error, .. } => out.push(base(
                        Severity::Notice,
                        format!("{s}: соединение отклонено"),
                        format!("TCP-проверка {target} → {s}: отказ ({}).", error.name.as_deref().unwrap_or(&error.message)),
                        vec![hyp("На этом адресе и порту нет слушающей службы, либо узел отвечает RST.", Confidence::Medium)],
                        vec![
                            "Неверный порт или служба остановлена.".into(),
                            "RST может отправить брандмауэр на пути; по одному отказу источник RST не определить.".into(),
                        ],
                        Confidence::Medium,
                    )),
                    TcpOutcome::TimedOut { timeout_ms } => out.push(base(
                        Severity::Warning,
                        format!("{s}: нет ответа за {timeout_ms} мс"),
                        format!("TCP-проверка {target} → {s}: рукопожатие не завершилось за {timeout_ms} мс."),
                        vec![
                            hyp("Узел не отвечает или пакеты теряются по пути.", Confidence::Low),
                            hyp("Фильтрация на пути (в том числе возможная DPI или блокировка по IP). Тайм-аут сам по себе этого не доказывает.", Confidence::VeryLow),
                        ],
                        vec!["Сервер выключен или перегружен.".into(), "Локальный брандмауэр.".into(), "Слишком короткий тайм-аут для этой сети.".into()],
                        Confidence::Low,
                    )),
                    TcpOutcome::Unreachable { error, .. } => out.push(base(
                        Severity::Warning,
                        format!("{s}: адрес недоступен"),
                        format!("TCP-проверка {target} → {s}: {}.", error.name.as_deref().unwrap_or(&error.message)),
                        vec![hyp("Нет маршрута до сети или узла (локально или по ICMP-ответу).", Confidence::Medium)],
                        vec!["Отключён сетевой адаптер или VPN.".into(), "Нет IPv6-маршрута для IPv6-адреса.".into()],
                        Confidence::Medium,
                    )),
                    TcpOutcome::Failed { error, .. } => out.push(base(
                        Severity::Notice,
                        format!("{s}: ошибка проверки"),
                        format!("TCP-проверка {target} → {s}: {}.", error.message),
                        vec![],
                        vec!["Ошибка локального сетевого стека или прав доступа.".into()],
                        Confidence::VeryLow,
                    )),
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------

fn dns_of(p: &ProbeReport) -> Option<&DnsResult> {
    match p {
        ProbeReport::Dns(d) => Some(d),
        ProbeReport::Tcp { dns, .. } | ProbeReport::Udp { dns, .. } => dns.as_ref(),
    }
}

struct ProbeDns;

impl Rule for ProbeDns {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "probe.dns_failure",
            category: Category::Dns,
            title: "Имя не разрешается системным резолвером",
            status: RuleStatus::Implemented,
            requires: &["active_probe"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        ev.probes
            .iter()
            .filter_map(|p| dns_of(&p.report).map(|d| (p, d)))
            .filter_map(|(p, d)| {
                let (o, sev) = match &d.outcome {
                    DnsOutcome::Resolved { ipv4, ipv6 } if ipv4.is_empty() && ipv6.is_empty() => {
                        ("Резолвер вернул пустой ответ.".to_string(), Severity::Warning)
                    }
                    DnsOutcome::Resolved { .. } => return None,
                    DnsOutcome::Failed { error } => (format!("Ошибка резолвера: {}.", error.message), Severity::Warning),
                    DnsOutcome::TimedOut { timeout_ms } => (format!("Нет ответа за {timeout_ms} мс."), Severity::Warning),
                };
                Some(Finding {
                    id: format!("probe.dns_failure:{}:{}", p.id, d.name),
                    rule: "probe.dns_failure".into(),
                    category: Category::Dns,
                    severity: sev,
                    title: format!("{}: имя не разрешено", d.name),
                    observations: vec![obs(format!("Системный резолвер, {}: {o}", d.name), Confidence::High, DataSource::ActiveProbe)],
                    evidence: vec![Evidence::Probe { probe_id: p.id.clone() }],
                    hypotheses: vec![
                        hyp("Имя не существует или введено с ошибкой.", Confidence::Low),
                        hyp("Настроенный DNS-сервер недоступен или не отвечает.", Confidence::Low),
                        hyp("DNS-фильтрация (провайдер, родительский контроль, блокировщик).", Confidence::VeryLow),
                    ],
                    alternative_explanations: vec!["Нет подключения к сети.".into(), "Временный сбой DNS-сервера.".into()],
                    confidence: Confidence::Low,
                    limitations: vec!["Используется системный резолвер (getaddrinfo): неизвестно, какой сервер ответил и был ли ответ из кэша.".into()],
                    suggested_checks: vec!["Повторите проверку; сравните с другим DNS-сервером или другой сетью.".into()],
                })
            })
            .collect()
    }
}

/// Public names resolving to addresses that cannot be the real service:
/// unspecified, loopback, private, link-local or documentation ranges.
struct DnsSpecialAnswers;

impl Rule for DnsSpecialAnswers {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "dns.special_answer",
            category: Category::Dns,
            title: "Публичное имя разрешается в служебный адрес",
            status: RuleStatus::Implemented,
            requires: &["active_probe"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for p in ev.probes {
            let Some(d) = dns_of(&p.report) else { continue };
            if d.name == "localhost"
                || d.name.ends_with(".localhost")
                || d.name.ends_with(".local")
                || !d.name.contains('.')
            {
                continue;
            }
            let DnsOutcome::Resolved { ipv4, ipv6 } = &d.outcome else {
                continue;
            };
            let special: Vec<String> = ipv4
                .iter()
                .chain(ipv6.iter())
                .filter(|a| {
                    matches!(
                        addr::scope(a),
                        Scope::Unspecified
                            | Scope::Loopback
                            | Scope::Private
                            | Scope::LinkLocal
                            | Scope::Documentation
                    )
                })
                .map(|a| a.to_string())
                .collect();
            if special.is_empty() {
                continue;
            }
            out.push(Finding {
                id: format!("dns.special_answer:{}:{}", p.id, d.name),
                rule: "dns.special_answer".into(),
                category: Category::Dns,
                severity: Severity::Warning,
                title: format!("{} разрешается в служебный адрес", d.name),
                observations: vec![obs(
                    format!("Системный резолвер вернул для {}: {}.", d.name, special.join(", ")),
                    Confidence::High,
                    DataSource::ActiveProbe,
                )],
                evidence: vec![Evidence::Probe { probe_id: p.id.clone() }],
                hypotheses: vec![
                    hyp("Запись в файле hosts или локальный DNS-фильтр (блокировщик рекламы, родительский контроль).", Confidence::Medium),
                    hyp("DNS-фильтрация на стороне провайдера или сети, подменяющая ответ.", Confidence::Low),
                ],
                alternative_explanations: vec![
                    "Корпоративный/домашний split-DNS, где имя действительно указывает на внутренний адрес.".into(),
                    "Ошибка конфигурации DNS-зоны владельца домена.".into(),
                ],
                confidence: Confidence::Low,
                limitations: vec!["Ответ получен через системный резолвер; источник ответа (hosts, кэш, сервер) не известен.".into()],
                suggested_checks: vec![
                    r"Проверьте C:\Windows\System32\drivers\etc\hosts.".into(),
                    "Сравните с ответом другого DNS-сервера (например, через DoH в браузере).".into(),
                ],
            });
        }
        out
    }
}

// ---------------------------------------------------------------------------

/// Same target and port: IPv4 connects but IPv6 does not (or vice versa).
struct ProbeFamilyDifference;

impl Rule for ProbeFamilyDifference {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "probe.family_difference",
            category: Category::ControlComparison,
            title: "Разный исход для IPv4 и IPv6",
            status: RuleStatus::Implemented,
            requires: &["active_probe"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for p in ev.probes {
            let ProbeReport::Tcp {
                target, attempts, ..
            } = &p.report
            else {
                continue;
            };
            let ok = |f: Family| {
                attempts
                    .iter()
                    .any(|a| a.family == f && matches!(a.outcome, TcpOutcome::Connected { .. }))
            };
            let failed = |f: Family| {
                attempts.iter().any(|a| a.family == f)
                    && !attempts
                        .iter()
                        .any(|a| a.family == f && matches!(a.outcome, TcpOutcome::Connected { .. }))
            };
            for (good, bad, name_good, name_bad) in [
                (Family::Ipv4, Family::Ipv6, "IPv4", "IPv6"),
                (Family::Ipv6, Family::Ipv4, "IPv6", "IPv4"),
            ] {
                if ok(good) && failed(bad) {
                    out.push(Finding {
                        id: format!("probe.family_difference:{}:{}", p.id, name_bad),
                        rule: "probe.family_difference".into(),
                        category: Category::ControlComparison,
                        severity: Severity::Notice,
                        title: format!("{target}: {name_good} работает, {name_bad} — нет"),
                        observations: vec![obs(
                            format!("TCP-проверка {target}: соединение по {name_good} установлено, по {name_bad} — нет ни с одним адресом."),
                            Confidence::High,
                            DataSource::ActiveProbe,
                        )],
                        evidence: vec![Evidence::Probe { probe_id: p.id.clone() }],
                        hypotheses: vec![hyp(format!("Проблема {name_bad}-связности в вашей сети или у провайдера."), Confidence::Medium)],
                        alternative_explanations: vec![
                            format!("Сервис не обслуживает {name_bad} на этом порту."),
                            "Различная фильтрация для разных семейств адресов.".into(),
                        ],
                        confidence: Confidence::Low,
                        limitations: vec!["Проверку выполнил Network Intelligence, а не приложение.".into()],
                        suggested_checks: vec![format!(
                            "Приложения, выбирающие {name_bad} первым, могут долго ждать перед переключением; проверьте настройки {name_bad} адаптера."
                        )],
                    });
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------

struct ProbeUdp;

impl Rule for ProbeUdp {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "probe.udp_result",
            category: Category::Udp,
            title: "Результаты UDP-проверок",
            status: RuleStatus::Implemented,
            requires: &["active_probe"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for p in ev.probes {
            let ProbeReport::Udp {
                target, attempts, ..
            } = &p.report
            else {
                continue;
            };
            for a in attempts {
                let s = sock(&a.addr, a.port);
                let (sev, title, o, hyps, conf) = match &a.outcome {
                    UdpOutcome::Reply { .. } => continue,
                    UdpOutcome::NoReply { timeout_ms } => (
                        Severity::Info,
                        format!("{s}: нет UDP-ответа"),
                        format!("UDP-проверка {target} → {s}: ответ не получен за {timeout_ms} мс."),
                        vec![
                            hyp("Служба не отвечает на такой запрос (многие UDP-службы молчат на неожиданные датаграммы).", Confidence::Medium),
                            hyp("Пакеты теряются или фильтруются по пути. Отсутствие ответа этого не доказывает.", Confidence::VeryLow),
                        ],
                        Confidence::VeryLow,
                    ),
                    UdpOutcome::PortUnreachable { .. } => (
                        Severity::Notice,
                        format!("{s}: порт UDP закрыт"),
                        format!("UDP-проверка {target} → {s}: получено ICMP «порт недоступен»."),
                        vec![hyp("На этом порту нет службы.", Confidence::Medium)],
                        Confidence::Medium,
                    ),
                    UdpOutcome::Failed { error } => (
                        Severity::Notice,
                        format!("{s}: ошибка UDP-проверки"),
                        format!("UDP-проверка {target} → {s}: {}.", error.message),
                        vec![],
                        Confidence::VeryLow,
                    ),
                };
                out.push(Finding {
                    id: format!("probe.udp_result:{}:{}", p.id, s),
                    rule: "probe.udp_result".into(),
                    category: Category::Udp,
                    severity: sev,
                    title,
                    observations: vec![obs(o, Confidence::High, DataSource::ActiveProbe)],
                    evidence: vec![Evidence::Probe { probe_id: p.id.clone() }],
                    hypotheses: hyps,
                    alternative_explanations: vec!["Неподходящее содержимое запроса для этой службы.".into()],
                    confidence: conf,
                    limitations: vec![
                        "UDP не устанавливает соединение: молчание и потеря пакета неразличимы.".into(),
                        "Проверку выполнил Network Intelligence, а не приложение.".into(),
                    ],
                    suggested_checks: vec!["Используйте запрос, на который служба должна ответить (DNS-запрос для порта 53, STUN для голосовых серверов).".into()],
                });
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------

/// The application's handshake to ip:port stalled, but a probe from Network
/// Intelligence to the same ip:port in the same session connected.
struct AppVsProbe;

impl Rule for AppVsProbe {
    fn info(&self) -> RuleInfo {
        RuleInfo {
            id: "compare.app_vs_probe",
            category: Category::ControlComparison,
            title: "Приложение не подключается, контрольная проверка подключается",
            status: RuleStatus::Implemented,
            requires: &["observed_process", "active_probe"],
        }
    }
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding> {
        let stalled = HandshakeStalled.evaluate(ev);
        let mut out = Vec::new();
        for f in &stalled {
            let Some(key) = f.id.strip_prefix("tcp.handshake_stalled:") else {
                continue;
            };
            for p in ev.probes {
                let ProbeReport::Tcp { attempts, .. } = &p.report else {
                    continue;
                };
                if attempts.iter().any(|a| {
                    sock(&a.addr, a.port) == key
                        && matches!(a.outcome, TcpOutcome::Connected { .. })
                }) {
                    out.push(Finding {
                        id: format!("compare.app_vs_probe:{key}:{}", p.id),
                        rule: "compare.app_vs_probe".into(),
                        category: Category::ControlComparison,
                        severity: Severity::Warning,
                        title: format!("{key}: приложение не подключилось, контрольная проверка подключилась"),
                        observations: vec![
                            obs(format!("Сокеты приложения к {key} оставались в SYN_SENT."), Confidence::High, DataSource::ObservedProcess),
                            obs(format!("TCP-проверка Network Intelligence к {key} установила соединение."), Confidence::High, DataSource::ActiveProbe),
                        ],
                        evidence: f.evidence.iter().cloned().chain([Evidence::Probe { probe_id: p.id.clone() }]).collect(),
                        hypotheses: vec![
                            hyp("Проблема была временной и прошла к моменту проверки.", Confidence::Low),
                            hyp("Трафик именно этого приложения обрабатывается иначе (правило брандмауэра, прокси, VPN с раздельным туннелированием).", Confidence::Low),
                        ],
                        alternative_explanations: vec![
                            "Проверка и попытки приложения выполнялись в разное время.".into(),
                            "Блокировка только по IP маловероятна, раз контрольное соединение к тому же адресу и порту прошло, но фильтрация по содержимому (например, SNI) не исключена.".into(),
                        ],
                        confidence: Confidence::VeryLow,
                        limitations: vec![SNAPSHOT_LIMIT.into(), "Контрольная проверка не отправляет данных (нет TLS), поэтому фильтрацию по содержимому она не выявляет.".into()],
                        suggested_checks: vec!["Повторите проверку в момент воспроизведения проблемы и поставьте маркер.".into()],
                    });
                }
            }
        }
        out
    }
}

// Package registry — catalog.go registers all available blackhorn-modules into
// the global registry at program startup. The Blackhorn orchestrator can then
// call registry.All(), registry.ByCategory(), registry.ForInput(), etc. without
// importing every module package individually.
//
// This file is the ONLY place that imports concrete module packages. All other
// callers use the registry interface (factory pattern).
//
// To add a new module: add one Register() call in init() following the pattern.
package registry

import (
	"github.com/DonatoReis/blackhorn-modules/modules/addresssearch"
	"github.com/DonatoReis/blackhorn-modules/modules/alterx"
	"github.com/DonatoReis/blackhorn-modules/modules/anatel"
	"github.com/DonatoReis/blackhorn-modules/modules/apiaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/apkosint"
	"github.com/DonatoReis/blackhorn-modules/modules/asnmap"
	"github.com/DonatoReis/blackhorn-modules/modules/bgpinfo"
	"github.com/DonatoReis/blackhorn-modules/modules/brandmon"
	"github.com/DonatoReis/blackhorn-modules/modules/brazilinfo"
	"github.com/DonatoReis/blackhorn-modules/modules/bypass403"
	"github.com/DonatoReis/blackhorn-modules/modules/cacheprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/cdncheck"
	"github.com/DonatoReis/blackhorn-modules/modules/certs"
	"github.com/DonatoReis/blackhorn-modules/modules/clickjacking"
	"github.com/DonatoReis/blackhorn-modules/modules/cloudlist"
	"github.com/DonatoReis/blackhorn-modules/modules/cloudosint"
	"github.com/DonatoReis/blackhorn-modules/modules/cmdi"
	"github.com/DonatoReis/blackhorn-modules/modules/companyosint"
	"github.com/DonatoReis/blackhorn-modules/modules/cors2"
	"github.com/DonatoReis/blackhorn-modules/modules/corsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/cpflookup"
	"github.com/DonatoReis/blackhorn-modules/modules/crawler"
	"github.com/DonatoReis/blackhorn-modules/modules/credleak"
	"github.com/DonatoReis/blackhorn-modules/modules/credstuffing"
	"github.com/DonatoReis/blackhorn-modules/modules/crlf"
	"github.com/DonatoReis/blackhorn-modules/modules/darkweb"
	"github.com/DonatoReis/blackhorn-modules/modules/dehashed"
	"github.com/DonatoReis/blackhorn-modules/modules/deserial"
	"github.com/DonatoReis/blackhorn-modules/modules/dnsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/dnsprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/dnsrecon"
	"github.com/DonatoReis/blackhorn-modules/modules/emailosint"
	"github.com/DonatoReis/blackhorn-modules/modules/emailspoof"
	"github.com/DonatoReis/blackhorn-modules/modules/emailverify"
	"github.com/DonatoReis/blackhorn-modules/modules/ffuf"
	"github.com/DonatoReis/blackhorn-modules/modules/fingerprint"
	"github.com/DonatoReis/blackhorn-modules/modules/gau"
	"github.com/DonatoReis/blackhorn-modules/modules/gitdorker"
	"github.com/DonatoReis/blackhorn-modules/modules/githistory"
	"github.com/DonatoReis/blackhorn-modules/modules/googledork"
	"github.com/DonatoReis/blackhorn-modules/modules/govbr"
	"github.com/DonatoReis/blackhorn-modules/modules/graphql"
	"github.com/DonatoReis/blackhorn-modules/modules/headeraudit"
	"github.com/DonatoReis/blackhorn-modules/modules/hibp"
	"github.com/DonatoReis/blackhorn-modules/modules/hostinjection"
	"github.com/DonatoReis/blackhorn-modules/modules/httpxpro"
	"github.com/DonatoReis/blackhorn-modules/modules/idor"
	"github.com/DonatoReis/blackhorn-modules/modules/interactsh"
	"github.com/DonatoReis/blackhorn-modules/modules/ipgeolocation"
	"github.com/DonatoReis/blackhorn-modules/modules/ipintel"
	"github.com/DonatoReis/blackhorn-modules/modules/jwt"
	"github.com/DonatoReis/blackhorn-modules/modules/jwtaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/katana"
	"github.com/DonatoReis/blackhorn-modules/modules/leakosint"
	"github.com/DonatoReis/blackhorn-modules/modules/lfi"
	"github.com/DonatoReis/blackhorn-modules/modules/mapcidr"
	"github.com/DonatoReis/blackhorn-modules/modules/metadata"
	"github.com/DonatoReis/blackhorn-modules/modules/namesearch"
	"github.com/DonatoReis/blackhorn-modules/modules/netmon"
	"github.com/DonatoReis/blackhorn-modules/modules/nosqli"
	"github.com/DonatoReis/blackhorn-modules/modules/notify"
	"github.com/DonatoReis/blackhorn-modules/modules/oauth2"
	"github.com/DonatoReis/blackhorn-modules/modules/oauthprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/openredirect"
	"github.com/DonatoReis/blackhorn-modules/modules/osintbr"
	"github.com/DonatoReis/blackhorn-modules/modules/osintleak"
	"github.com/DonatoReis/blackhorn-modules/modules/paramdisc"
	"github.com/DonatoReis/blackhorn-modules/modules/paramspider"
	"github.com/DonatoReis/blackhorn-modules/modules/pastebin"
	"github.com/DonatoReis/blackhorn-modules/modules/pathprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/phonelookup"
	"github.com/DonatoReis/blackhorn-modules/modules/portscanner"
	"github.com/DonatoReis/blackhorn-modules/modules/prototype"
	"github.com/DonatoReis/blackhorn-modules/modules/proxify"
	"github.com/DonatoReis/blackhorn-modules/modules/ratelimit"
	"github.com/DonatoReis/blackhorn-modules/modules/recon"
	"github.com/DonatoReis/blackhorn-modules/modules/registroempresas"
	"github.com/DonatoReis/blackhorn-modules/modules/repochecker"
	"github.com/DonatoReis/blackhorn-modules/modules/s3enum"
	"github.com/DonatoReis/blackhorn-modules/modules/secretscan"
	"github.com/DonatoReis/blackhorn-modules/modules/sherlock"
	"github.com/DonatoReis/blackhorn-modules/modules/shodanwatch"
	"github.com/DonatoReis/blackhorn-modules/modules/shuffledns"
	"github.com/DonatoReis/blackhorn-modules/modules/smuggler"
	"github.com/DonatoReis/blackhorn-modules/modules/smuggling"
	"github.com/DonatoReis/blackhorn-modules/modules/socialmedia"
	"github.com/DonatoReis/blackhorn-modules/modules/socialscan"
	"github.com/DonatoReis/blackhorn-modules/modules/soft404"
	"github.com/DonatoReis/blackhorn-modules/modules/sqli"
	"github.com/DonatoReis/blackhorn-modules/modules/sslcheck"
	"github.com/DonatoReis/blackhorn-modules/modules/ssrfprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/ssti"
	"github.com/DonatoReis/blackhorn-modules/modules/sstiprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/subdiscovery"
	"github.com/DonatoReis/blackhorn-modules/modules/swaggerfuzz"
	"github.com/DonatoReis/blackhorn-modules/modules/takeover"
	"github.com/DonatoReis/blackhorn-modules/modules/telegramosint"
	"github.com/DonatoReis/blackhorn-modules/modules/threatintel"
	"github.com/DonatoReis/blackhorn-modules/modules/tlsaudit"
	"github.com/DonatoReis/blackhorn-modules/modules/tlsfinder"
	"github.com/DonatoReis/blackhorn-modules/modules/tribunais"
	"github.com/DonatoReis/blackhorn-modules/modules/truffler"
	"github.com/DonatoReis/blackhorn-modules/modules/udpprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/uncover"
	"github.com/DonatoReis/blackhorn-modules/modules/urldedup"
	"github.com/DonatoReis/blackhorn-modules/modules/urlfinder"
	"github.com/DonatoReis/blackhorn-modules/modules/urlparse"
	"github.com/DonatoReis/blackhorn-modules/modules/userlookup"
	"github.com/DonatoReis/blackhorn-modules/modules/verbtamper"
	"github.com/DonatoReis/blackhorn-modules/modules/vulndb"
	"github.com/DonatoReis/blackhorn-modules/modules/vulnscan"
	"github.com/DonatoReis/blackhorn-modules/modules/vulnx"
	"github.com/DonatoReis/blackhorn-modules/modules/wafscan"
	"github.com/DonatoReis/blackhorn-modules/modules/wayback"
	"github.com/DonatoReis/blackhorn-modules/modules/webdav"
	"github.com/DonatoReis/blackhorn-modules/modules/webprobe"
	"github.com/DonatoReis/blackhorn-modules/modules/whatsapp"
	"github.com/DonatoReis/blackhorn-modules/modules/whois"
	"github.com/DonatoReis/blackhorn-modules/modules/wifite2"
	"github.com/DonatoReis/blackhorn-modules/modules/xssreflect"
	"github.com/DonatoReis/blackhorn-modules/modules/xssscan"
	"github.com/DonatoReis/blackhorn-modules/modules/xxeprobe"
	"github.com/DonatoReis/blackhorn-modules/pkg/module"
)

func init() {
	// ── OSINT Brasil ──────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "addresssearch", Category: CategoryOSINTBrasil,
		Description: "CEP, logradouro e coordenadas via BrasilAPI, ViaCEP, Nominatim e IBGE",
		InputTypes:  []string{"cep", "address", "domain"},
		OutputTypes: []string{"address_found", "coordinates", "neighborhood"},
		Factory:     func() module.Module { return addresssearch.New() },
	})
	Register(&Meta{
		Name: "anatel", Category: CategoryOSINTBrasil,
		Description: "Informações de DDD, portabilidade e operadora via ANATEL e BrasilAPI",
		InputTypes:  []string{"phone"},
		OutputTypes: []string{"phone_info", "carrier", "portability"},
		Factory:     func() module.Module { return anatel.New() },
	})
	Register(&Meta{
		Name: "brazilinfo", Category: CategoryOSINTBrasil,
		Description: "CEP, CNPJ, câmbio, bancos e feriados via BrasilAPI e ViaCEP",
		InputTypes:  []string{"cnpj", "cep", "phone", "email", "name", "ip"},
		OutputTypes: []string{"company_info", "address_found", "exchange_rate"},
		Factory:     func() module.Module { return brazilinfo.New() },
	})
	Register(&Meta{
		Name: "companyosint", Category: CategoryOSINTBrasil,
		Description: "CNPJ, sócios, situação Receita Federal, CVM e Portal Transparência",
		InputTypes:  []string{"cnpj", "domain"},
		OutputTypes: []string{"company_info", "partners", "cvm_info"},
		Factory:     func() module.Module { return companyosint.New() },
	})
	Register(&Meta{
		Name: "cpflookup", Category: CategoryOSINTBrasil,
		Description: "Consulta de CPF com situação Receita Federal (requer consentimento LGPD)",
		Gates:       []Gate{GateLGPD},
		InputTypes:  []string{"cpf"},
		OutputTypes: []string{"cpf_status", "cpf_name"},
		Factory:     func() module.Module { return cpflookup.New() },
	})
	Register(&Meta{
		Name: "govbr", Category: CategoryOSINTBrasil,
		Description: "APIs oficiais Gov.br: CNPJ, feriados, câmbio BCB/PTAX, bancos, transparência",
		InputTypes:  []string{"cnpj", "cep", "currency", "year", "ibge_code", "name"},
		OutputTypes: []string{"company_info", "holiday", "exchange_rate", "bank_info"},
		Factory:     func() module.Module { return govbr.New() },
	})
	Register(&Meta{
		Name: "namesearch", Category: CategoryOSINTBrasil,
		Description: "Busca de pessoas por nome: IBGE, Portal Transparência, OpenSanctions, Interpol",
		Gates:       []Gate{GateLGPD},
		InputTypes:  []string{"name"},
		OutputTypes: []string{"person_found", "sanction_hit", "interpol_notice"},
		Factory:     func() module.Module { return namesearch.New() },
	})
	Register(&Meta{
		Name: "osintbr", Category: CategoryOSINTBrasil,
		Description: "OSINT agregado Brasil: CPF, CNPJ, telefone, email (requer consentimento LGPD)",
		Gates:       []Gate{GateLGPD},
		InputTypes:  []string{"cpf", "cnpj", "phone", "email"},
		OutputTypes: []string{"person_info", "company_info", "contact_info"},
		Factory:     func() module.Module { return osintbr.New() },
	})
	Register(&Meta{
		Name: "phonelookup", Category: CategoryOSINTBrasil,
		Description: "OSINT de número de telefone: operadora, tipo, reputação, portabilidade",
		InputTypes:  []string{"phone"},
		OutputTypes: []string{"carrier", "phone_reputation", "phone_type"},
		Factory:     func() module.Module { return phonelookup.New() },
	})
	Register(&Meta{
		Name: "registroempresas", Category: CategoryOSINTBrasil,
		Description: "CNPJ.ws, Simples Nacional, MEI e Brasil.io; busca por CPF com LGPD gate",
		Gates:       []Gate{GateLGPD},
		InputTypes:  []string{"cnpj", "cpf", "name"},
		OutputTypes: []string{"company_info", "partners", "mei_info"},
		Factory:     func() module.Module { return registroempresas.New() },
	})
	Register(&Meta{
		Name: "tribunais", Category: CategoryOSINTBrasil,
		Description: "Processos judiciais: DataJud (CNJ), BNMP (mandados de prisão), JusBrasil",
		Gates:       []Gate{GateLGPD},
		InputTypes:  []string{"cpf", "cnpj", "name", "case_number"},
		OutputTypes: []string{"lawsuit", "arrest_warrant", "court_process"},
		Factory:     func() module.Module { return tribunais.New() },
	})
	Register(&Meta{
		Name: "whatsapp", Category: CategoryOSINTBrasil,
		Description: "Verifica existência de conta WhatsApp e disponibilidade de foto de perfil",
		InputTypes:  []string{"phone"},
		OutputTypes: []string{"whatsapp_found", "profile_picture"},
		Factory:     func() module.Module { return whatsapp.New() },
	})

	// ── OSINT Email ───────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "emailosint", Category: CategoryOSINTEmail,
		Description: "MX/SPF/DMARC, Gravatar, Hunter.io, EmailRep, HIBP, LeakCheck, Clearbit",
		InputTypes:  []string{"email"},
		OutputTypes: []string{"mx_record", "email_breach", "email_reputation"},
		EnvVars:     []EnvVar{{Name: "HUNTER_API_KEY"}, {Name: "EMAILREP_API_KEY"}, {Name: "HIBP_API_KEY"}},
		Factory:     func() module.Module { return emailosint.New() },
	})
	Register(&Meta{
		Name: "emailspoof", Category: CategoryOSINTEmail,
		Description: "Auditoria de autenticação de email: SPF, DMARC, DKIM, BIMI, MTA-STS — detecta spoofability",
		InputTypes:  []string{"domain", "email"},
		OutputTypes: []string{"spf_missing", "dmarc_missing", "emailspoof_verdict", "dkim_selectors_found"},
		Factory:     func() module.Module { return emailspoof.New() },
	})
	Register(&Meta{
		Name: "emailverify", Category: CategoryOSINTEmail,
		Description: "Verificação de existência de email via SMTP VRFY e catch-all detection",
		InputTypes:  []string{"email"},
		OutputTypes: []string{"email_valid", "email_catchall"},
		Factory:     func() module.Module { return emailverify.New() },
	})
	Register(&Meta{
		Name: "hibp", Category: CategoryOSINTEmail,
		Description: "HaveIBeenPwned: breaches, pastes e k-anonymity de senha",
		InputTypes:  []string{"email", "password"},
		EnvVars:     []EnvVar{{Name: "HIBP_API_KEY", Required: true}},
		OutputTypes: []string{"breach_found", "paste_found", "pwned_password"},
		Factory:     func() module.Module { return hibp.New() },
	})

	// ── OSINT Username ────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "sherlock", Category: CategoryOSINTUsername,
		Description: "150+ plataformas: ProbeStatus, ProbeMessage, ProbeURL, ProbeContain",
		InputTypes:  []string{"username"},
		OutputTypes: []string{"username_found"},
		Factory:     func() module.Module { return sherlock.New() },
	})
	Register(&Meta{
		Name: "socialmedia", Category: CategoryOSINTUsername,
		Description: "OSINT em redes sociais: Twitter/X, LinkedIn, Instagram, YouTube",
		InputTypes:  []string{"username", "name"},
		OutputTypes: []string{"social_profile"},
		Factory:     func() module.Module { return socialmedia.New() },
	})
	Register(&Meta{
		Name: "socialscan", Category: CategoryOSINTUsername,
		Description: "Verifica disponibilidade de username/email em múltiplas plataformas",
		InputTypes:  []string{"username", "email"},
		OutputTypes: []string{"username_taken", "username_available"},
		Factory:     func() module.Module { return socialscan.New() },
	})
	Register(&Meta{
		Name: "telegramosint", Category: CategoryOSINTUsername,
		Description: "OSINT de perfis, grupos e canais no Telegram via Bot API",
		InputTypes:  []string{"username", "phone"},
		EnvVars:     []EnvVar{{Name: "TELEGRAM_BOT_TOKEN"}},
		OutputTypes: []string{"telegram_profile", "telegram_group"},
		Factory:     func() module.Module { return telegramosint.New() },
	})
	Register(&Meta{
		Name: "userlookup", Category: CategoryOSINTUsername,
		Description: "65+ plataformas + WhatsMyName JSON; complementa o sherlock",
		InputTypes:  []string{"username"},
		OutputTypes: []string{"username_found"},
		Factory:     func() module.Module { return userlookup.New() },
	})

	// ── Breach / Credential ───────────────────────────────────────────────────
	Register(&Meta{
		Name: "credleak", Category: CategoryOSINTEmail,
		Description: "HIBP + LeakCheck + análise local de padrão de senha + k-anonymity",
		InputTypes:  []string{"email", "password"},
		EnvVars:     []EnvVar{{Name: "HIBP_API_KEY"}, {Name: "LEAKCHECK_API_KEY"}},
		OutputTypes: []string{"breach_found", "password_pattern"},
		Factory:     func() module.Module { return credleak.New() },
	})
	Register(&Meta{
		Name: "dehashed", Category: CategoryOSINTEmail,
		Description: "DeHashed API: busca por email, username, IP, nome, endereço",
		InputTypes:  []string{"email", "username", "ip", "name"},
		EnvVars:     []EnvVar{{Name: "DEHASHED_EMAIL", Required: true}, {Name: "DEHASHED_API_KEY", Required: true}},
		OutputTypes: []string{"dehashed_result"},
		Factory:     func() module.Module { return dehashed.New() },
	})
	Register(&Meta{
		Name: "leakosint", Category: CategoryOSINTEmail,
		Description: "IntelX, BreachDirectory, HudsonRock (Cavalier info-stealers), Leak-Lookup",
		InputTypes:  []string{"email", "domain", "username", "ip", "hash"},
		EnvVars:     []EnvVar{{Name: "INTELX_API_KEY"}, {Name: "LEAKLOOKUP_API_KEY"}},
		OutputTypes: []string{"breach_found", "infostealer_found"},
		Factory:     func() module.Module { return leakosint.New() },
	})
	Register(&Meta{
		Name: "osintleak", Category: CategoryOSINTEmail,
		Description: "DeHashed + LeakCheck + HIBP + IntelX + BreachDirectory combinados",
		InputTypes:  []string{"email", "username", "domain"},
		OutputTypes: []string{"breach_found"},
		Factory:     func() module.Module { return osintleak.New() },
	})

	// ── Recon / DNS ───────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "asnmap", Category: CategoryRecon,
		Description: "Mapeia ASN, CIDR e organização de um IP ou domínio via RIPE, BGPView",
		InputTypes:  []string{"ip", "domain", "asn"},
		OutputTypes: []string{"asn_info", "asn_prefix_summary"},
		Factory:     func() module.Module { return asnmap.New() },
	})
	Register(&Meta{
		Name: "bgpinfo", Category: CategoryRecon,
		Description: "RIPE NCC Stat, BGP.tools, Cloudflare Radar, IPinfo, RPKI",
		InputTypes:  []string{"ip", "asn"},
		OutputTypes: []string{"bgp_prefix", "asn_info", "rpki_status"},
		Factory:     func() module.Module { return bgpinfo.New() },
	})
	Register(&Meta{
		Name: "brandmon", Category: CategoryRecon,
		Description: "Monitoramento de candidatos e referências de abuso de marca sem assumir vínculo malicioso",
		InputTypes:  []string{"domain", "name"},
		OutputTypes: []string{"brand_domain_candidate", "brand_domain_reference", "phishing_reference"},
		Options: []Option{
			{Key: "sources", Default: "", Hint: "dns,urlscan,phishtank,openphish"},
			{Key: "max_typos", Default: "100", Hint: "Máximo de candidatos DNS"},
			{Key: "max_results", Default: "100", Hint: "Limite total de referências"},
			{Key: "max_runtime_seconds", Default: "60", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return brandmon.New() },
	})
	Register(&Meta{
		Name: "cdncheck", Category: CategoryRecon,
		Description: "Detecta CDN, WAF e proxy reverso via headers e fingerprinting",
		InputTypes:  []string{"domain", "ip", "url"},
		OutputTypes: []string{"cdn_detected", "waf_detected"},
		Factory:     func() module.Module { return cdncheck.New() },
	})
	Register(&Meta{
		Name: "certs", Category: CategoryRecon,
		Description: "Referências históricas de CT e inventário externo; promove apenas nomes confirmados por IP válido",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{
			"ct_name_reference",
			"ct_wildcard_reference",
			"censys_name_reference",
			"passive_name_candidate",
			"subdomain_resolved",
		},
		Options: []Option{
			{Key: "max_results", Default: "200", Hint: "Limite total de referências retornadas"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução em segundos"},
			{Key: "wildcard", Default: "true", Hint: "Inclui referências históricas de certificados wildcard"},
		},
		Factory: func() module.Module { return certs.New() },
	})
	Register(&Meta{
		Name: "dnsaudit", Category: CategoryRecon,
		Description: "Auditoria de DNS: MX, SPF, DMARC, DNSKEY, NSEC, zona axfr, wildcard",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"dns_record", "zone_transfer", "dns_misconfiguration"},
		Factory:     func() module.Module { return dnsaudit.New() },
	})
	Register(&Meta{
		Name: "dnsprobe", Category: CategoryRecon,
		Description: "Resolução DNS multi-tipo: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR",
		InputTypes:  []string{"domain", "ip"},
		OutputTypes: []string{"dns_record"},
		Factory:     func() module.Module { return dnsprobe.New() },
	})
	Register(&Meta{
		Name: "dnsrecon", Category: CategoryRecon,
		Description: "Reconhecimento DNS avançado: brute-force de subdomínios, zone walk, DNSSEC",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"subdomain", "dns_record"},
		Factory:     func() module.Module { return dnsrecon.New() },
	})
	Register(&Meta{
		Name: "ipgeolocation", Category: CategoryRecon,
		Description: "Geolocalização e referências externas de reputação para IPs, sem confirmar vulnerabilidade",
		InputTypes:  []string{"ip"},
		OutputTypes: []string{
			"address_classification",
			"geolocation_reference",
			"abuse_contact_reference",
			"abuse_reputation_reference",
			"external_inventory_reference",
			"external_vulnerability_reference",
			"fraud_reputation_reference",
			"malware_reputation_reference",
		},
		Options: []Option{
			{Key: "sources", Default: "all", Hint: "ipapi,ipinfo,abuseipdb,shodan,ipqs,virustotal"},
			{Key: "days", Default: "30", Hint: "Janela de reputação do AbuseIPDB"},
			{Key: "max_results", Default: "100", Hint: "Limite total de referências"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return ipgeolocation.New() },
	})
	Register(&Meta{
		Name: "ipintel", Category: CategoryRecon,
		Description: "Inteligência de IP com classificação local e referências externas de reputação sem confirmar vulnerabilidade",
		InputTypes:  []string{"ip"},
		OutputTypes: []string{
			"address_classification",
			"geolocation_reference",
			"abuse_reputation_reference",
			"asn_reference",
			"noise_reputation_reference",
			"external_inventory_reference",
			"external_vulnerability_reference",
			"threat_ioc_reference",
		},
		Options: []Option{
			{Key: "sources", Default: "", Hint: "local,ipapi,abuseipdb,ipinfo,greynoise,shodan,threatfox"},
			{Key: "days", Default: "90", Hint: "Janela de reputação do AbuseIPDB"},
			{Key: "max_results", Default: "100", Hint: "Limite total de referências"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return ipintel.New() },
	})
	Register(&Meta{
		Name: "mapcidr", Category: CategoryRecon,
		Description: "Operações em CIDR: expand, aggregate, count, overlap, subnet",
		InputTypes:  []string{"cidr"},
		OutputTypes: []string{"cidr_info", "ip_list"},
		Options:     []Option{{Key: "op", Default: "count", Hint: "expand|aggregate|count|overlap"}},
		Factory:     func() module.Module { return mapcidr.New() },
	})
	Register(&Meta{
		Name: "recon", Category: CategoryRecon,
		Description: "Reconhecimento geral: WHOIS, DNS, HTTP, TLS, headers, tecnologias",
		InputTypes:  []string{"domain", "ip", "url"},
		OutputTypes: []string{"passive_name_candidate", "subdomain_resolved", "dns_record", "historical_reference", "scan_reference"},
		Options: []Option{
			{Key: "max_subs", Default: "5000", Hint: "Máximo de resultados passivos retornados"},
			{Key: "max_runtime_seconds", Default: "90", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return recon.New() },
	})
	Register(&Meta{
		Name: "repochecker", Category: CategoryRecon,
		Description: "Enumera repositórios públicos GitHub/GitLab/Bitbucket de uma organização",
		InputTypes:  []string{"repository"},
		EnvVars:     []EnvVar{{Name: "GITHUB_TOKEN"}},
		OutputTypes: []string{"public_repo"},
		Factory:     func() module.Module { return repochecker.New() },
	})
	Register(&Meta{
		Name: "shodanwatch", Category: CategoryRecon,
		Description: "Inteligência externa do Shodan; referências exigem validação direta antes de confirmar risco ou ativo",
		InputTypes:  []string{"ip", "domain", "asn"},
		EnvVars:     []EnvVar{{Name: "SHODAN_API_KEY"}},
		OutputTypes: []string{
			"shodan_inventory_reference",
			"shodan_banner_reference",
			"shodan_vulnerability_reference",
			"shodan_asset_reference",
			"shodan_dns_reference",
			"shodan_honeyscore",
			"shodan_search_total",
		},
		Options: []Option{
			{Key: "mode", Default: "host", Hint: "host|org|search"},
			{Key: "parallelism", Default: "4", Hint: "Concorrência máxima, limitada a 16"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
			{Key: "honeyscore", Default: "false", Hint: "Consulta classificação de honeypot"},
		},
		Factory: func() module.Module { return shodanwatch.New() },
	})
	Register(&Meta{
		Name: "shuffledns", Category: CategoryRecon,
		Description: "Brute-force de subdomínios via DNS paralelo com wordlist embutida",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"subdomain_resolved"},
		Options: []Option{
			{Key: "max_candidates", Default: "2000", Hint: "Máximo de nomes consultados"},
			{Key: "concurrency", Default: "50", Hint: "Consultas DNS simultâneas"},
			{Key: "dns_timeout_ms", Default: "5000", Hint: "Timeout por consulta DNS"},
			{Key: "max_runtime_seconds", Default: "60", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return shuffledns.New() },
	})
	Register(&Meta{
		Name: "subdiscovery", Category: CategoryRecon,
		Description: "Descoberta de subdomínios: crt.sh, VirusTotal, SecurityTrails, Subfinder",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"passive_name_candidate", "passive_name_summary", "subdomain_resolved"},
		Options: []Option{
			{Key: "resolve", Default: "true", Hint: "Promove somente nomes confirmados por DNS"},
			{Key: "include_unresolved", Default: "false", Hint: "Inclui candidatos não resolvidos individualmente"},
			{Key: "max_candidates", Default: "1000", Hint: "Máximo de nomes passivos validados"},
			{Key: "resolve_parallelism", Default: "32", Hint: "Máximo de consultas DNS simultâneas"},
			{Key: "dns_timeout_ms", Default: "2000", Hint: "Timeout por consulta DNS em milissegundos"},
			{Key: "max_runtime_seconds", Default: "60", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return subdiscovery.New() },
	})
	Register(&Meta{
		Name: "takeover", Category: CategoryRecon,
		Description: "Detecta subdomain takeover: CNAME para serviços expirados (50+ providers)",
		InputTypes:  []string{"domain", "url"},
		OutputTypes: []string{"subdomain_takeover"},
		Factory:     func() module.Module { return takeover.New() },
	})
	Register(&Meta{
		Name: "whois", Category: CategoryRecon,
		Description: "WHOIS de domínio e IP: registrante, datas, nameservers, ASN",
		InputTypes:  []string{"domain", "ip"},
		OutputTypes: []string{"whois_info"},
		Factory:     func() module.Module { return whois.New() },
	})

	// ── Web Vulnerability ─────────────────────────────────────────────────────
	Register(&Meta{
		Name: "apiaudit", Category: CategoryWebVuln,
		Description: "Detecta APIs expostas, Swagger/OpenAPI, GraphQL e endpoints sem auth",
		InputTypes:  []string{"url", "domain"},
		OutputTypes: []string{"api_exposed", "swagger_found", "graphql_found"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de origens HTTP analisadas"},
			{Key: "max_runtime_seconds", Default: "180", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return apiaudit.New() },
	})
	Register(&Meta{
		Name: "bypass403", Category: CategoryWebVuln,
		Description: "Técnicas de bypass de respostas 403: headers, path fuzzing, method override",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"bypass_403_success"},
		Factory:     func() module.Module { return bypass403.New() },
	})
	Register(&Meta{
		Name: "cacheprobe", Category: CategoryWebVuln,
		Description: "Cache poisoning e cache deception: headers, vary, X-Forwarded-Host",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"cache_poisoning", "cache_deception"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de origens HTTP analisadas"},
			{Key: "max_runtime_seconds", Default: "180", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return cacheprobe.New() },
	})
	Register(&Meta{
		Name: "clickjacking", Category: CategoryWebVuln,
		Description: "Detecta ausência de X-Frame-Options e CSP frame-ancestors",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"clickjacking_vulnerable"},
		Factory:     func() module.Module { return clickjacking.New() },
	})
	Register(&Meta{
		Name: "cors2", Category: CategoryWebVuln,
		Description: "CORS avançado: null origin, prefix bypass, subdomain bypass, downgrade HTTP",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"cors_null_origin", "cors_prefix_bypass", "cors_subdomain_bypass"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de origens HTTP analisadas"},
			{Key: "max_runtime_seconds", Default: "300", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return cors2.New() },
	})
	Register(&Meta{
		Name: "corsaudit", Category: CategoryWebVuln,
		Description: "Detecta CORS misconfiguration: reflect origin, wildcard com credentials",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"cors_misconfiguration"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de origens HTTP analisadas"},
			{Key: "max_runtime_seconds", Default: "300", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return corsaudit.New() },
	})
	Register(&Meta{
		Name: "graphql", Category: CategoryWebVuln,
		Description: "Introspection, query depth, batch abuse, field suggestion, DoS vectors",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"graphql_introspection", "graphql_batch_abuse"},
		Factory:     func() module.Module { return graphql.New() },
	})
	Register(&Meta{
		Name: "headeraudit", Category: CategoryWebVuln,
		Description: "Auditoria de security headers: CSP, HSTS, X-Frame-Options, Referrer-Policy",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"missing_security_header", "weak_security_header"},
		Factory:     func() module.Module { return headeraudit.New() },
	})
	Register(&Meta{
		Name: "hostinjection", Category: CategoryWebVuln,
		Description: "Host header injection: password reset poisoning, cache poisoning via Host",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"host_injection"},
		Factory:     func() module.Module { return hostinjection.New() },
	})
	Register(&Meta{
		Name: "idor", Category: CategoryWebVuln,
		Description: "Testa IDOR substituindo IDs numéricos e UUIDs em parâmetros e paths",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"idor_found"},
		Factory:     func() module.Module { return idor.New() },
	})
	Register(&Meta{
		Name: "openredirect", Category: CategoryWebVuln,
		Description: "Open redirect: payloads de bypass com double-encode, protocol-relative, data:",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"open_redirect", "open_redirect_reflected"},
		Factory:     func() module.Module { return openredirect.New() },
	})
	Register(&Meta{
		Name: "prototype", Category: CategoryWebVuln,
		Description: "Prototype pollution: GET params, JSON body, merge patterns",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"prototype_pollution"},
		Factory:     func() module.Module { return prototype.New() },
	})
	Register(&Meta{
		Name: "ratelimit", Category: CategoryWebVuln,
		Description: "Detecta ausência de rate limiting em endpoints de login, reset, API",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"rate_limit_missing"},
		Factory:     func() module.Module { return ratelimit.New() },
	})
	Register(&Meta{
		Name: "soft404", Category: CategoryWebVuln,
		Description: "Detecta soft 404: páginas de erro mascaradas como 200",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"soft_404_detected"},
		Factory:     func() module.Module { return soft404.New() },
	})
	Register(&Meta{
		Name: "swaggerfuzz", Category: CategoryWebVuln,
		Description: "Fuzzing via spec OpenAPI/Swagger 2.0 e 3.x: auth bypass, mass assignment, injection, type confusion",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"swagger_spec_found", "swagger_auth_bypass", "swagger_mass_assignment"},
		Options: []Option{
			{Key: "spec_url", Hint: "URL explícita da spec (skip auto-discovery)"},
			{Key: "checks", Default: "auth,types,injection,massassign,methods"},
			{Key: "bearer", Hint: "Bearer token para autenticar as probes"},
		},
		Factory: func() module.Module { return swaggerfuzz.New() },
	})
	Register(&Meta{
		Name: "verbtamper", Category: CategoryWebVuln,
		Description: "HTTP verb tampering: testa métodos não documentados (DELETE, PATCH, OPTIONS)",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"verb_tamper_found"},
		Factory:     func() module.Module { return verbtamper.New() },
	})
	Register(&Meta{
		Name: "vulnscan", Category: CategoryWebVuln,
		Description: "Scanner de vulnerabilidades baseado em templates Nuclei-compatíveis",
		InputTypes:  []string{"url", "domain"},
		OutputTypes: []string{"vuln_found"},
		Options:     []Option{{Key: "parallelism", Default: "10"}},
		Factory:     func() module.Module { return vulnscan.New() },
	})
	Register(&Meta{
		Name: "vulnx", Category: CategoryWebVuln,
		Description: "Detecção de CMS, plugins vulneráveis, LFI, SQLi básico",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"cms_detected", "vuln_found"},
		Factory:     func() module.Module { return vulnx.New() },
	})
	Register(&Meta{
		Name: "webdav", Category: CategoryWebVuln,
		Description: "Detecta WebDAV habilitado: PROPFIND, PUT, COPY, MOVE, DELETE",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"webdav_enabled", "webdav_write_access"},
		Factory:     func() module.Module { return webdav.New() },
	})

	// ── Injection ────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "cmdi", Category: CategoryInjection,
		Description: "Command injection: OS command execution via canaries e OOB (interactsh)",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"cmdi_found", "cmdi_oob"},
		Options: []Option{
			{Key: "max_targets", Default: "50", Hint: "Máximo de endpoints com parâmetros analisados"},
			{Key: "max_runtime_seconds", Default: "300", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return cmdi.New() },
	})
	Register(&Meta{
		Name: "crlf", Category: CategoryInjection,
		Description: "CRLF injection: HTTP header injection, log injection, cookie injection",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"crlf_found"},
		Factory:     func() module.Module { return crlf.New() },
	})
	Register(&Meta{
		Name: "deserial", Category: CategoryInjection,
		Description: "Deserialization gadget probes: Java, PHP, Python pickle, Ruby marshal",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"deserialization_found"},
		Factory:     func() module.Module { return deserial.New() },
	})
	Register(&Meta{
		Name: "lfi", Category: CategoryInjection,
		Description: "Local File Inclusion: path traversal, null byte, encoding bypass",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"lfi_found"},
		Factory:     func() module.Module { return lfi.New() },
	})
	Register(&Meta{
		Name: "nosqli", Category: CategoryInjection,
		Description: "NoSQL injection: error-based, boolean, time-based para MongoDB/CouchDB",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"nosqli_found"},
		Factory:     func() module.Module { return nosqli.New() },
	})
	Register(&Meta{
		Name: "sqli", Category: CategoryInjection,
		Description: "SQL injection: error-based, boolean-based, time-based; 13 DBMSs",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"sqli_found"},
		Factory:     func() module.Module { return sqli.New() },
	})
	Register(&Meta{
		Name: "ssti", Category: CategoryInjection,
		Description: "Server-Side Template Injection: Jinja2, Twig, Smarty, Pebble, Freemarker",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"ssti"},
		Factory:     func() module.Module { return ssti.New() },
	})
	Register(&Meta{
		Name: "sstiprobe", Category: CategoryInjection,
		Description: "SSTI com 2 níveis de confirmação (detected/confirmed): 10+ engines",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"ssti_detected", "ssti_confirmed"},
		Factory:     func() module.Module { return sstiprobe.New() },
	})
	Register(&Meta{
		Name: "xssreflect", Category: CategoryInjection,
		Description: "XSS refletido: canary em params de URL, checagem de encoding bypass",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"reflected_xss_candidate"},
		Factory:     func() module.Module { return xssreflect.New() },
	})
	Register(&Meta{
		Name: "xssscan", Category: CategoryInjection,
		Description: "XSS scan completo: reflected, DOM, stored candidate, param discovery",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"xss_reflected", "xss_confirmed"},
		Factory:     func() module.Module { return xssscan.New() },
	})
	Register(&Meta{
		Name: "xxeprobe", Category: CategoryInjection,
		Description: "XXE: entity injection em XML endpoints, file read, SSRF via DTD",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"xxe_found"},
		Factory:     func() module.Module { return xxeprobe.New() },
	})

	// ── Network Scan ──────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "portscanner", Category: CategoryNetworkScan,
		Description: "Scanner TCP nativo; confirma conexão local e mantém Shodan/Censys como referências externas",
		InputTypes:  []string{"ip", "domain"},
		Options: []Option{
			{Key: "ports", Default: "top100", Hint: "top100|80,443,8080-8090"},
			{Key: "timeout_ms", Default: "3000"},
			{Key: "concurrency", Default: "100", Hint: "Concorrência máxima de conexões"},
			{Key: "max_ports", Default: "1000", Hint: "Limite explícito de portas por execução"},
			{Key: "max_runtime_seconds", Default: "300", Hint: "Orçamento global de execução"},
		},
		EnvVars:     []EnvVar{{Name: "SHODAN_API_KEY"}},
		OutputTypes: []string{"open_port", "scan_summary", "external_inventory_reference", "external_vulnerability_reference"},
		Factory:     func() module.Module { return portscanner.New() },
	})
	Register(&Meta{
		Name: "udpprobe", Category: CategoryNetworkScan,
		Description: "Sonda serviços UDP: DNS, NTP, SNMP, SSDP, mDNS",
		InputTypes:  []string{"ip", "domain"},
		OutputTypes: []string{"udp_service_open"},
		Factory:     func() module.Module { return udpprobe.New() },
	})
	Register(&Meta{
		Name: "webprobe", Category: CategoryNetworkScan,
		Description: "Probe HTTP/HTTPS: status, redirect chain, headers, tecnologias",
		InputTypes:  []string{"domain", "url", "ip"},
		OutputTypes: []string{"web_probe"},
		Factory:     func() module.Module { return webprobe.New() },
	})

	// ── TLS ───────────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "sslcheck", Category: CategoryTLS,
		Description: "Inspeção TLS nativa: expiração, SANs, auto-assinado, wildcard, OCSP, CT logs",
		InputTypes:  []string{"domain", "ip"},
		OutputTypes: []string{"tls_cert_info", "tls_expired", "tls_weak_protocol"},
		Factory:     func() module.Module { return sslcheck.New() },
	})
	Register(&Meta{
		Name: "tlsaudit", Category: CategoryTLS,
		Description: "Auditoria TLS/SSL: cipher suites, protocolos, Heartbleed, POODLE, BEAST",
		InputTypes:  []string{"domain", "ip"},
		OutputTypes: []string{"tls_vuln", "weak_cipher"},
		Factory:     func() module.Module { return tlsaudit.New() },
	})
	Register(&Meta{
		Name: "tlsfinder", Category: CategoryTLS,
		Description: "Coleta referências de nomes em Certificate Transparency sem presumir atividade",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"ct_name_reference"},
		Factory:     func() module.Module { return tlsfinder.New() },
	})

	// ── Cloud ─────────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "cloudlist", Category: CategoryCloud,
		Description: "Inventário autenticado de cloud, filtrado pelo target por padrão e nunca promovido automaticamente",
		InputTypes:  []string{"domain", "name"},
		OutputTypes: []string{
			"cloud_inventory_reference",
			"cloud_storage_reference",
			"cloud_zone_reference",
			"cloud_cdn_reference",
		},
		Options: []Option{
			{Key: "providers", Default: "aws,gcp,azure", Hint: "Providers separados por vírgula"},
			{Key: "scope", Default: "target", Hint: "target|all; all exige intenção explícita"},
			{Key: "max_results", Default: "500", Hint: "Limite total de recursos retornados"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return cloudlist.New() },
	})
	Register(&Meta{
		Name: "cloudosint", Category: CategoryCloud,
		Description: "Candidatos e referências de storage cloud por naming patterns e fontes públicas",
		InputTypes:  []string{"domain", "name"},
		OutputTypes: []string{"cloud_storage_candidate", "cloud_storage_reference"},
		Options: []Option{
			{Key: "sources", Default: "", Hint: "http,grayhat"},
			{Key: "max_permutations", Default: "30", Hint: "Máximo de nomes candidatos"},
			{Key: "max_results", Default: "100", Hint: "Limite total de referências"},
			{Key: "max_runtime_seconds", Default: "60", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return cloudosint.New() },
	})
	Register(&Meta{
		Name: "s3enum", Category: CategoryCloud,
		Description: "Enumera buckets S3, GCS, DO Spaces, Backblaze B2 via naming patterns",
		InputTypes:  []string{"domain", "name"},
		OutputTypes: []string{"aws_s3_public_listing"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de nomes candidatos consultados"},
			{Key: "max_runtime_seconds", Default: "120", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return s3enum.New() },
	})

	// ── Threat Intel ─────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "darkweb", Category: CategoryThreatIntel,
		Description: "Monitoramento de dark web: menções em fóruns, pastes e marketplaces",
		InputTypes:  []string{"domain", "email", "name"},
		OutputTypes: []string{"darkweb_mention"},
		Factory:     func() module.Module { return darkweb.New() },
	})
	Register(&Meta{
		Name: "pastebin", Category: CategoryThreatIntel,
		Description: "Busca em Pastebin, Ghostbin, PasteGov por domínio/email/keyword",
		InputTypes:  []string{"domain", "email", "keyword"},
		OutputTypes: []string{"paste_found"},
		Factory:     func() module.Module { return pastebin.New() },
	})
	Register(&Meta{
		Name: "threatintel", Category: CategoryThreatIntel,
		Description: "Referências externas de threat intelligence com escopo validado e sem promoção automática",
		InputTypes:  []string{"url", "ip", "domain", "hash"},
		EnvVars:     []EnvVar{{Name: "VIRUSTOTAL_API_KEY"}, {Name: "OTX_API_KEY"}},
		OutputTypes: []string{"malware_found", "phishing_found", "threat_intel"},
		Options: []Option{
			{Key: "sources", Default: "", Hint: "virustotal,otx,threatfox,malwarebazaar,urlhaus,phishtank"},
			{Key: "min_detections", Default: "1", Hint: "Mínimo de detecções antes de emitir referência"},
			{Key: "max_results", Default: "100", Hint: "Limite total de referências"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return threatintel.New() },
	})
	Register(&Meta{
		Name: "vulndb", Category: CategoryThreatIntel,
		Description: "Busca CVEs por produto/versão: NVD, OSV, VulnDB, GitHub Advisory",
		InputTypes:  []string{"name", "domain"},
		OutputTypes: []string{"cve_found"},
		Factory:     func() module.Module { return vulndb.New() },
	})

	// ── Secrets ───────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "gitdorker", Category: CategorySecrets,
		Description: "GitHub dorks: busca secrets em repositórios públicos via search API",
		InputTypes:  []string{"domain", "name", "keyword"},
		EnvVars:     []EnvVar{{Name: "GITHUB_TOKEN"}},
		OutputTypes: []string{"github_dork_hit"},
		Factory:     func() module.Module { return gitdorker.New() },
	})
	Register(&Meta{
		Name: "githistory", Category: CategorySecrets,
		Description: "Auditoria de histórico Git: commits suspeitos, arquivos sensíveis, secret alerts",
		InputTypes:  []string{"url"},
		EnvVars:     []EnvVar{{Name: "GITHUB_TOKEN"}},
		OutputTypes: []string{"githistory_sensitive_file", "githistory_suspicious_commit", "githistory_secret_alert"},
		Factory:     func() module.Module { return githistory.New() },
	})
	Register(&Meta{
		Name: "secretscan", Category: CategorySecrets,
		Description: "Regex scan de secrets em conteúdo: 35+ padrões (AWS, Stripe, PyPI, HuggingFace…)",
		InputTypes:  []string{"url", "domain"},
		OutputTypes: []string{"secret_found"},
		Factory:     func() module.Module { return secretscan.New() },
	})
	Register(&Meta{
		Name: "truffler", Category: CategorySecrets,
		Description: "Scan de entropy + regex em JS/HTML/text: detecta tokens e chaves com alta confiança",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"secret_found"},
		Factory:     func() module.Module { return truffler.New() },
	})

	// ── Fingerprint ───────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "fingerprint", Category: CategoryFingerprint,
		Description: "Detecta tecnologias: CMS, framework, linguagem, servidor, WAF via Wappalyzer rules",
		InputTypes:  []string{"url", "domain"},
		OutputTypes: []string{"tech_detected"},
		Factory:     func() module.Module { return fingerprint.New() },
	})
	Register(&Meta{
		Name: "httpxpro", Category: CategoryFingerprint,
		Description: "HTTP probe avançado: tecnologias, status, redirect chain, CDN, title",
		InputTypes:  []string{"url", "domain"},
		OutputTypes: []string{"http_probe", "tech_detected"},
		Factory:     func() module.Module { return httpxpro.New() },
	})
	Register(&Meta{
		Name: "metadata", Category: CategoryFingerprint,
		Description: "Extrai metadados de arquivos: EXIF de imagens, PDF author, Office properties",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"metadata_found"},
		Factory:     func() module.Module { return metadata.New() },
	})
	Register(&Meta{
		Name: "netmon", Category: CategoryFingerprint,
		Description: "Agrega referências externas de Shodan, InternetDB, Censys e FOFA sem promover ativos ou riscos não confirmados",
		InputTypes:  []string{"ip", "domain"},
		EnvVars:     []EnvVar{{Name: "SHODAN_API_KEY"}, {Name: "CENSYS_API_ID"}, {Name: "FOFA_KEY"}},
		OutputTypes: []string{
			"external_inventory_reference",
			"external_banner_reference",
			"external_vulnerability_reference",
			"external_tls_reference",
			"external_dns_reference",
		},
		Options: []Option{
			{Key: "sources", Default: "", Hint: "shodan,censys,fofa,internetdb"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return netmon.New() },
	})
	Register(&Meta{
		Name: "wafscan", Category: CategoryFingerprint,
		Description: "Detecta e fingerprinta WAF: Cloudflare, Akamai, AWS WAF, Imperva, F5",
		InputTypes:  []string{"url", "domain"},
		OutputTypes: []string{"waf_detected"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de hosts únicos analisados"},
			{Key: "max_runtime_seconds", Default: "180", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return wafscan.New() },
	})

	// ── HTTP Audit ────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "crawler", Category: CategoryHTTPAudit,
		Description: "Web crawler recursivo com promoção apenas de páginas confirmadas por resposta HTTP",
		InputTypes:  []string{"url"},
		Options: []Option{
			{Key: "depth", Default: "3", Hint: "Profundidade máxima, limitada a 5"},
			{Key: "scope", Default: "subdomain", Hint: "subdomain|strict"},
			{Key: "parallelism", Default: "10", Hint: "Requisições simultâneas, limitadas a 32"},
			{Key: "max_pages", Default: "200", Hint: "Máximo de páginas agendadas"},
			{Key: "max_results", Default: "500", Hint: "Máximo de páginas confirmadas retornadas"},
			{Key: "max_runtime_seconds", Default: "120", Hint: "Orçamento global de execução"},
		},
		OutputTypes: []string{"crawled_url"},
		Factory:     func() module.Module { return crawler.New() },
	})
	Register(&Meta{
		Name: "ffuf", Category: CategoryHTTPAudit,
		Description: "Fuzzing de diretórios e parâmetros com wordlist embutida",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"path_found"},
		Factory:     func() module.Module { return ffuf.New() },
	})
	Register(&Meta{
		Name: "gau", Category: CategoryHTTPAudit,
		Description: "Coleta referências históricas não confirmadas: Wayback, Common Crawl, URLScan e AlienVault",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"historical_reference"},
		Options: []Option{
			{Key: "max_urls", Default: "1000", Hint: "Máximo de referências históricas retornadas"},
			{Key: "max_domains", Default: "10", Hint: "Máximo de domínios únicos consultados"},
			{Key: "max_runtime_seconds", Default: "90", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return gau.New() },
	})
	Register(&Meta{
		Name: "googledork", Category: CategoryHTTPAudit,
		Description: "Google dorks automatizados via CSE: filetype, inurl, site, intitle",
		InputTypes:  []string{"domain"},
		EnvVars:     []EnvVar{{Name: "GOOGLE_CSE_KEY"}, {Name: "GOOGLE_CSE_CX"}},
		OutputTypes: []string{"dork_hit"},
		Factory:     func() module.Module { return googledork.New() },
	})
	Register(&Meta{
		Name: "katana", Category: CategoryHTTPAudit,
		Description: "Crawler avançado: confirma páginas por HTTP e mantém referências de JS, forms, robots e sitemap como candidatos",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"crawled_url"},
		Options: []Option{
			{Key: "depth", Default: "3", Hint: "Profundidade máxima, limitada a 5"},
			{Key: "parallelism", Default: "10", Hint: "Requisições simultâneas, limitadas a 32"},
			{Key: "scope", Default: "host", Hint: "host|domain|all"},
			{Key: "max_pages", Default: "300", Hint: "Máximo de páginas agendadas"},
			{Key: "max_results", Default: "1000", Hint: "Máximo de registros retornados"},
			{Key: "max_runtime_seconds", Default: "180", Hint: "Orçamento global de execução"},
			{Key: "forms", Default: "true", Hint: "Extrai campos de formulários observados"},
			{Key: "js", Default: "true", Hint: "Extrai candidatos de endpoints JavaScript"},
			{Key: "assets", Default: "false", Hint: "Extrai referências de assets"},
			{Key: "robots", Default: "true", Hint: "Consulta robots.txt"},
			{Key: "sitemap", Default: "true", Hint: "Consulta sitemap.xml"},
		},
		Factory: func() module.Module { return katana.New() },
	})
	Register(&Meta{
		Name: "paramdisc", Category: CategoryHTTPAudit,
		Description: "Descoberta de parâmetros via wordlist e análise de JS",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"param_found"},
		Factory:     func() module.Module { return paramdisc.New() },
	})
	Register(&Meta{
		Name: "paramspider", Category: CategoryHTTPAudit,
		Description: "Extrai candidatos históricos de URLs parametrizadas do Wayback sem promovê-los antes de validação HTTP",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"historical_parameter_url_candidate"},
		Options: []Option{
			{Key: "placeholder", Default: "FUZZ", Hint: "Valor substituto para parâmetros"},
			{Key: "max_results", Default: "500", Hint: "Máximo de candidatos históricos retornados"},
			{Key: "max_source_urls", Default: "10000", Hint: "Máximo de registros lidos da fonte"},
			{Key: "max_runtime_seconds", Default: "45", Hint: "Orçamento global de execução"},
			{Key: "save", Default: "false", Hint: "Salva resultado localmente quando habilitado"},
		},
		Factory: func() module.Module { return paramspider.New() },
	})
	Register(&Meta{
		Name: "pathprobe", Category: CategoryHTTPAudit,
		Description: "Probe de caminhos sensíveis: admin, backup, debug, .git, .env",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"sensitive_path_found"},
		Factory:     func() module.Module { return pathprobe.New() },
	})
	Register(&Meta{
		Name: "proxify", Category: CategoryHTTPAudit,
		Description: "Proxy HTTP para captura e replay de requests durante pentest",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"proxied_request"},
		Factory:     func() module.Module { return proxify.New() },
	})
	Register(&Meta{
		Name: "urldedup", Category: CategoryHTTPAudit,
		Description: "Deduplica candidatos de URL por estrutura sem afirmar disponibilidade ou promover contexto",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"deduplicated_url_candidate"},
		Options: []Option{
			{Key: "max_inputs", Default: "10000", Hint: "Máximo de URLs processadas"},
			{Key: "max_results", Default: "2000", Hint: "Máximo de padrões retornados"},
			{Key: "keep_content", Default: "false", Hint: "Mantém URLs com aparência de conteúdo editorial"},
		},
		Factory: func() module.Module { return urldedup.New() },
	})
	Register(&Meta{
		Name: "urlfinder", Category: CategoryHTTPAudit,
		Description: "Extrai candidatos de localização web de HTML, JS, CSS e comentários sem promovê-los antes de validação HTTP",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"web_location_candidate"},
		Options: []Option{
			{Key: "max_targets", Default: "100", Hint: "Máximo de documentos analisados"},
			{Key: "max_results", Default: "1000", Hint: "Máximo de URLs extraídas"},
			{Key: "max_runtime_seconds", Default: "180", Hint: "Orçamento global de execução em segundos"},
			{Key: "include_external", Default: "false", Hint: "Inclui URLs fora dos hosts de entrada"},
		},
		Factory: func() module.Module { return urlfinder.New() },
	})
	Register(&Meta{
		Name: "urlparse", Category: CategoryHTTPAudit,
		Description: "Parse e análise de URLs: parâmetros, fragmentos, path segments",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"url_component"},
		Factory:     func() module.Module { return urlparse.New() },
	})
	Register(&Meta{
		Name: "wayback", Category: CategoryHTTPAudit,
		Description: "Busca referências históricas não confirmadas em arquivos públicos",
		InputTypes:  []string{"domain", "url"},
		OutputTypes: []string{"historical_reference", "archived_version"},
		Options: []Option{
			{Key: "max_urls", Default: "1000", Hint: "Máximo de referências históricas retornadas"},
			{Key: "max_runtime_seconds", Default: "60", Hint: "Orçamento global de execução em segundos"},
		},
		Factory: func() module.Module { return wayback.New() },
	})

	// ── Auth ─────────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "credstuffing", Category: CategoryAuth,
		Description: "Simulação de credential stuffing com classificação de lockout/captcha/MFA (requer authorized=true)",
		Gates:       []Gate{GateAuthorized},
		InputTypes:  []string{"url"},
		OutputTypes: []string{"credstuffing_success", "credstuffing_lockout_detected", "credstuffing_summary"},
		Options: []Option{
			{Key: "authorized", Default: "false", Hint: "Deve ser 'true' para executar"},
			{Key: "login_url", Hint: "URL relativa ou absoluta do endpoint de login"},
			{Key: "creds", Hint: "user:pass,user2:pass2 separados por vírgula ou newline"},
		},
		Factory: func() module.Module { return credstuffing.New() },
	})
	Register(&Meta{
		Name: "jwt", Category: CategoryAuth,
		Description: "JWT: alg:none, expired, jku/jwk header injection, kid path traversal",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"jwt_alg_none", "jwt_expired", "jwt_jku_header"},
		Factory:     func() module.Module { return jwt.New() },
	})
	Register(&Meta{
		Name: "jwtaudit", Category: CategoryAuth,
		Description: "JWT auditoria completa: decode, alg confusion, weak secret brute-force",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"jwt_vuln"},
		Factory:     func() module.Module { return jwtaudit.New() },
	})
	Register(&Meta{
		Name: "oauth2", Category: CategoryAuth,
		Description: "OAuth2: implicit flow, broad scope, discovery endpoint misconfigs",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"oauth2_implicit_flow", "oauth2_broad_scope"},
		Factory:     func() module.Module { return oauth2.New() },
	})
	Register(&Meta{
		Name: "oauthprobe", Category: CategoryAuth,
		Description: "OAuth2/OIDC endpoint misconfigurations: PKCE, state, token leak",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"oauth_misconfiguration"},
		Factory:     func() module.Module { return oauthprobe.New() },
	})

	// ── Wireless ──────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "wifite2", Category: CategoryWireless,
		Description: "Auditoria WiFi: scan, handshake capture, WPS crack (requer authorized=true)",
		Gates:       []Gate{GateAuthorized},
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"wifi_network", "wps_vulnerable"},
		Factory:     func() module.Module { return wifite2.New() },
	})

	// ── Util ──────────────────────────────────────────────────────────────────
	Register(&Meta{
		Name: "alterx", Category: CategoryUtil,
		Description: "Gera candidatos de DNS e, quando habilitado, promove somente nomes confirmados fora de wildcard",
		InputTypes:  []string{"domain"},
		OutputTypes: []string{"dns_permutation_candidate", "subdomain_resolved"},
		Options: []Option{
			{Key: "max_results", Default: "500", Hint: "Máximo de permutações geradas"},
			{Key: "resolve", Default: "true", Hint: "Promover somente nomes confirmados por DNS"},
			{Key: "parallelism", Default: "20", Hint: "Consultas DNS simultâneas"},
			{Key: "max_runtime_seconds", Default: "20", Hint: "Orçamento global de validação DNS"},
		},
		Factory: func() module.Module { return alterx.New() },
	})
	Register(&Meta{
		Name: "apkosint", Category: CategoryUtil,
		Description: "OSINT de APK Android: Exodus Privacy (trackers/permissions), AndroZoo, MobSF",
		InputTypes:  []string{"name", "url"},
		OutputTypes: []string{"apkosint_app_info", "apkosint_tracker_found", "apkosint_high_risk_permission"},
		Factory:     func() module.Module { return apkosint.New() },
	})
	Register(&Meta{
		Name: "interactsh", Category: CategoryUtil,
		Description: "Servidor OOB para detectar SSRF, XXE, CMDi, DNS rebinding out-of-band",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"oob_interaction"},
		Factory:     func() module.Module { return interactsh.NewPublic() },
	})
	Register(&Meta{
		Name: "notify", Category: CategoryUtil,
		Description: "Envia notificações de findings via Slack, Discord, Telegram, email",
		InputTypes:  []string{"notification"},
		OutputTypes: []string{"notification_sent"},
		Factory:     func() module.Module { return notify.New([]notify.Provider{}) },
	})
	Register(&Meta{
		Name: "ssrfprobe", Category: CategoryUtil,
		Description: "SSRF: probe de parâmetros de URL redirecionando para IP interno/OOB",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"ssrf_found"},
		Factory:     func() module.Module { return ssrfprobe.New() },
	})
	Register(&Meta{
		Name: "smuggler", Category: CategoryUtil,
		Description: "HTTP Request Smuggling: CL.TE e TE.CL via timing e desync",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"request_smuggling"},
		Factory:     func() module.Module { return smuggler.New() },
	})
	Register(&Meta{
		Name: "smuggling", Category: CategoryUtil,
		Description: "HTTP Smuggling timing-based: probe de timing para CL.TE e TE.CL",
		InputTypes:  []string{"url"},
		OutputTypes: []string{"http_smuggling_timing"},
		Factory:     func() module.Module { return smuggling.New() },
	})
	Register(&Meta{
		Name: "uncover", Category: CategoryUtil,
		Description: "Busca referências externas em Shodan, Censys, FOFA, Hunter, Quake e outras fontes sem confirmar exposição automaticamente",
		InputTypes:  []string{"domain", "keyword"},
		OutputTypes: []string{
			"external_inventory_reference",
			"external_vulnerability_reference",
			"external_source_reference",
		},
		Options: []Option{
			{Key: "sources", Default: "shodan", Hint: "Fontes externas separadas por vírgula"},
			{Key: "limit", Default: "100", Hint: "Limite de resultados por fonte"},
			{Key: "max_runtime_seconds", Default: "30", Hint: "Orçamento global de execução"},
		},
		Factory: func() module.Module { return uncover.New() },
	})
}

{
  "input": "Objective: Conduct deep web research to identify and compile a comprehensive list of primary source websites, open-source intelligence (OSINT) platforms, threat tracking databases, and security repositories that actively publish raw lists of malicious URLs, domains, IP addresses, and file hashes.\n\nResearch Guidelines:\n- Find websites, community feeds, and tracking portals (such as URLhaus, PhishTank, MalwareBazaar, ThreatFox, OpenPhish, or active GitHub IOC repositories) that provide live tables, logs, or downloadable feeds of malicious indicators.\n- Include blogs, security researcher feeds, or paste archives that frequently publish real-time cyberattack campaigns and malicious links.\n- Do NOT list the malicious links themselves; instead, provide the landing pages, homepages, search portals, or API feed directories where these malicious links are hosted and displayed.\n\nOutput Requirements:\nPresent the discovered sources in a clean, structured table with the following columns:\n1. Source Name (e.g., Platform or Repository Name)\n2. Website URL (The main source page or search portal)\n3. Type of Indicators Hosted (e.g., Phishing URLs, Malware Hashes, C2 Domains, Ransomware IPs)\n4. Access Type (e.g., Free Public Database, Search Engine, Downloadable CSV/JSON Feed, Community Forum)",
  "output": {
    "executive_summary": "- **Start With The Indicator Type**: URLhaus focuses on malware-delivery URLs, MalwareBazaar on sample hashes, and Feodo Tracker on botnet command-and-control (C2) infrastructure [executive_summary[0]] [14][executive_summary[1]] [11][executive_summary[2]] [1]. Choose a source that matches the indicator you need rather than treating every blacklist as interchangeable.\n- **Distinguish Browsing From Downloading**: The abuse.ch databases can be explored on the web, but URLhaus, MalwareBazaar, and ThreatFox require an Auth-Key for the documented bulk downloads or API access [executive_summary[0]] [14][executive_summary[3]] [40][executive_summary[1]] [11][executive_summary[4]] [33]. Check access requirements before designing an automated collection.\n- **Use Purpose-Built Phishing Feeds**: PhishTank offers hourly database downloads, while OpenPhish's free Community Feed updates every 12 hours; its more frequent premium feeds are commercial [executive_summary[5]] [6][executive_summary[6]] [3]. CERT Polska also distributes a warning list in several machine-readable formats [executive_summary[7]] [64].\n- **Separate Original Feeds From Aggregators**: FireHOL compiles independently maintained IP lists, and MISP indexes feeds with differing formats and conditions [executive_summary[8]] [9][executive_summary[9]] [36]. Inspect the underlying source before using an aggregated hit as grounds for blocking.\n- **Use Ransomware IOC Pages, Not Just Victim Trackers**: Ransomware.live has an IOC page that includes network indicators and file hashes [executive_summary[10]] [2]. Victim-post counts alone do not supply equivalent network evidence.\n- **Treat Search Results As Leads**: urlscan indexes scans that can include benign sites, and Triage's public reports include pending or unclassified submissions [executive_summary[11]] [38][executive_summary[12]] [56]. Investigate an entry before labeling it malicious.\n- **Add Campaign Context**: Cisco Talos, Unit 42, Bitdefender, and other researchers publish campaign-specific IOC files alongside their investigations [executive_summary[13]] [63][executive_summary[14]] [22][executive_summary[15]] [57]. These archives are useful for explaining an indicator but are not necessarily continuously refreshed blocklists.\n\nThe tables below link to **source homepages, browse pages, repository indexes, or feed documentation**. They deliberately do not reproduce any malicious indicator.",
    "malware_delivery_urls_and_file_hash_collections": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| URLhaus | `https://urlhaus.abuse.ch/` | Malware-delivery URLs and associated records [malware_delivery_urls_and_file_hash_collections[0]] [14] | Free public database; CSV/JSON API downloads require an Auth-Key [malware_delivery_urls_and_file_hash_collections[1]] [40] |\n| MalwareBazaar | `https://bazaar.abuse.ch/export/` | Malware-sample hashes and sample metadata [malware_delivery_urls_and_file_hash_collections[2]] [11] | Searchable database; downloadable hash CSV and API access require an Auth-Key [malware_delivery_urls_and_file_hash_collections[2]] [11] |\n| MalShare | `https://www.malshare.com/` | Recently submitted file samples and SHA-256 hashes [malware_delivery_urls_and_file_hash_collections[3]] [16] | Public recent-sample table and search; registered-user API offers recent hash lists [malware_delivery_urls_and_file_hash_collections[4]] [58] |\n| VirusShare | `https://virusshare.com/search` | Malware samples searchable by multiple file-hash algorithms [malware_delivery_urls_and_file_hash_collections[5]] [10] | Search and sample-download portal; login required [malware_delivery_urls_and_file_hash_collections[5]] [10] |\n| Triage public reports | `https://tria.ge/reports` | Submitted files, SHA-256 fields, analysis status and scores [malware_delivery_urls_and_file_hash_collections[6]] [56] | Public report-search portal; submissions are not all confirmed malware [malware_delivery_urls_and_file_hash_collections[6]] [56] |\n\n**How to use these together:** If an investigation starts with a suspected malware download, URLhaus is a place to examine the delivery URL; a sample-hash collection is a different place to examine the file. This is a *workflow*, not an assertion that every URL has a matching sample in every database. MalwareBazaar's recent hash datasets are generated every five minutes, but access to the export requires its Auth-Key [malware_delivery_urls_and_file_hash_collections[2]] [11].",
    "phishing_url_and_dangerous_domain_feeds": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| PhishTank | `https://phishtank.org/developer_info.php` | Community-reported phishing URLs [phishing_url_and_dangerous_domain_feeds[0]] [65] | Free public database; hourly XML, CSV, PHP and JSON downloads, with an application key needed for automated fetching [phishing_url_and_dangerous_domain_feeds[1]] [6] |\n| OpenPhish | `https://openphish.com/phishing_feeds.html` | Phishing URLs; additional metadata in commercial tiers [phishing_url_and_dangerous_domain_feeds[2]] [3] | Free 12-hour text feed; more frequent CSV/JSON feeds are commercial [phishing_url_and_dangerous_domain_feeds[2]] [3] |\n| PhishStats | `https://phishstats.info/api-docs` | Searchable phishing URLs, IPs, ASNs and scores [phishing_url_and_dangerous_domain_feeds[3]] [17] | Public read-only API with authentication-dependent quotas [phishing_url_and_dangerous_domain_feeds[3]] [17] |\n| phishunt | `https://phishunt.io/feed` | Suspicious phishing URLs and associated domains [phishing_url_and_dangerous_domain_feeds[4]] [20] | Public TXT, JSON and CSV downloads; hourly updates [phishing_url_and_dangerous_domain_feeds[4]] [20] |\n| PhishDestroy live feed | `https://phishdestroy.io/live` | Recently detected phishing domains and associated infrastructure [phishing_url_and_dangerous_domain_feeds[5]] [61] | Public live table and raw JSON feed; some entries await further confirmation [phishing_url_and_dangerous_domain_feeds[5]] [61] |\n| CERT Polska Dangerous websites Warning List | `https://cert.pl/en/warning-list` | Domains used to deceive users and steal data or credentials [phishing_url_and_dangerous_domain_feeds[6]] [64] | Public downloads in text, TSV, JSON, XML, hosts, RPZ and other formats [phishing_url_and_dangerous_domain_feeds[6]] [64] |\n| Phishing.Database | `https://github.com/Phishing-Database/Phishing.Database` | Phishing URL and domain lists, including active-status files [phishing_url_and_dangerous_domain_feeds[7]] [13] | Public GitHub repository with regularly retested lists [phishing_url_and_dangerous_domain_feeds[7]] [13] |\n\n**Versioning matters:** CERT Polska deprecated the first version of its warning list and discontinued legacy-format downloads from June 2025; its maintained replacement is version 2 [phishing_url_and_dangerous_domain_feeds[8]] [62]. This is a concrete reason to use the landing page and current documentation, rather than copying a historical feed address into an automated job. Likewise, phishunt describes its entries as *suspicious* sites, not a guarantee that every entry is a confirmed phish [phishing_url_and_dangerous_domain_feeds[4]] [20].",
    "botnet_c2_and_ransomware_infrastructure": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| ThreatFox | `https://threatfox.abuse.ch/export/` | Malware-associated C2 and payload-delivery domains, network IOCs and searchable hashes [botnet_c2_and_ransomware_infrastructure[0]] [33][botnet_c2_and_ransomware_infrastructure[1]] [34] | Public browse database; CSV, JSON, MISP and other exports require a free community Auth-Key [botnet_c2_and_ransomware_infrastructure[0]] [33] |\n| Feodo Tracker | `https://feodotracker.abuse.ch/blocklist/` | Botnet C2 IP addresses and related IOC records [botnet_c2_and_ransomware_infrastructure[2]] [1][botnet_c2_and_ransomware_infrastructure[3]] [35] | Public text, JSON and CSV blocklists/feeds [botnet_c2_and_ransomware_infrastructure[3]] [35] |\n| SSLBL | `https://sslbl.abuse.ch/blacklist/` | Botnet C2 IPs, suspect TLS certificates and JA3 fingerprints [botnet_c2_and_ransomware_infrastructure[4]] [41] | Public CSV, IP-only text, rulesets and DNS RPZ feeds [botnet_c2_and_ransomware_infrastructure[4]] [41] |\n| Ransomware.live IOCs | `https://www.ransomware.live/ioc` | Ransomware-related domains, URLs, IPs and file hashes [botnet_c2_and_ransomware_infrastructure[5]] [2] | Public IOC browsing page; separate public API documentation is available [botnet_c2_and_ransomware_infrastructure[6]] [47] |\n| Criminal IP C2 Daily Feed | `https://github.com/criminalip/C2-Daily-Feed` | C2 IP addresses [botnet_c2_and_ransomware_infrastructure[7]] [31] | Public GitHub list publishing a daily sample of 50 IPs [botnet_c2_and_ransomware_infrastructure[7]] [31] |\n| C2-Tracker | `https://github.com/montysecurity/C2-Tracker` | Malware, botnet and C2 IPs organized by tool, plus a combined list [botnet_c2_and_ransomware_infrastructure[8]] [53] | Public GitHub IOC feed; its documentation specifies weekly updates [botnet_c2_and_ransomware_infrastructure[8]] [53] |\n\n**Different mechanisms call for different controls.** Feodo's recommended blocklist targets C2 IPs, whereas SSLBL also supplies certificate and TLS-fingerprint indicators [botnet_c2_and_ransomware_infrastructure[3]] [35][botnet_c2_and_ransomware_infrastructure[4]] [41]. ThreatFox supports broader malware IOC investigation, while Ransomware.live exposes ransomware-specific records [botnet_c2_and_ransomware_infrastructure[1]] [34][botnet_c2_and_ransomware_infrastructure[5]] [2]. An IP-only firewall import will not make use of a certificate fingerprint or a file hash; select the feed format to fit the control.",
    "attack_ip_lists_and_domain_blocklists": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| Spamhaus DROP | `https://www.spamhaus.org/blocklists/do-not-route-or-peer` | Networks associated with professional spam or cybercrime operations, including malware and botnet activity [attack_ip_lists_and_domain_blocklists[0]] [54] | Free JSON datasets intended for network blocking; observe attribution terms [attack_ip_lists_and_domain_blocklists[0]] [54] |\n| Spamhaus Blocklist (SBL) | `https://www.spamhaus.org/blocklists/spamhaus-blocklist` | IPs implicated in spam, malicious hosting, hijacked address space or bulletproof hosting [attack_ip_lists_and_domain_blocklists[1]] [59] | IP/listing lookup and DNS blocklist; low-volume, noncommercial DNSBL use is free [attack_ip_lists_and_domain_blocklists[1]] [59] |\n| blocklist.de | `https://blocklist.de/en/export.html` | Attack-source IPs, with service-specific and recent-activity lists [attack_ip_lists_and_domain_blocklists[2]] [15] | Public downloadable IP exports [attack_ip_lists_and_domain_blocklists[2]] [15] |\n| SANS ISC / DShield feeds | `https://www.dshield.org/feeds_doc.html` | Attacking source IPs, active networks and related summaries [attack_ip_lists_and_domain_blocklists[3]] [19] | Public documented feeds; attribution requested and resale prohibited [attack_ip_lists_and_domain_blocklists[3]] [19] |\n| AbuseIPDB | `https://www.abuseipdb.com/` | Community-reported abusive IP addresses [attack_ip_lists_and_domain_blocklists[4]] [32] | Public lookup and reporting portal; free registered-account API [attack_ip_lists_and_domain_blocklists[4]] [32] |\n| FireHOL IP Lists | `https://iplists.firehol.org/` | Multiple third-party attack and abuse IP lists [attack_ip_lists_and_domain_blocklists[5]] [9] | Public searchable feed index and downloadable IP sets; individual lists have different owners [attack_ip_lists_and_domain_blocklists[5]] [9] |\n| GreenSnow | `https://greensnow.co/` | IPs associated with observed attacks against servers [attack_ip_lists_and_domain_blocklists[6]] [39][attack_ip_lists_and_domain_blocklists[7]] [60] | Public downloadable, automatically updated IP blocklist [attack_ip_lists_and_domain_blocklists[6]] [39] |\n| Project Honey Pot | `https://www.projecthoneypot.org/list_of_ips.php` | IPs recorded in its malicious-IP directory [attack_ip_lists_and_domain_blocklists[8]] [29] | Public top-25 browse list; joining provides additional participant functions [attack_ip_lists_and_domain_blocklists[8]] [29] |\n\n**Blocking decision:** Spamhaus DROP describes malicious *netblocks*, while blocklist.de and DShield expose observed attack-source IPs [attack_ip_lists_and_domain_blocklists[0]] [54][attack_ip_lists_and_domain_blocklists[2]] [15][attack_ip_lists_and_domain_blocklists[3]] [19]. FireHOL is an aggregator rather than the originator of all its lists [attack_ip_lists_and_domain_blocklists[5]] [9]. Those differences affect how broadly a rule may block traffic and how easily an investigator can trace an entry to its reporting source. FireHOL itself warns that injudicious blacklisting can block legitimate users [attack_ip_lists_and_domain_blocklists[9]] [37].",
    "osint_search_and_feed_directories": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| LevelBlue / AlienVault OTX | `https://otx.alienvault.com/` | Community-shared threat indicators grouped into Pulses [osint_search_and_feed_directories[0]] [12] | Threat-intelligence portal; subscribed-Pulse API and TAXII access use an account API key [osint_search_and_feed_directories[1]] [43] |\n| Pulsedive Explore | `https://pulsedive.com/explore/` | Searchable IP, IPv6, domain and URL indicators, with risk and feed context [osint_search_and_feed_directories[2]] [42] | Public search with limited initial results; account enables broader browsing/export [osint_search_and_feed_directories[2]] [42] |\n| urlscan.io search | `https://urlscan.io/search/` | Scanned URLs and associated domain/IP observations; scans are not necessarily malicious [osint_search_and_feed_directories[3]] [38] | Public search; API search supports domains, IPs and hashes, with API-key and quota conditions [osint_search_and_feed_directories[4]] [52] |\n| MISP default feeds | `https://www.misp-project.org/feeds/` | Directory of OSINT and other indicator feeds in MISP, CSV or freetext forms [osint_search_and_feed_directories[5]] [36] | Public feed directory; availability and licensing vary by individual feed [osint_search_and_feed_directories[5]] [36] |\n\n**Investigative distinction:** A matching urlscan result shows that a page was scanned, not that it was convicted as malicious [osint_search_and_feed_directories[3]] [38]. OTX Pulses and MISP feeds add sharer or feed context; that context helps an analyst decide what to validate next, but it does not turn every submitted observable into a safe automatic block. Pulsedive's export includes source-feed and risk fields that can assist that review [osint_search_and_feed_directories[2]] [42].",
    "maintained_github_ioc_repositories": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| Cisco Talos IOCs | `https://github.com/Cisco-Talos/IOCs` | Campaign IOC files, including phishing-framework investigations [maintained_github_ioc_repositories[0]] [23][maintained_github_ioc_repositories[1]] [63] | Public GitHub archive; its August 2026 directory contains JSON and TXT files [maintained_github_ioc_repositories[1]] [63] |\n| ESET malware-ioc | `https://github.com/eset/malware-ioc` | Investigation-specific sample hashes and other security indicators [maintained_github_ioc_repositories[2]] [24] | Public GitHub research repository [maintained_github_ioc_repositories[2]] [24] |\n| Unit 42 timely threat intelligence | `https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel` | Dated campaign IOC files containing domains, URLs, IPs and hashes [maintained_github_ioc_repositories[3]] [22] | Public GitHub text-file archive with 2026 entries [maintained_github_ioc_repositories[3]] [22] |\n| Bitdefender malware-ioc | `https://github.com/bitdefender/malware-ioc` | IOCs accompanying malware research papers [maintained_github_ioc_repositories[4]] [57] | Public GitHub archive containing 2026 IOC CSV files [maintained_github_ioc_repositories[4]] [57] |\n| TweetFeed | `https://github.com/0xDanielLopez/TweetFeed` | Researcher-shared URLs, domains, IPs, MD5 and SHA-256 hashes [maintained_github_ioc_repositories[5]] [26] | Public GitHub collection with a 2026 directory [maintained_github_ioc_repositories[5]] [26] |\n| OpenPhish Community Feed mirror | `https://github.com/openphish/public_feed` | Phishing URLs in the project's feed file [maintained_github_ioc_repositories[6]] [25] | Public GitHub text feed, updated every 12 hours; **noncommercial use only** [maintained_github_ioc_repositories[6]] [25] |\n| FireHOL blocklist-ipsets | `https://github.com/firehol/blocklist-ipsets` | Source-specific, dynamically updated IP sets [maintained_github_ioc_repositories[7]] [37] | Public GitHub repository; check each constituent list's provenance and terms [maintained_github_ioc_repositories[7]] [37] |\n| IPsum | `https://github.com/stamparm/ipsum` | Bad-IP lists annotated with counts of source-list appearances [maintained_github_ioc_repositories[8]] [55] | Public GitHub feed rebuilt daily [maintained_github_ioc_repositories[8]] [55] |\n| HaGeZi DNS blocklists | `https://github.com/hagezi/dns-blocklists` | Security-oriented domain lists covering malware, phishing and C2, alongside other blocking categories [maintained_github_ioc_repositories[9]] [50] | Public GitHub DNS-blocklist repository; builds occur several times daily [maintained_github_ioc_repositories[9]] [50] |\n\n**Campaign case study:** Cisco Talos keeps dated TXT and JSON files for August 2026 investigations, including a phishing-framework case [maintained_github_ioc_repositories[1]] [63]. Unit 42 also maintains dated text files supporting its timely threat-intelligence posts [maintained_github_ioc_repositories[3]] [22]. These are useful when the question is *which campaign produced an indicator and what else appeared with it*; for a continuously refreshed defensive list, the dedicated feed pages above are the more direct starting point. A repo's presence here should not be read as a promise that every individual campaign file remains current.",
    "campaign_diaries_and_research_archives": "| Source Name | Website URL | Type of Indicators Hosted | Access Type |\n|---|---|---|---|\n| SANS Internet Storm Center diaries | `https://isc.sans.edu/diaryarchive.html` | Incident-specific traffic indicators, hashes and file details in individual diaries [campaign_diaries_and_research_archives[0]] [46] | Public, dated researcher diary archive [campaign_diaries_and_research_archives[1]] [66] |\n| Malware-Traffic-Analysis.net | `https://www.malware-traffic-analysis.net/2026/index.html` | Malware-infection case notes and downloadable traffic/analysis attachments [campaign_diaries_and_research_archives[2]] [45][campaign_diaries_and_research_archives[3]] [51] | Public campaign-post archive; some attached files are password-protected [campaign_diaries_and_research_archives[3]] [51] |\n| Cisco Talos Blog | `https://blog.talosintelligence.com/` | Campaign narratives to read alongside Talos's separate IOC files [campaign_diaries_and_research_archives[4]] [30][campaign_diaries_and_research_archives[5]] [63] | Public security-research blog; use the Talos repository above for the raw TXT/JSON files [campaign_diaries_and_research_archives[5]] [63] |\n\nThese archives answer a different question from a rolling feed: *what happened in a particular investigation?* For example, a Malware-Traffic-Analysis.net case page supplies research notes, a traffic capture and a malware archive rather than a continuously refreshed domain blocklist [campaign_diaries_and_research_archives[3]] [51]. SANS diaries likewise present indicators within incident write-ups [campaign_diaries_and_research_archives[0]] [46]. Treat attachments as investigation material, not automatically as ready-to-deploy blocks.",
    "synthesis": "| Source class | How indicators arrive | Best use | Principal trade-off |\n|---|---|---|---|\n| Original operational feeds | Community reports, samples or tracked botnet infrastructure [synthesis[0]] [14][synthesis[1]] [67][synthesis[2]] [1] | Ongoing URL, hash or C2 collection | Narrow scope by design; bulk-access rules vary [synthesis[3]] [40][synthesis[4]] [11] |\n| IP/domain blocking lists | Threat research or attack observations [synthesis[5]] [54][synthesis[6]] [19] | Matching an enforcement control to IPs, networks or domains | False positives and different blocking breadth require care [synthesis[7]] [37] |\n| Search portals and aggregators | Shared Pulses, public scans or constituent feeds [synthesis[8]] [12][synthesis[9]] [38][synthesis[10]] [9] | Discovery, enrichment and cross-checking | A search hit may be unverified or not malicious [synthesis[9]] [38] |\n| Campaign repositories and diaries | Research files and incident write-ups [synthesis[11]] [63][synthesis[12]] [46] | Attribution, context and retrospective hunting | A dated report is not a live blocklist |\n\nThe practical starting point is the **question being asked**: use a phishing feed for candidate phishing URLs, a hash-indexed sample database for a file, a C2 feed for infrastructure, and a campaign archive for context. Then check the publisher's current access terms, recency and classification before using an indicator operationally. The four classes complement one another, but neither a broad aggregator nor a research article replaces the provenance of an original feed."
  },
  "outputBasis": [
    {
      "field": "executive_summary",
      "citations": [
        {
          "title": "URLhaus | Malware URL exchange",
          "url": "https://urlhaus.abuse.ch/",
          "excerpts": [
            "URLhaus is a platform from abuse.ch and Spamhaus dedicated to sharing malicious URLs that are being used for malware distribution.",
            "Browse malware URLs Gain valuable insights and find the latest malicious URLs being used for malware distribution. [Access database »](https://urlhaus.abuse.ch/browse/)",
            "Use the APIs, to seamlessly push and pull signals, and automate bulk queries."
          ]
        },
        {
          "title": "MalwareBazaar | Export",
          "url": "https://bazaar.abuse.ch/export/",
          "excerpts": [
            "MalwareBazaar offers the exporting of hash lists in the following formats:",
            "**Recent** datasets (\"recent additions\") include hashes for the last 48 hours and are being generated every **5 minutes** . Please do not fetch them more often than that. **Full** data dumps include all hashes and are only being generated once per hour.",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first.",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include the URI parameter `auth-key` which contains your Auth-Key as value."
          ]
        },
        {
          "title": "Feodo Tracker",
          "url": "https://feodotracker.abuse.ch/",
          "excerpts": [
            "Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor). It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo.",
            "It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo. [Download Blocklist »](https://feodotracker.abuse.ch/blocklist/)",
            "Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor). It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo. [Download Blocklist »](https://feodotracker.abuse.ch/blocklist/)"
          ]
        },
        {
          "title": "URLhaus | Community API",
          "url": "https://urlhaus.abuse.ch/api/",
          "excerpts": [
            "You can choose between CSV and JSON format.",
            "Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL.",
            "Manual submissions through the URLhaus [web interface](https://urlhaus.abuse.ch/browse/) (note: you need to authenticate yourself with your [abuse.ch account](https://auth.abuse.ch/ \"Login to abuse.ch\") )"
          ]
        },
        {
          "title": "ThreatFox | Export",
          "url": "https://threatfox.abuse.ch/export/",
          "excerpts": [
            "ThreatFox offers the exporting of indicators of compromise (IOCs) in following formats: Auth-Key ( **Required** ) Daily MISP Events Suricata IDS Ruleset DNS Response Policy Zone (RPZ) host file (domain only) JSON file CSV files",
            "For this purpose, ThreatFox offers a list of domain based IOCs. The host file below contains the following datasets observed in the **past 6 month** : Payload delivery domains Botnet C2 domains The following file gets generated every **5 minutes** .",
            "ThreatFox provides a ruleset containing all network based Indicators Of Compromise (IOCs) for [Suricata IDS](https://suricata-ids.org/ \"Suricata IDS\") . As we believe that IOCs have an expiration date too and to avoid false positive, we only export IOCs for the **past 6 month** . Please note that the ruleset has been tested with Suricata version 6.0.0. The ruleset gets generated **every 5 minutes** . To achieve the best protection, we recommend to fetch it every 5 minutes.",
            "By using an DNS Reponse Policy Zone (RPZ), also known as DNS firewall, you can detect the resolution of certain domain names ovserved in the **past 6 month** on your DNS resolver. ThreatFox offerst the following IOCs as RPZ dataset: Payload delivery domains Botnet C2 domains More information about DNS RPZ can be found on [dnsrpz.info](https://dnsrpz.info/ \"DNS Response Policy Zones\") . The following file gets generated every **5 minutes** . To achieve the best protection, we recommend to fetch it every 5 minutes.",
            "The following data exports exists in JSON format: Login required In order to view this documentation, you need to and create an `Auth-Key` . CSV files * * The following data exports exists in CSV format:",
            "Obtain an Auth-Key ( **Required** ) * * In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL. Example curl command: ``` curl -i \"https://threatfox-api.abuse.ch/v2/files/exports/YOUR-AUTH-KEY-HERE/full.csv.zip\" ```",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL."
          ]
        },
        {
          "title": "PhishTank > Developer Information",
          "url": "https://phishtank.org/developer_info.php",
          "excerpts": [
            "Get the Database If you'll be doing lots of lookups, the best option is to take advantage of our downloadable databases. Available in multiple formats and updated hourly, these make it easy to have fast and up to date phishing detection built into your application. The data is available in a variety of formats to make it as easy as possible for you to implement.",
            "If you do intend to fetch these files automatically, please register for an application key and see below for instructions on how to use it to request files. Without this key, you will be limited to a few downloads per day.",
            "We require that you use a descriptive User Agent string in your application to identify the application. If your User Agent is blank or generic, you may recieve an increased number of rate limited requests or be redirected to additional security checks.",
            "Get the Database If you'll be doing lots of lookups, the best option is to take advantage of our downloadable databases. Available in multiple formats and updated hourly, these make it easy to have fast and up to date phishing detection built into your application. The data is available in a variety of formats to make it as easy as possible for you to implement. We're always open to suggestions for additional formats we could provide, so if you have any thoughts, please join our developers list and let us know! If you do intend to fetch these files automatically, please register for an application key and see below for instructions on how to use it to request files. Without this key, you will be limited to a few downloads per day.",
            "Format Options |XML | |http://data.phishtank.com/data/online-valid.xml | |http://data.phishtank.com/data/online-valid.xml.gz | |http://data.phishtank.com/data/online-valid.xml.bz2 | |CSV | |http://data.phishtank.com/data/online-valid.csv | |http://data.phishtank.com/data/online-valid.csv.gz | |http://data.phishtank.com/data/online-valid.csv.bz2 | |Serialized PHP | |http://data.phishtank.com/data/online-valid.php\\_serialized | |http://data.phishtank.com/data/online-valid.php\\_serialized.gz | |http://data.phishtank.com/data/online-valid.php\\_serialized.bz2 | |JSON | |http://data.phishtank.com/data/online-valid.json | |http://data.phishtank.com/data/online-valid.json.gz | |http://data.phishtank.com/data/online-valid.json.bz2 |"
          ]
        },
        {
          "title": "OpenPhish - Phishing Feeds",
          "url": "https://openphish.com/phishing_feeds.html",
          "excerpts": [
            "12 hours Limited * * * * * * * [Terms of Use](https://openphish.com/terms.html) Text File [Free](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt) ¹",
            "Premium 5 minutes * * * * * * * * * CSV, JSON",
            "The Intelligence Pack offers enhanced metadata and specialized data feeds to help you track high-risk activities and gain deeper insights into the phishing threat landscape.",
            "12 hours Limited * * * * * * * [Terms of Use](https://openphish.com/terms.html) Text File [Free](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt) ¹ Premium 5 minutes * * * * * * * * * CSV, JSON",
            "Phishing URLs Targeted Brand IP and ASN GeoIP Industry Sector 30 Days Archive Page Language SSL Metadata",
            "Premium 5 minutes * * * * * * * * * CSV, JSON [Contact Us](mailto:contact@openphish.com) ² Platinum 5 minutes * * * * * * * * * CSV, JSON [Contact Us](mailto:contact@openphish.com) The Intelligence Pack offers enhanced metadata and specialized data feeds to help you track high-risk activities and gain deeper insights into the phishing threat landscape."
          ]
        },
        {
          "title": "    Dangerous websites Warning List | CERT Polska\n",
          "url": "https://cert.pl/en/warning-list",
          "excerpts": [
            "From March 2020 we continuously provide a list of dangerous websites (the Warning List, the List). We maintain it 24 hours a day, 7 days per week and update with all domains that trick Polish internet users to steal their data and credentials. Phishing websites collecting personal data and credentials are now a mass phenomenon, affecting various groups of internet users in Poland. Links to such webpages are sent through various channels: SMS, e-mail or social media. The websites are registered in large numbers and used within a short time of registration, after which they are abandoned in favor of new addresses.",
            "Available formats text format, active domains only, single domain per line – <https://hole.cert.pl/domains/v2/domains.txt> TSV (tab-separated values) format – <https://hole.cert.pl/domains/v2/domains.csv> JSON format – <https://hole.cert.pl/domains/v2/domains.json> XML format – <https://hole.cert.pl/domains/v2/domains.xml> ad-blocker list compatible with uBlock Origin and AdGuard AdBlocker browser extensions – [https://hole.cert.pl/domains/v2/domains\\_adblock.txt](https://hole.cert.pl/domains/v2/domains_adblock.txt) hosts format – [https://hole.cert.pl/domains/v2/domains\\_hosts.txt](https://hole.cert.pl/domains/v2/domains_hosts.txt) .rsc format, limited to 4096 bytes, for MikroTik/RouterOS systems – [https://hole.cert.pl/domains/v2/domains\\_mikrotik.rsc](https://hole.cert.pl/domains/v2/domains_mikrotik.rsc) RPZ (Response Policy Zones) blacklist format – [https://hole.cert.pl/domains/v2/domains\\_rpz.db](https://hole.cert.pl/domains/v2/domains_rpz.db)",
            "Changes introduced in the second version of the List In response to changing threats and the ever-growing size of the List, we have decided to make a few changes in the operation of the List that will help us to better respond to new threats, and help users to integrate it more easily: domains are blocked for a **6 month** period, after this time if a domain is still considered as dangerous it will be added as a new entry considering the above, all List formats are time-limited to the last 6 months - this will solve the problem of having to download increasingly large files at short intervals in order to maintain transparency regarding blocked domains, a data stream has been introduced – \"actions.log\". It lists all domains we add to the Warning List and remove from it grouped by year in addition to blocking the domains on the List, we also recommend blocking traffic to their subdomains"
          ]
        },
        {
          "title": "FireHOL IP Lists | IP Blacklists | IP Blocklists | IP Reputation",
          "url": "https://iplists.firehol.org/",
          "excerpts": [
            "This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** .",
            "It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data.",
            "The data on this page are automatically generated using FireHOL's [update-ipsets.sh](https://github.com/firehol/firehol/blob/master/sbin/update-ipsets) (for downloading the lists from their sources and generating the data for this site), which utilizes [iprange](https://github.com/firehol/firehol/wiki/iprange:-optimizing-ipsets-for-iptables) (for comparing and manipulating IP lists).",
            "This site is a single **static** page, with all its data uploaded as static JSON and CSV files every time an IP List is updated.",
            "It uses IP lists and related data provided and maintained by their respective owners (mentioned together with each IP list), IP-to-country geolocation data provided by [maxmind.com](https://www.maxmind.com/) (GeoLite2), [ipdeny.com](http://www.ipdeny.com/) , [ip2location.com](http://www.ip2location.com/) (Lite) and [ipip.net](http://ipip.net/) , javascript chart libraries provided by [highcharts.com](http://www.highcharts.com/) , comments engine provided by [disqus.com](https://disqus.com/) , social media sharing buttons provided by [shareaholic.com](https://shareaholic.com/) , the HTML, CSS and JS framework [bootstrap](https://getbootstrap.com/) , the [bootstrap-table](http://bootstrap-table.wenzhixin.net.cn/) component, icons provided by [iconsdb.com](http://www.iconsdb.com/) and it uses several services provided by [github](https://github.com/) .",
            "This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** . It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data.",
            "This site is a single **static** page, with all its data uploaded as static JSON and CSV files every time an IP List is updated. For the final result, it utilizes IP data and web services provided by third parties. It uses IP lists and related data provided and maintained by their respective owners (mentioned together with each IP list), IP-to-country geolocation data provided by [maxmind.com](https://www.maxmind.com/) (GeoLite2), [ipdeny.com](http://www.ipdeny.com/) , [ip2location.com](http://www.ip2location.com/) (Lite) and [ipip.net](http://ipip.net/) , javascript chart libraries provided by [highcharts.com](http://www.highcharts.com/) , comments engine provided by [disqus.com](https://disqus.com/) , social media sharing buttons provided by [shareaholic.com](https://shareaholic.com/) , the HTML, CSS and JS framework [bootstrap](https://getbootstrap.com/) , the [bootstrap-table](http://bootstrap-table.wenzhixin.net.cn/) component, icons provided by [iconsdb.com](http://www.iconsdb.com/) and it uses several services provided by [github](https://github.com/) . × About this site This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** . It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data."
          ]
        },
        {
          "title": "MISP Default Feeds",
          "url": "https://www.misp-project.org/feeds/",
          "excerpts": [
            "MISP includes a set of public OSINT feeds in its default configuration. The feeds can be used as a source of correlations for all of your events and attributes without the need to import them directly into your system.",
            "The feeds can be in three different formats: [MISP standardized format](https://github.com/MISP/misp-rfc/blob/master/misp-core-format/raw.md.txt) which is the preferred format to benefit from all the MISP functionalities. CSV format, allowing you to pick the columns that are to be imported. freetext format which allows automatic ingestion and detection of indicator/attribute by parsing any unstructured text. and located in different input transports: Network (URL) Local (file)",
            "[IPs from High-Confidence DGA-Based C&Cs Actively Resolving - requires a valid license](https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt) \\- osint.bambenekconsulting.com - feed format: csv",
            "[IPsum (aggregation of all feeds) - level 1 - lot of false positives](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt) \\- IPsum - feed format: freetext",
            "MISP includes a set of public OSINT feeds in its default configuration. The feeds can be used as a source of correlations for all of your events and attributes without the need to import them directly into your system. The MISP feed system allows for fast correlation but also a for quick comparisons of the feeds against one another. The feeds can be in three different formats: [MISP standardized format](https://github.com/MISP/misp-rfc/blob/master/misp-core-format/raw.md.txt) which is the preferred format to benefit from all the MISP functionalities. CSV format, allowing you to pick the columns that are to be imported. freetext format which allows automatic ingestion and detection of indicator/attribute by parsing any unstructured text. and located in different input transports: Network (URL) Local (file)",
            "[IPs from High-Confidence DGA-Based C&Cs Actively Resolving - requires a valid license](https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt) \\- osint.bambenekconsulting.com - feed format: csv [ipspamlist](http://www.ipspamlist.com/public_feeds.csv) \\- ipspamlist - feed format: csv [IPsum (aggregation of all feeds) - level 1 - lot of false positives](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt) \\- IPsum - feed format: freetext"
          ]
        },
        {
          "title": "IoCs",
          "url": "https://www.ransomware.live/ioc",
          "excerpts": [
            "Indicators of Compromise (IoCs) by Group",
            "Contact info (Tox, Session, Telegram, Email)",
            "Hash (MD5 & SHA256)",
            "IP Addresses",
            "|`Domain` |`crpx0.su`  | |`Domain` |`crpxoxo.pw`  | |`Domain` |`option.spark198.com`  |",
            "|`IP Address` |`104.18.20.226` Cloudflare, Inc. | |`IP Address` |`104.18.21.226` Cloudflare, Inc. | |`IP Address` |`140.248.136.175` Fastly, Inc. | |`IP Address` |`146.75.116.175` Fastly, Inc. Germany | |`IP Address` |`146.75.120.175` Fastly, Inc. Germany | |`IP Address` |`146.75.122.133` Fastly, Inc. Germany | |`IP Address` |`151.101.0.223` Fastly, Inc. United States | |`IP Address` |`151.101.128.223` Fastly, Inc. United States | |`IP Address` |`151.101.192.223` Fastly, Inc. United States | |`IP Address` |`23.224.4.114` CNSERVERS LLC United States | |`IP Address` |`48.192.1.65` Microsoft Corporation United States | |`Session` |`050546f6719172e04151c31acb37a242fa3eeff5766aa57331d26cc06e83e9e25b` | |`Tox` |`17EB54B8455144E088C7E77F88A97221C319F0CFE4FE306853EEB113EE8DB5607BB6EE481C7C` | |`URL` |`https://23.224.4.114` | |`URL` |`https://23.224.4.115` | |`URL` |`https://23.224.4.116` | |`URL` |`https://23.224.4.117` | |`URL` |`https://23.224.4.118` |",
            "Akira Bitcoin Wallet 15 Hash MD5 320 Hash SHA256 37 IP Address 1 Mutex 2",
            "|`Bitcoin Wallet` |`bc1q6dqe4esmqejmxhpj95qadv0j4clsqcxxp4cd94`   | |`Bitcoin Wallet` |`bc1qandfxc4knaf943njca77edl9mmegzs83tv8lpx`   | |`Bitcoin Wallet` |`bc1qcnw5v94y40ast06eatgalnjpluu2p067qewh46`   | |`Bitcoin Wallet` |`bc1qghj85gz0dkr9jeucana3z4xu50ujtllj50rvj0`   | |`Bitcoin Wallet` |`bc1qpwwtck0zhzrj56fxeayz6wz5546nlp607qzpvh`   | |`Bitcoin Wallet` |`bc1qr0pqfghr9cksfc5arr2rak3lt2y50v03pc76nh`   | |`Bitcoin Wallet` |`bc1qr0txunr259we37wer7w6et33qyq0n6hv83pw24`   |",
            "Conti Bitcoin Wallet 103",
            "Crpxo Domain 3 Hash MD5 16 IP Address 11 Session 1 Tox 1 URL 5",
            "|`URL` |`https://23.224.4.114` |",
            "|`IP Address` |`45.227.253.59:3111` Alviva Holding Limited Panama |",
            "|`Hash MD5` |`12e22f588f6128cf1a042d1122556cd2`  |",
            "|`Hash SHA1` |`74b3c1b58e12f3d854dc3ac7a5f05578faa8916c`  |",
            "|Type |IOC |"
          ]
        },
        {
          "title": "Search - urlscan.io",
          "url": "https://urlscan.io/search/",
          "excerpts": [
            "Search for domains, IPs, filenames, hashes, ASNs Search Scans",
            "Search results (100 / 10000 \\+ , sorted by date, took 20ms) Showing All Hits Details: Hidden |URL |Age |Size | |",
            "(10000 results in total, 100 shown)",
            "|Public [www.credit-agricole-conseil-invest.ph/](https://urlscan.io/result/01a0d710-44e3-7608-a1cc-6980a37ed33e/ \"www.credit-agricole-conseil-invest.ph/\") |10 seconds |1 |1 |0 | |",
            "|Public [www.sindonews.com/](https://urlscan.io/result/01a0d710-80c8-7133-a2fc-acf75d6e84e2/ \"www.sindonews.com/\") |14 seconds |4 MB |207 |35 |5 | |",
            "|Public [www.davidzwirner.com/collect](https://urlscan.io/result/01a0d70f-c8e9-76ad-89b9-d4be7df7783a/ \"www.davidzwirner.com/collect\") |19 seconds |1 MB |70 |4 |2 | |"
          ]
        },
        {
          "title": "Reports |  Triage™ ",
          "url": "https://tria.ge/reports",
          "excerpts": [
            "Search Sample ID Created Filename Tags Status/Score SHA256",
            "Reports * Search Sample ID Created Filename Tags Status/Score SHA256 260622-1wvq8agx4n 22/06/2026, 22:00 https://linktr.ee/nyckidsris Running N/A 260622-1wnb5sg13x 22/06/2026, 22:00 http://nyckidsrise.org/ Running N/A 260622-1wltbagx4m 22/06/2026, 22:00 https://skill-pharmaceutical-societies-roots.trycloudflare.com/NDMxRzFtOXc4QzFUMUw= Running N/A 260622-1wkagsg13w 22/06/2026, 21:59 \\_b2042a3d582987297d3e21e4ec35813e608d2c2b18db409edb36c1173f0b5520.exe Running 260622-1wjzqagx4l 22/06/2026, 21:59 setup.bat Running 260622-1whfwsg13v 22/06/2026, 21:59 \\_7e1e3dd418f70e0a973727bd106ed4bee047dd79a8d1c20004d37ceb477d5d6a.exe Running 260622-1wgvcsg13t 22/06/2026, 21:59 ccsetup639\\_pro.exe Pending N/A 260622-1wafaagx4k 22/06/2026, 21:59 2753\\_260128174907\\_001.pdf adware discovery spyware 3 Reported",
            "260622-1wvq8agx4n 22/06/2026, 22:00 https://linktr.ee/nyckidsris Running N/A 260622-1wnb5sg13x 22/06/2026, 22:00 http://nyckidsrise.org/ Running N/A 260622-1wltbagx4m 22/06/2026, 22:00 https://skill-pharmaceutical-societies-roots.trycloudflare.com/NDMxRzFtOXc4QzFUMUw= Running N/A 260622-1wkagsg13w 22/06/2026, 21:59 \\_b2042a3d582987297d3e21e4ec35813e608d2c2b18db409edb36c1173f0b5520.exe Running 260622-1wjzqagx4l 22/06/2026, 21:59 setup.bat Running 260622-1whfwsg13v 22/06/2026, 21:59 \\_7e1e3dd418f70e0a973727bd106ed4bee047dd79a8d1c20004d37ceb477d5d6a.exe Running 260622-1wgvcsg13t 22/06/2026, 21:59 ccsetup639\\_pro.exe Pending N/A 260622-1wafaagx4k 22/06/2026, 21:59 2753\\_260128174907\\_001.pdf adware discovery spyware 3 Reported"
          ]
        },
        {
          "title": "IOCs/2026/08 at main · Cisco-Talos/IOCs · GitHub",
          "url": "https://github.com/Cisco-Talos/IOCs/tree/main/2026/08",
          "excerpts": [
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main",
            "UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt",
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main Contents UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt"
          ]
        },
        {
          "title": "GitHub - PaloAltoNetworks/Unit42-timely-threat-intel: A collection of files with indicators supporting social media posts from Palo Alto Network's Unit 42 team to disseminate timely threat intelligence. · GitHub",
          "url": "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel",
          "excerpts": [
            "Top-level files 2020-08-20-IOCs-for-Emotet-infection-with-Qakbot.txt",
            "2020-09-01-IOCs-for-Raccoon-Stealer.txt 2020-09-07-IOCs-for-Dridex-infection.txt",
            "2024-01-08-IOCs-for-GootLoader-infection.txt 2024-01-12-IOCs-from-StealC-activity.txt 2024-01-17-IOCs-for-WikiLoader-activity.txt 2024-01-19-IOCs-for-GootLoader-infection.txt",
            "2026-01-07-scams-using-calendar-invites.txt 2026-01-16-W-8BEN-themed-phishing-activity.txt 2026-01-22-Attack-chain-targeting-users-looking-for-legitimate-tools.txt 2026-01-30-IOCs-for-traffic-ticket-search-portal-themed-phishing.txt 2026-02-03-IOCs-from-KongTuke-ClickFix-activity.txt 2026-02-04-IOCs-for-December-2025-Contagious-Interview-activity.txt 2026-02-05-IOCs-for-phishing-and-scams.txt 2026-02-06-IOCs-for-Super-Bowl-LX-scams.txt 2026-02-10-IOCs-for-smishing-impersonating-US-wireless-carriers.txt 2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt 2026-02-13-IOCs-for-tactics-by-browser-extensions-to-avoid-bans.txt 2026-02-20- AI-Accelerated Malicious Chrome Extension Campaigns.txt 2026-02-20-IOCs-for-tech-support-scam-activity.txt 2026-02-27-IOCs-for-Alloy-Taurus-infrastructure 2026-03-09-Threat-Alert-30K-domains-distributing-malicious-AI-related-browser-extension.txt",
            "2026-03-10-IOCs-for-VoidLink-activity.txt 2026-03-12-Vishing-Campaigns-Lead-to-Data-Theft-and-Extortion.txt 2026-03-19-THE-GHOST-IN-CAMPAIGN.txt 2026-03-23- Device-Code-based-OAuth-Phishing.txt 2026-03-30-KIMWOLF-V7-IoT.txt 2026-03-31-SHub-Stealer-Activity.txt 2026-04-02-Threat-Actor-Targets-Military-Entities.txt 2026-04-07-Montana-Empire.txt 2026-04-13-LORIKAZZ-ANDROID-IOT.txt 2026-04-15-SEO-Poisoning.txt",
            "Description: A collection of files with indicators supporting social media posts from Palo Alto Network's Unit 42 team to disseminate timely threat intelligence. - PaloAltoNetworks/Unit42-timely-threat-intel",
            "This repository contains files with indicators supporting social media posts designed to disseminate timely threat intelligence data from Palo Alto Network's Unit 42 team.",
            "2026-01-07-scams-using-calendar-invites.txt 2026-01-16-W-8BEN-themed-phishing-activity.txt 2026-01-22-Attack-chain-targeting-users-looking-for-legitimate-tools.txt 2026-01-30-IOCs-for-traffic-ticket-search-portal-themed-phishing.txt 2026-02-03-IOCs-from-KongTuke-ClickFix-activity.txt 2026-02-04-IOCs-for-December-2025-Contagious-Interview-activity.txt 2026-02-05-IOCs-for-phishing-and-scams.txt 2026-02-06-IOCs-for-Super-Bowl-LX-scams.txt 2026-02-10-IOCs-for-smishing-impersonating-US-wireless-carriers.txt 2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt 2026-02-13-IOCs-for-tactics-by-browser-extensions-to-avoid-bans.txt 2026-02-20- AI-Accelerated Malicious Chrome Extension Campaigns.txt 2026-02-20-IOCs-for-tech-support-scam-activity.txt 2026-02-27-IOCs-for-Alloy-Taurus-infrastructure 2026-03-09-Threat-Alert-30K-domains-distributing-malicious-AI-related-browser-extension.txt 2026-03-10-IOCs-for-VoidLink-activity.txt 2026-03-12-Vishing-Campaigns-Lead-to-Data-Theft-and-Extortion.txt 2026-03-19-THE-GHOST-IN-CAMPAIGN.txt 2026-03-23- Device-Code-based-OAuth-Phishing.txt 2026-03-30-KIMWOLF-V7-IoT.txt 2026-03-31-SHub-Stealer-Activity.txt 2026-04-02-Threat-Actor-Targets-Military-Entities.txt 2026-04-07-Montana-Empire.txt 2026-04-13-LORIKAZZ-ANDROID-IOT.txt 2026-04-15-SEO-Poisoning.txt",
            "Top-level files 2020-08-20-IOCs-for-Emotet-infection-with-Qakbot.txt 2020-08-24-IOCs-for-Trickbot-gtag-ono66.txt 2020-08-25-IOCs-for-Emotet-with-Trickbot.txt 2020-09-01-IOCs-for-Raccoon-Stealer.txt 2020-09-07-IOCs-for-Dridex-infection.txt"
          ]
        },
        {
          "title": "GitHub - bitdefender/malware-ioc: Indicators of Compromise for malware documented in whitepapers. · GitHub",
          "url": "https://github.com/bitdefender/malware-ioc",
          "excerpts": [
            "This space aggregates Indicators of Compromise detailed in research papers published by Bitdefender on [Bitdefender Labs](https://labs.bitdefender.com/) .",
            "dark_nexus/ metamorfo_malware/ rdp_abusers/ silkparasite-2026_08/ vapor_malware/",
            "2026_02_11-Lumma-Stealer-ioc.csv 2026_03_05-apt36-iocs.csv 2026_03_31-axios-iocs.csv 2026_05_13-famoussparrow-iocs.csv 2026_08-silkparasite-iocs.csv"
          ]
        }
      ],
      "reasoning": "Assessment reasoning:\n- Completeness: The field_description requests a clean, structured table listing sources with specific columns. The provided field_answer is a set of guidance notes and some source examples, not a complete table or a comprehensive listing as required. Therefore, completeness should be false.\n- Supported: The excerpts include multiple sources and statements that align with the field_answer's referenced items (e.g., URLhaus, MalwareBazaar, ThreatFox, PhishTank, OpenPhish, etc., and notes about access/auth requirements). The field_answer references these kinds of sources and access details that are indeed present in the excerpts. Therefore, support should be true.\n- Overall: The answer partially aligns with referenced sources and access notes but fails to deliver the requested structured table format, hence incomplete but supported by excerpts.\n",
      "confidence": "low"
    },
    {
      "field": "malware_delivery_urls_and_file_hash_collections",
      "citations": [
        {
          "title": "URLhaus | Malware URL exchange",
          "url": "https://urlhaus.abuse.ch/",
          "excerpts": [
            "URLhaus is a platform from abuse.ch and Spamhaus dedicated to sharing malicious URLs that are being used for malware distribution.",
            "Browse malware URLs Gain valuable insights and find the latest malicious URLs being used for malware distribution. [Access database »](https://urlhaus.abuse.ch/browse/)",
            "Use the APIs, to seamlessly push and pull signals, and automate bulk queries."
          ]
        },
        {
          "title": "URLhaus | Community API",
          "url": "https://urlhaus.abuse.ch/api/",
          "excerpts": [
            "You can choose between CSV and JSON format.",
            "Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL.",
            "Manual submissions through the URLhaus [web interface](https://urlhaus.abuse.ch/browse/) (note: you need to authenticate yourself with your [abuse.ch account](https://auth.abuse.ch/ \"Login to abuse.ch\") )"
          ]
        },
        {
          "title": "MalwareBazaar | Export",
          "url": "https://bazaar.abuse.ch/export/",
          "excerpts": [
            "MalwareBazaar offers the exporting of hash lists in the following formats:",
            "**Recent** datasets (\"recent additions\") include hashes for the last 48 hours and are being generated every **5 minutes** . Please do not fetch them more often than that. **Full** data dumps include all hashes and are only being generated once per hour.",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first.",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include the URI parameter `auth-key` which contains your Auth-Key as value."
          ]
        },
        {
          "title": "MalShare",
          "url": "https://www.malshare.com/",
          "excerpts": [
            "Quick Search: Search Recently added Samples |SHA256 Hash |File type |Added |Source |",
            "Quick Search: Search Recently added Samples |SHA256 Hash |File type |Added |Source | |[3cda8de56aebc5002cce369efff7631758f9d8cd16af7f8632dbeaf148ad722f](https://www.malshare.com/sample.php?action=detail&hash=3cda8de56aebc5002cce369efff7631758f9d8cd16af7f8632dbeaf148ad722f) |DOS |2026-09-18 05:42:48 UTC |User Submission |"
          ]
        },
        {
          "title": "MalShare",
          "url": "https://www.malshare.com/doc.php",
          "excerpts": [
            "The API is provided for the registered users to allow for accessing of files and data stored within out dataset.",
            "|GET |/api.php?api\\_key=[API\\_KEY]&action=getlist |List hashes from the past 24 hours |JSON |",
            "|GET |/api.php?api\\_key=[API\\_KEY]&action=getlistraw |List hashes from the past 24 hours |Raw Text List |",
            "|GET |/api.php?api\\_key=[API\\_KEY]&action=getsources |List of sample sources from the past 24 hours |JSON |",
            "|GET |/api.php?api\\_key=[API\\_KEY]&action=getlist |List hashes from the past 24 hours |JSON | |GET |/api.php?api\\_key=[API\\_KEY]&action=getlistraw |List hashes from the past 24 hours |Raw Text List |"
          ]
        },
        {
          "title": "VirusShare.com",
          "url": "https://virusshare.com/search",
          "excerpts": [
            "|Searching by hash value | |You can search by a number of cryptographic hash alogrithims simply by entering a single hash value in the search box. Hash values supported are md5, sha1, sha224, sha256, sha384, and sha512. There is no need to specify the hash type context as it will be auto-detected by the server. Hashes must be submitted one at a time and not combined with any other values as hash values are (generally) expected to be unique and combining with other search values will probably return less results than you are hoping for. |",
            "Account: Please <login> to search and download.",
            "|This reference is for the web-based search interface. You can find the API reference here . |"
          ]
        },
        {
          "title": "Reports |  Triage™ ",
          "url": "https://tria.ge/reports",
          "excerpts": [
            "Search Sample ID Created Filename Tags Status/Score SHA256",
            "Reports * Search Sample ID Created Filename Tags Status/Score SHA256 260622-1wvq8agx4n 22/06/2026, 22:00 https://linktr.ee/nyckidsris Running N/A 260622-1wnb5sg13x 22/06/2026, 22:00 http://nyckidsrise.org/ Running N/A 260622-1wltbagx4m 22/06/2026, 22:00 https://skill-pharmaceutical-societies-roots.trycloudflare.com/NDMxRzFtOXc4QzFUMUw= Running N/A 260622-1wkagsg13w 22/06/2026, 21:59 \\_b2042a3d582987297d3e21e4ec35813e608d2c2b18db409edb36c1173f0b5520.exe Running 260622-1wjzqagx4l 22/06/2026, 21:59 setup.bat Running 260622-1whfwsg13v 22/06/2026, 21:59 \\_7e1e3dd418f70e0a973727bd106ed4bee047dd79a8d1c20004d37ceb477d5d6a.exe Running 260622-1wgvcsg13t 22/06/2026, 21:59 ccsetup639\\_pro.exe Pending N/A 260622-1wafaagx4k 22/06/2026, 21:59 2753\\_260128174907\\_001.pdf adware discovery spyware 3 Reported",
            "260622-1wvq8agx4n 22/06/2026, 22:00 https://linktr.ee/nyckidsris Running N/A 260622-1wnb5sg13x 22/06/2026, 22:00 http://nyckidsrise.org/ Running N/A 260622-1wltbagx4m 22/06/2026, 22:00 https://skill-pharmaceutical-societies-roots.trycloudflare.com/NDMxRzFtOXc4QzFUMUw= Running N/A 260622-1wkagsg13w 22/06/2026, 21:59 \\_b2042a3d582987297d3e21e4ec35813e608d2c2b18db409edb36c1173f0b5520.exe Running 260622-1wjzqagx4l 22/06/2026, 21:59 setup.bat Running 260622-1whfwsg13v 22/06/2026, 21:59 \\_7e1e3dd418f70e0a973727bd106ed4bee047dd79a8d1c20004d37ceb477d5d6a.exe Running 260622-1wgvcsg13t 22/06/2026, 21:59 ccsetup639\\_pro.exe Pending N/A 260622-1wafaagx4k 22/06/2026, 21:59 2753\\_260128174907\\_001.pdf adware discovery spyware 3 Reported"
          ]
        }
      ],
      "reasoning": "Assessment reasoning:\n- The field_answer provides a structured table of five sources: URLhaus, MalwareBazaar, MalShare, VirusShare, and Triage public reports. These sources align with the user query’s target categories (malicious URL/domains, malware hashes, etc.) and match the excerpts provided.\n- Excerpts include explicit references to URLhaus, MalwareBazaar, MalShare, VirusShare, and Triage, supporting the presence and descriptions of these sources in the field answer.\n- Although the user’s prompt mentions additional example sources (e.g., OpenPhish, ThreatFox, etc.), the field answer does cover several canonical live feeds and databases with explicit access details, satisfying the core asked outcome. It does not claim to be exhaustive beyond the listed entries, which is acceptable unless completeness requires every possible source.\n- Therefore, the field answer appears to be complete with respect to the requested structured listing of sources and is supported by the provided excerpts.\n",
      "confidence": "high"
    },
    {
      "field": "phishing_url_and_dangerous_domain_feeds",
      "citations": [
        {
          "title": "PhishTank | Join the fight against phishing",
          "url": "https://phishtank.org/",
          "excerpts": [
            "PhishTank | Join the fight against phishing PhishTank is a collaborative clearing house for data and information about phishing on the Internet."
          ]
        },
        {
          "title": "PhishTank > Developer Information",
          "url": "https://phishtank.org/developer_info.php",
          "excerpts": [
            "Get the Database If you'll be doing lots of lookups, the best option is to take advantage of our downloadable databases. Available in multiple formats and updated hourly, these make it easy to have fast and up to date phishing detection built into your application. The data is available in a variety of formats to make it as easy as possible for you to implement.",
            "If you do intend to fetch these files automatically, please register for an application key and see below for instructions on how to use it to request files. Without this key, you will be limited to a few downloads per day.",
            "We require that you use a descriptive User Agent string in your application to identify the application. If your User Agent is blank or generic, you may recieve an increased number of rate limited requests or be redirected to additional security checks.",
            "Get the Database If you'll be doing lots of lookups, the best option is to take advantage of our downloadable databases. Available in multiple formats and updated hourly, these make it easy to have fast and up to date phishing detection built into your application. The data is available in a variety of formats to make it as easy as possible for you to implement. We're always open to suggestions for additional formats we could provide, so if you have any thoughts, please join our developers list and let us know! If you do intend to fetch these files automatically, please register for an application key and see below for instructions on how to use it to request files. Without this key, you will be limited to a few downloads per day.",
            "Format Options |XML | |http://data.phishtank.com/data/online-valid.xml | |http://data.phishtank.com/data/online-valid.xml.gz | |http://data.phishtank.com/data/online-valid.xml.bz2 | |CSV | |http://data.phishtank.com/data/online-valid.csv | |http://data.phishtank.com/data/online-valid.csv.gz | |http://data.phishtank.com/data/online-valid.csv.bz2 | |Serialized PHP | |http://data.phishtank.com/data/online-valid.php\\_serialized | |http://data.phishtank.com/data/online-valid.php\\_serialized.gz | |http://data.phishtank.com/data/online-valid.php\\_serialized.bz2 | |JSON | |http://data.phishtank.com/data/online-valid.json | |http://data.phishtank.com/data/online-valid.json.gz | |http://data.phishtank.com/data/online-valid.json.bz2 |"
          ]
        },
        {
          "title": "OpenPhish - Phishing Feeds",
          "url": "https://openphish.com/phishing_feeds.html",
          "excerpts": [
            "12 hours Limited * * * * * * * [Terms of Use](https://openphish.com/terms.html) Text File [Free](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt) ¹",
            "Premium 5 minutes * * * * * * * * * CSV, JSON",
            "The Intelligence Pack offers enhanced metadata and specialized data feeds to help you track high-risk activities and gain deeper insights into the phishing threat landscape.",
            "12 hours Limited * * * * * * * [Terms of Use](https://openphish.com/terms.html) Text File [Free](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt) ¹ Premium 5 minutes * * * * * * * * * CSV, JSON",
            "Phishing URLs Targeted Brand IP and ASN GeoIP Industry Sector 30 Days Archive Page Language SSL Metadata",
            "Premium 5 minutes * * * * * * * * * CSV, JSON [Contact Us](mailto:contact@openphish.com) ² Platinum 5 minutes * * * * * * * * * CSV, JSON [Contact Us](mailto:contact@openphish.com) The Intelligence Pack offers enhanced metadata and specialized data feeds to help you track high-risk activities and gain deeper insights into the phishing threat landscape."
          ]
        },
        {
          "title": "API Documentation - PhishStats",
          "url": "https://phishstats.info/api-docs",
          "excerpts": [
            "Read-only endpoints on `api.phishstats.info` are public, but **daily quotas depend on how you authenticate** .",
            "Filter results based on field conditions",
            "`eq` equals `ne` not equals `gt` greater than `lt` less than `like` contains `and` logical AND `or` logical OR",
            "Sort by field (use -field for descending order)",
            "`_p=page_number` (default: 1) `_size=records_per_page` (default: 20, max: 100)"
          ]
        },
        {
          "title": "Phishing Domains Feed - Free TXT, JSON, CSV - phishunt.io",
          "url": "https://phishunt.io/feed",
          "excerpts": [
            "Every record in the JSON and CSV feeds includes these fields:",
            "|`url` |string |Full suspicious URL | |`domain` |string |Domain (includes subdomains) |",
            "TXT Plain text - one URL per line. Ideal for simple blocklists and scripts. [Download feed.txt](https://phishunt.io/feed.txt) JSON Structured data with enrichment (IP, ASN, GeoIP, detection sources). [Download feed.json](https://phishunt.io/feed.json) CSV Spreadsheet-ready. All fields with UTF-8 encoding and proper escaping. [Download feed.csv](https://phishunt.io/feed.csv)",
            "Use the [REST API](https://phishunt.io/api/) to filter by brand, date range, or pagination - with the same data and formats.",
            "All feeds are updated hourly and served via Cloudflare for fast, reliable delivery.",
            "Free real-time feed of active suspicious phishing sites - download in TXT, JSON, or CSV format",
            "|`malicious_google` |boolean |Flagged by Google Safe Browsing | |`malicious_openphish` |boolean |Listed in OpenPhish feed | |`malicious_phishtank` |boolean |Listed in PhishTank feed | |`malicious_tweetfeed` |boolean |Reported on TweetFeed | |`malicious_urlscan` |boolean |Detected by urlscan.io |",
            "Threat intelligence from Google Safe Browsing, OpenPhish, PhishTank, TweetFeed, and urlscan.io.",
            "Every record in the JSON and CSV feeds includes these fields: |Field |Type |Description | |`url` |string |Full suspicious URL | |`domain` |string |Domain (includes subdomains) |",
            "All feeds are updated hourly and served via Cloudflare for fast, reliable delivery. TXT Plain text - one URL per line. Ideal for simple blocklists and scripts. [Download feed.txt](https://phishunt.io/feed.txt) JSON Structured data with enrichment (IP, ASN, GeoIP, detection sources). [Download feed.json](https://phishunt.io/feed.json) CSV Spreadsheet-ready. All fields with UTF-8 encoding and proper escaping. [Download feed.csv](https://phishunt.io/feed.csv)"
          ]
        },
        {
          "title": "Live Phishing Threat Feed | PhishDestroy",
          "url": "https://phishdestroy.io/live",
          "excerpts": [
            "The PhishDestroy live phishing threat feed is an append-only public record of recently detected phishing domains and malicious infrastructure. DNS resolvers, browser extensions and threat-intelligence pipelines use the same raw evidence. [Download JSON feed →](https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json) Browse threats [Report via bot](https://t.me/PhishDestroy_bot)",
            "02 / Append log · DestroyList The blacklist _scrolls whether you watch or not._ Source: **github.com/phishdestroy/destroylist** Format: append-only · CC-BY-4.0 scan@phishdestroy: **~/destroylist** $ LIVE uptime 430 d scan@phishdestroy:~$ git log --follow list.json | head ▸ append-only blacklist · once added, an entry is never edited or removed ▸ 159,537 live-feed records since 01.07.2025 · sync interval ≈ 14s scan@phishdestroy:~$ tail -f scan\\_results | jq",
            "Last entry: **\\+faceit.accsyncing.com** · 2026-09-04 02:18 UTC Showing **16** of **159,537** live-feed records · Browse full database →",
            "[Download JSON feed →](https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json) Browse threats [Report via bot](https://t.me/PhishDestroy_bot)",
            "faceit.accsyncing.com Reported Screenshot of faceit.accsyncing.com Screenshot pending SCAM Detected: **2026-09-04 04:18**",
            "brobadak.com Reported Screenshot of brobadak.com Screenshot pending SCAM Detected: **2026-09-04 00:50**"
          ]
        },
        {
          "title": "    Dangerous websites Warning List | CERT Polska\n",
          "url": "https://cert.pl/en/warning-list",
          "excerpts": [
            "From March 2020 we continuously provide a list of dangerous websites (the Warning List, the List). We maintain it 24 hours a day, 7 days per week and update with all domains that trick Polish internet users to steal their data and credentials. Phishing websites collecting personal data and credentials are now a mass phenomenon, affecting various groups of internet users in Poland. Links to such webpages are sent through various channels: SMS, e-mail or social media. The websites are registered in large numbers and used within a short time of registration, after which they are abandoned in favor of new addresses.",
            "Available formats text format, active domains only, single domain per line – <https://hole.cert.pl/domains/v2/domains.txt> TSV (tab-separated values) format – <https://hole.cert.pl/domains/v2/domains.csv> JSON format – <https://hole.cert.pl/domains/v2/domains.json> XML format – <https://hole.cert.pl/domains/v2/domains.xml> ad-blocker list compatible with uBlock Origin and AdGuard AdBlocker browser extensions – [https://hole.cert.pl/domains/v2/domains\\_adblock.txt](https://hole.cert.pl/domains/v2/domains_adblock.txt) hosts format – [https://hole.cert.pl/domains/v2/domains\\_hosts.txt](https://hole.cert.pl/domains/v2/domains_hosts.txt) .rsc format, limited to 4096 bytes, for MikroTik/RouterOS systems – [https://hole.cert.pl/domains/v2/domains\\_mikrotik.rsc](https://hole.cert.pl/domains/v2/domains_mikrotik.rsc) RPZ (Response Policy Zones) blacklist format – [https://hole.cert.pl/domains/v2/domains\\_rpz.db](https://hole.cert.pl/domains/v2/domains_rpz.db)",
            "Changes introduced in the second version of the List In response to changing threats and the ever-growing size of the List, we have decided to make a few changes in the operation of the List that will help us to better respond to new threats, and help users to integrate it more easily: domains are blocked for a **6 month** period, after this time if a domain is still considered as dangerous it will be added as a new entry considering the above, all List formats are time-limited to the last 6 months - this will solve the problem of having to download increasingly large files at short intervals in order to maintain transparency regarding blocked domains, a data stream has been introduced – \"actions.log\". It lists all domains we add to the Warning List and remove from it grouped by year in addition to blocking the domains on the List, we also recommend blocking traffic to their subdomains"
          ]
        },
        {
          "title": "GitHub - Phishing-Database/Phishing.Database: Phishing Domains, urls websites and threats database. We use the PyFunceble testing tool to validate the status of all known Phishing domains and provide stats to reveal how many unique domains used for Phishing are still active. · GitHub",
          "url": "https://github.com/Phishing-Database/Phishing.Database",
          "excerpts": [
            "|ALL-phishing-domains.lst |[Download](https://phish.co.za/latest/ALL-phishing-domains.lst) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha512) | |ALL-phishing-links.lst |[Download](https://phish.co.za/latest/ALL-phishing-links.lst) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha512) | |ALL-phishing-domains.tar.gz |[Download](https://phish.co.za/latest/ALL-phishing-domains.tar.gz) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha512) | |ALL-phishing-links.tar.gz |[Download](https://phish.co.za/latest/ALL-phishing-links.tar.gz) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha512) | |phishing-domains-ACTIVE.txt |[Download](https://phish.co.za/latest/phishing-domains-ACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha512) | |phishing-domains-INACTIVE.txt |[Download](https://phish.co.za/latest/phishing-domains-INACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.sha512) | |phishing-domains-INVALID.txt |[Download](https://phish.co.za/latest/phishing-domains-INVALID.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.sha512) |",
            "|phishing-links-ACTIVE.txt |[Download](https://phish.co.za/latest/phishing-links-ACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha512) | |phishing-links-INACTIVE.txt |[Download](https://phish.co.za/latest/phishing-links-INACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.sha512) | _The files are updated regularly._",
            "_The files are updated regularly._",
            "The testing of the domains and URLs is automated using the awesome [PyFunceble Testing Suite](https://github.com/funilrys/PyFunceble) written by Nissar Chababy _(AKA [@funilrys](https://github.com/funilrys) )_ . Over many years in development, this tool has become a robust and reliable source of domain and URL status. We use it in an automated environment which actively retests domains and URLs on a regular basis.",
            "The links below will direct you to the latest data files for this project. The checksums for the files are available in the [checksums repository](https://github.com/Phishing-Database/checksums) . |File Name |Official Source |Checksums | |ALL-phishing-domains.lst |[Download](https://phish.co.za/latest/ALL-phishing-domains.lst) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha512) | |ALL-phishing-links.lst |[Download](https://phish.co.za/latest/ALL-phishing-links.lst) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha512) | |ALL-phishing-domains.tar.gz |[Download](https://phish.co.za/latest/ALL-phishing-domains.tar.gz) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha512) | |ALL-phishing-links.tar.gz |[Download](https://phish.co.za/latest/ALL-phishing-links.tar.gz) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha512) | |phishing-domains-ACTIVE.txt |[Download](https://phish.co.za/latest/phishing-domains-ACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha512) |",
            "Top-level files .github/workflows/ phishing-IPs-ACTIVE-today/ phishing-IPs-ACTIVE/ phishing-IPs-INACTIVE/ phishing-IPs-INVALID/ phishing-IPs-NEW-today/ phishing-domains-ACTIVE-today/ phishing-domains-ACTIVE/ phishing-domains-INACTIVE/ phishing-domains-INVALID/ phishing-domains-NEW-last-hour/ phishing-domains-NEW-today/ phishing-ips-NEW-last-hour/ phishing-ips-NEW-today/ phishing-links-ACTIVE-today/ phishing-links-ACTIVE/ phishing-links-INACTIVE/ phishing-links-INVALID/ phishing-links-NEW-last-hour/ phishing-links-NEW-today/ LICENSE README.md phishing-IPs-ACTIVE.txt phishing-IPs-INACTIVE.txt phishing-IPs-INVALID.txt phishing-domains-ACTIVE.adblock phishing-domains-ACTIVE.txt phishing-domains-INACTIVE.txt phishing-domains-INVALID.txt phishing-domains-NEW-last-hour.txt phishing-domains-NEW-today.txt phishing-ips-NEW-last-hour.txt phishing-ips-NEW-today.txt phishing-links-ACTIVE-NOW.txt phishing-links-ACTIVE-today.txt phishing-links-ACTIVE.txt phishing-links-INACTIVE.txt phishing-links-INVALID.txt phishing-links-NEW-last-hour.txt phishing-links-NEW-today.txt",
            "|ALL-phishing-domains.lst |[Download](https://phish.co.za/latest/ALL-phishing-domains.lst) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.lst.sha512) | |ALL-phishing-links.lst |[Download](https://phish.co.za/latest/ALL-phishing-links.lst) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.lst.sha512) | |ALL-phishing-domains.tar.gz |[Download](https://phish.co.za/latest/ALL-phishing-domains.tar.gz) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-domains.tar.gz.sha512) | |ALL-phishing-links.tar.gz |[Download](https://phish.co.za/latest/ALL-phishing-links.tar.gz) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/ALL-phishing-links.tar.gz.sha512) | |phishing-domains-ACTIVE.txt |[Download](https://phish.co.za/latest/phishing-domains-ACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha512) | |phishing-domains-INACTIVE.txt |[Download](https://phish.co.za/latest/phishing-domains-INACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INACTIVE.txt.sha512) | |phishing-domains-INVALID.txt |[Download](https://phish.co.za/latest/phishing-domains-INVALID.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-INVALID.txt.sha512) | |phishing-IPs-ACTIVE.txt |[Download](https://phish.co.za/latest/phishing-IPs-ACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-ACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-ACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-ACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-ACTIVE.txt.sha512) | |phishing-IPs-INACTIVE.txt |[Download](https://phish.co.za/latest/phishing-IPs-INACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INACTIVE.txt.sha512) | |phishing-IPs-INVALID.txt |[Download](https://phish.co.za/latest/phishing-IPs-INVALID.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INVALID.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INVALID.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INVALID.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-IPs-INVALID.txt.sha512) | |phishing-links-ACTIVE.txt |[Download](https://phish.co.za/latest/phishing-links-ACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha512) | |phishing-links-INACTIVE.txt |[Download](https://phish.co.za/latest/phishing-links-INACTIVE.txt) |[md5](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.md5) , [sha1](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.sha1) , [sha256](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.sha256) , [sha512](https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-INACTIVE.txt.sha512) | _The files are updated regularly._"
          ]
        },
        {
          "title": "    Deprecation of the first version of Dangerous websites Warning List | CERT Polska\n",
          "url": "https://cert.pl/en/posts/2025/01/hole-v1-deprecation-notice",
          "excerpts": [
            "Deprecation of the first version of Dangerous websites Warning List",
            "Over a year ago we've started publishing the List using a new format.",
            "Over a year ago we've started publishing the List using a new format. The second version allows to block malicious domains more precisely and solves the issue of integrators still blocking expired domains. **As of 1st of June, 2025 we will no longer offer downloads in the legacy format**"
          ]
        }
      ],
      "reasoning": "Assessment reasoning:\n- The user asked to compile a structured table of sources that publish malicious indicators (malicious URLs, domains, IPs, file hashes) and to describe the research question. The provided field_answer includes a multi-source table with 4 columns (Source Name, Website URL, Type of Indicators Hosted, Access Type) and lists sources such as PhishTank, OpenPhish, PhishStats, Phishunt, PhishDestroy, CERT Polska, Phishing.Database. This aligns with the requested scope and includes multiple live feeds or landing pages. Although the field_answer does not include an explicit separate Description column in the table, the research question intent is reflected in the content. The Excerpts show supportive evidence for several listed sources (PhishTank, OpenPhish, PhishStats, PhishDestroy, CERT Polska, Phishing.Database, Phishunt).\n- Completeness evaluation: The answer directly addresses the query by enumerating relevant sources and describing the type of indicators and access mode for each. It covers a broad set of well-known sources and even notes versioning considerations, which enhances usefulness. Therefore completeness can be considered true.\n- Excerpts support evaluation: Excerpts include entries for PhishTank, OpenPhish, PhishStats, PhishDestroy, CERT Polska, Phishing.Database, Phishunt and PhishTank developer info, which corroborates the presence and nature of these sources. Thus, supported should be true.",
      "confidence": "high"
    },
    {
      "field": "botnet_c2_and_ransomware_infrastructure",
      "citations": [
        {
          "title": "ThreatFox | Export",
          "url": "https://threatfox.abuse.ch/export/",
          "excerpts": [
            "ThreatFox offers the exporting of indicators of compromise (IOCs) in following formats: Auth-Key ( **Required** ) Daily MISP Events Suricata IDS Ruleset DNS Response Policy Zone (RPZ) host file (domain only) JSON file CSV files",
            "For this purpose, ThreatFox offers a list of domain based IOCs. The host file below contains the following datasets observed in the **past 6 month** : Payload delivery domains Botnet C2 domains The following file gets generated every **5 minutes** .",
            "ThreatFox provides a ruleset containing all network based Indicators Of Compromise (IOCs) for [Suricata IDS](https://suricata-ids.org/ \"Suricata IDS\") . As we believe that IOCs have an expiration date too and to avoid false positive, we only export IOCs for the **past 6 month** . Please note that the ruleset has been tested with Suricata version 6.0.0. The ruleset gets generated **every 5 minutes** . To achieve the best protection, we recommend to fetch it every 5 minutes.",
            "By using an DNS Reponse Policy Zone (RPZ), also known as DNS firewall, you can detect the resolution of certain domain names ovserved in the **past 6 month** on your DNS resolver. ThreatFox offerst the following IOCs as RPZ dataset: Payload delivery domains Botnet C2 domains More information about DNS RPZ can be found on [dnsrpz.info](https://dnsrpz.info/ \"DNS Response Policy Zones\") . The following file gets generated every **5 minutes** . To achieve the best protection, we recommend to fetch it every 5 minutes.",
            "The following data exports exists in JSON format: Login required In order to view this documentation, you need to and create an `Auth-Key` . CSV files * * The following data exports exists in CSV format:",
            "Obtain an Auth-Key ( **Required** ) * * In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL. Example curl command: ``` curl -i \"https://threatfox-api.abuse.ch/v2/files/exports/YOUR-AUTH-KEY-HERE/full.csv.zip\" ```",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL."
          ]
        },
        {
          "title": "ThreatFox | Browse IOCs",
          "url": "https://threatfox.abuse.ch/browse/",
          "excerpts": [
            "|Date (UTC) |IOC |Malware |Tags |Reporter |",
            "Using the form below, you can search for malware samples by a hash (MD5, SHA256, SHA1), imphash, tlsh hash, ClamAV signature, tag or malware family.",
            "Search syntax is as follow: `keyword:search_term`"
          ]
        },
        {
          "title": "Feodo Tracker",
          "url": "https://feodotracker.abuse.ch/",
          "excerpts": [
            "Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor). It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo.",
            "It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo. [Download Blocklist »](https://feodotracker.abuse.ch/blocklist/)",
            "Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor). It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo. [Download Blocklist »](https://feodotracker.abuse.ch/blocklist/)"
          ]
        },
        {
          "title": "Feodo Tracker | Blocklist",
          "url": "https://feodotracker.abuse.ch/blocklist/",
          "excerpts": [
            "The Botnet C2 IP Blocklist gets **generated every 5 minutes** and is available in the plain-text and JSON format. We recommend you to update the list at **least every 15 minutes** (or even better: every 5 minutes) to receive the best protection against Dridex, Emotet, TrickBot, QakBot and BazarLoader. Recommended IP blocklist If you want to block botnet C&C IP addresses but avoid false positives, I highly recommend you to use the following blocklist as it only contains **active** botnet C&C servers or such that have been active in the past hours. Although false positives can happen on this blocklist, the false positive rate should be low. [Plain-Text](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt \"download Botnet C2 IP Blacklist (recommended)\") [JSON](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json \"download Botnet C2 IP Blacklist (recommended) in JSON format\")",
            "Botnet C2 Indicators Of Compromise (IOCs) * * If you have a SIEM (Security Information and Event Management) product, you can enrich it with data from Feodo Tracker to get alerted about potential botnet C2 traffic leaving your network. Unlike the IP blocklist above, these datasets do not only contain additional information on tracked botnet C2s but also IP addresses that were acting as a botnet C2 within the **past 30 days** . [Download CSV](https://feodotracker.abuse.ch/downloads/ipblocklist.csv \"download Botnet C2 IP Blacklist (CSV)\") [Download JSON](https://feodotracker.abuse.ch/downloads/ipblocklist.json \"download Botnet C2 IP Blacklist (JSON)\") [Download IPs only](https://feodotracker.abuse.ch/downloads/ipblocklist.txt \"download Botnet C2 IP Blacklist (IPs only)\")",
            "By using the website of Feodo Tracker, or any of the services / datasets referenced above, you agree that: All datasets offered by Feodo Tracker can be used for both, commercial and non-commercial purpose without any limitations ( [CC0](https://creativecommons.org/share-your-work/public-domain/cc0 \"CC0 - No Rights Reserved\") ) Any data offered by Feodo Tracker is served _as it is_ on best effort abuse.ch can not be held liable for any false positive or damage caused by the use of the website or the datasets offered above",
            "The Botnet C2 IP Blocklist gets **generated every 5 minutes** and is available in the plain-text and JSON format. We recommend you to update the list at **least every 15 minutes** (or even better: every 5 minutes) to receive the best protection against Dridex, Emotet, TrickBot, QakBot and BazarLoader. Recommended IP blocklist If you want to block botnet C&C IP addresses but avoid false positives, I highly recommend you to use the following blocklist as it only contains **active** botnet C&C servers or such that have been active in the past hours. Although false positives can happen on this blocklist, the false positive rate should be low. [Plain-Text](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt \"download Botnet C2 IP Blacklist (recommended)\") [JSON](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json \"download Botnet C2 IP Blacklist (recommended) in JSON format\") We also have custom formats of the blocklist available for McAfee Web Gateway and Palo Alto Firewall : [McAfee McAfee Web Gateway](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended_mcafee.txt \"Feodo Tracker Blocklsit for McAfee Web Gateway\") [Palo Alto Palo Alto Firewall](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended_paloalto.txt \"Feodo Tracker blocklist for Palo Alto Firewall\") Botnet C2 Indicators Of Compromise (IOCs) * * If you have a SIEM (Security Information and Event Management) product, you can enrich it with data from Feodo Tracker to get alerted about potential botnet C2 traffic leaving your network. Unlike the IP blocklist above, these datasets do not only contain additional information on tracked botnet C2s but also IP addresses that were acting as a botnet C2 within the **past 30 days** . [Download CSV](https://feodotracker.abuse.ch/downloads/ipblocklist.csv \"download Botnet C2 IP Blacklist (CSV)\") [Download JSON](https://feodotracker.abuse.ch/downloads/ipblocklist.json \"download Botnet C2 IP Blacklist (JSON)\") [Download IPs only](https://feodotracker.abuse.ch/downloads/ipblocklist.txt \"download Botnet C2 IP Blacklist (IPs only)\")"
          ]
        },
        {
          "title": "SSLBL | Blacklist",
          "url": "https://sslbl.abuse.ch/blacklist/",
          "excerpts": [
            "Botnet C2 IP Blacklist (CSV) * * An SSL certificate can be associated with one or more servers (IP address:port combination). SSLBL collects IP addresses that are running with an SSL certificate blacklisted on SSLBL. These are usually botnet Command&Control servers (C&C). SSLBL hence publishes a blacklist containing these IPs which can be used to detect botnet C2 traffic from infected machines towards the internet, leaving your network. The CSV format is useful if you want to process the blacklisted IP addresses further, e.g. loading them into your SIEM. The CSV contains the following values: Firstseen(UTC) Destination IP (DstIP) Destination Port (DstPort) The Botnet C2 IP Blacklist gets generated every 5 minutes. Please do not fetch it more often than every 5 minutes. Note As IP addresses are getting recycled and reused, this blacklist only contains IP addresses that have been see to be associated with malicious SSL certificate in **past 30 days** . The false positive rate for this blacklist should therefore be low. [Download CSV](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv \"download Botnet C2 IP Blacklist (CSV)\") In addition, there is an IPs only list available for download below. This is handy if you want to use botnet C&Cs identified by SSLBL as a list of Indicator Of Compromise (IOC). [Download IPs only](https://sslbl.abuse.ch/blacklist/sslipblacklist.txt \"download Botnet C2 IP Blacklist (IPS only)\")",
            "SSL Certificate Blacklist (CSV) * * The **SSL Certificate Blacklist (CSV)** is a CSV that contains SHA1 Fingerprint of all SSL certificates blacklisted on SSLBL. This format is useful if you want to process the blacklisted SSL certificate further, e.g. loading them into your SIEM. The CSV contains the following values: Listing date (UTC) SHA1 Fingerprint of the blacklisted SSL certificate Listing reason The SSL Certificate Blacklist (CSV) gets generated every 5 minutes. Please do not fetch it more often than every 5 minutes. [Download CSV](https://sslbl.abuse.ch/blacklist/sslblacklist.csv \"download SSL Certificate Blacklist (CSV)\") Suricata SSL Certificate Ruleset * * [Suricata](http://suricata-ids.org/ \"Suricata IDS/IPS\") is an Open Source Network Intrustion Detection / Prevention System (IDS/IPS). If you are running Suricata, you can use the SSLBL's Suricata SSL Certificate Ruleset to detect and/or block malicious SSL connections in your network based on the SSL certificate fingerprint. [Download IDS Ruleset (Suricata 1.4 or newer)](https://sslbl.abuse.ch/blacklist/sslblacklist.rules \"download Suricata SSL Certificate Ruleset for Suricata 1.4 or newer\") [Download IDS Ruleset (Suricata 1.4 or newer) - tar.gz](https://sslbl.abuse.ch/blacklist/sslblacklist.tar.gz \"download Suricata SSL Certificate Ruleset for Suricata 1.4 or newer (.tar.gz)\") In addition, SSLBL provides a more performant Suricata ruleset that uses _tls\\_cert\\_fingerprint_ instead of _tls.fingerprint_ . Please use either the ruleset above ( _sslblacklist.rules_ ) **OR** _sslblacklist\\_tls\\_cert.rules_ from below. Do not use both of them at the same time. The Suricata SSL Certificate Ruleset gets generated every 5 minutes. Please do not fetch it more often than every 5 minutes. Note In order to use the more perfomant Suricata ruleset avilable for download below, you must run **Suricata 4.1.0 or newer** . The ruleset will not work with any Suricata version prior 4.1.0. If you are running a version of Suricata older than 4.1.0, please use the ruleset above this box. [Download IDS Ruleset (Suricata 4.1.0 or newer)](https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.rules \"download Suricata SSL Certificate Ruleset for Suricata 4.1.0 or newer\") [Download IDS Ruleset (Suricata 4.1.0 or newer) - tar.gz](https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz \"download Suricata SSL Certificate Ruleset for Suricata 4.1.0 or newer (tar.gz)\")",
            "SSL Certificate Blacklist (CSV) Suricata SSL Certificate Ruleset Botnet C2 IP Blacklist (CSV) Suricata Botnet C2 IP Ruleset Botnet C2 IP DNS Response Policy Zone (RPZ) JA3 Fingerprint Blacklist (CSV) Suricata JA3 Fingerprint Ruleset Terms of Services",
            "JA3 Fingerprint Blacklist (CSV) * * JA3 is an [open source tool](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41 \"JA3\") used to fingerprint SSL/TLS client applications. In the best case, you can use JA3 to identify malware and botnet C2 traffic that is leveraging SSL/TLS. The CSV format is useful if you want to process the JA3 fingerprints further, e.g. loading them into your SIEM. The CSV contains the following values: JA3 Fingerprint First seen (UTC) Last seen (UTC) Listing reason The JA3 Fingerprint Blacklist (CSV) gets generated every 5 minutes. Please do not fetch it more often than every 5 minutes. Caution! The JA3 fingerprints blacklisted on SSLBL have been collected by analysing more than 25,000,000 PCAPs generated by malware samples. These fingerprints have **not been tested against known good traffic yet and may cause a significant amount of FPs!** [Download JA3 Fingerprints](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv \"download JA3 Fingerprint Blacklist\") Suricata JA3 Fingerprint Ruleset * * [Suricata](http://suricata-ids.org/ \"Suricata IDS/IPS\") is an Open Source Network Intrustion Detection / Prevention System (IDS/IPS). If you are running Suricata, you can use the SSLBL's Suricata JA3 FingerprintRuleset to detect and/or block malicious SSL connections in your network based on the JA3 fingerprint. Please note that your need Suricata 4.1.0 or newer in order to use the JA3 fingerprint ruleset. The Suricata JA3 Fingerprint Ruleset gets generated every 5 minutes. Please do not fetch it more often than every 5 minutes. Caution! The JA3 fingerprints blacklisted on SSLBL have been collected by analysing more than 25,000,000 PCAPs generated by malware samples. These fingerprints have **not been tested against known good traffic yet and may cause a significant amount of FPs!** [Download JA3 IDS Ruleset (Suricata 4.1.0 or newer)](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules \"download JA3 Fingerprint Suricata JA3 Fingerprint Ruleset\") [Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - tar.gz](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz \"download JA3 Fingerprint Suricata JA3 Fingerprint Ruleset (tar.gt)\")"
          ]
        },
        {
          "title": "IoCs",
          "url": "https://www.ransomware.live/ioc",
          "excerpts": [
            "Indicators of Compromise (IoCs) by Group",
            "Contact info (Tox, Session, Telegram, Email)",
            "Hash (MD5 & SHA256)",
            "IP Addresses",
            "|`Domain` |`crpx0.su`  | |`Domain` |`crpxoxo.pw`  | |`Domain` |`option.spark198.com`  |",
            "|`IP Address` |`104.18.20.226` Cloudflare, Inc. | |`IP Address` |`104.18.21.226` Cloudflare, Inc. | |`IP Address` |`140.248.136.175` Fastly, Inc. | |`IP Address` |`146.75.116.175` Fastly, Inc. Germany | |`IP Address` |`146.75.120.175` Fastly, Inc. Germany | |`IP Address` |`146.75.122.133` Fastly, Inc. Germany | |`IP Address` |`151.101.0.223` Fastly, Inc. United States | |`IP Address` |`151.101.128.223` Fastly, Inc. United States | |`IP Address` |`151.101.192.223` Fastly, Inc. United States | |`IP Address` |`23.224.4.114` CNSERVERS LLC United States | |`IP Address` |`48.192.1.65` Microsoft Corporation United States | |`Session` |`050546f6719172e04151c31acb37a242fa3eeff5766aa57331d26cc06e83e9e25b` | |`Tox` |`17EB54B8455144E088C7E77F88A97221C319F0CFE4FE306853EEB113EE8DB5607BB6EE481C7C` | |`URL` |`https://23.224.4.114` | |`URL` |`https://23.224.4.115` | |`URL` |`https://23.224.4.116` | |`URL` |`https://23.224.4.117` | |`URL` |`https://23.224.4.118` |",
            "Akira Bitcoin Wallet 15 Hash MD5 320 Hash SHA256 37 IP Address 1 Mutex 2",
            "|`Bitcoin Wallet` |`bc1q6dqe4esmqejmxhpj95qadv0j4clsqcxxp4cd94`   | |`Bitcoin Wallet` |`bc1qandfxc4knaf943njca77edl9mmegzs83tv8lpx`   | |`Bitcoin Wallet` |`bc1qcnw5v94y40ast06eatgalnjpluu2p067qewh46`   | |`Bitcoin Wallet` |`bc1qghj85gz0dkr9jeucana3z4xu50ujtllj50rvj0`   | |`Bitcoin Wallet` |`bc1qpwwtck0zhzrj56fxeayz6wz5546nlp607qzpvh`   | |`Bitcoin Wallet` |`bc1qr0pqfghr9cksfc5arr2rak3lt2y50v03pc76nh`   | |`Bitcoin Wallet` |`bc1qr0txunr259we37wer7w6et33qyq0n6hv83pw24`   |",
            "Conti Bitcoin Wallet 103",
            "Crpxo Domain 3 Hash MD5 16 IP Address 11 Session 1 Tox 1 URL 5",
            "|`URL` |`https://23.224.4.114` |",
            "|`IP Address` |`45.227.253.59:3111` Alviva Holding Limited Panama |",
            "|`Hash MD5` |`12e22f588f6128cf1a042d1122556cd2`  |",
            "|`Hash SHA1` |`74b3c1b58e12f3d854dc3ac7a5f05578faa8916c`  |",
            "|Type |IOC |"
          ]
        },
        {
          "title": "API Documentation",
          "url": "https://www.ransomware.live/apidocs",
          "excerpts": [
            "Gain programmatic access to ransomware victim data, group details, cyberattacks, and intelligence. **Base URL:** `https://api.ransomware.live/v2`",
            "Available Endpoints |Method |Endpoint |Description | |GET |`/info` |Basic API metadata | |GET |`/recentvictims` |Latest disclosed victims | |GET |`/group/<group_name>` |Details about a specific group |",
            "**Authentication:** No authentication is required to use the Ransomware.live API.",
            "All endpoints are publicly accessible.",
            "However, usage may be rate-limited to ensure fair access and platform stability.",
            "**Authentication:** No authentication is required to use the Ransomware.live API. All endpoints are publicly accessible. However, usage may be rate-limited to ensure fair access and platform stability."
          ]
        },
        {
          "title": "GitHub - criminalip/C2-Daily-Feed · GitHub",
          "url": "https://github.com/criminalip/C2-Daily-Feed",
          "excerpts": [
            "This repository provides a daily updated list of IP addresses derived from Criminal IP ( <https://www.criminalip.io/> ) under the C2\\_TI license. Our goal is to offer a daily sample of 50 malicious IP addresses identified by the Criminal IP real-time threat hunting search engine, specializing in OSINT-based Cyber Threat Intelligence (CTI). This includes Command and Control (C2, C&C) IP addresses categorized under the C2\\_TI license. Hosted on Criminal IP's official GitHub, this repository serves as a direct access point to our threat intelligence data.",
            "Our goal is to offer a daily sample of 50 malicious IP addresses identified by the Criminal IP real-time threat hunting search engine, specializing in OSINT-based Cyber Threat Intelligence (CTI).",
            "The selection criteria for the IP addresses listed in this repository are based on various conditions such as Criminal IP's threat tags ( <https://www.criminalip.io/developer/filters-and-tags/tags> ) and honeypot detections. This ensures a diverse representation of threats within the C2\\_TI dataset. The repository updates daily with a sample of 50 IP addresses, providing insights into a subset of the extensive C2\\_TI data. These IP addresses are intentionally chosen to reflect a broad spectrum of conditions, showcasing different types of threats identified by Criminal IP's real-time threat hunting capabilities. Criteria for IP Selection **Tags:** IPs with C2\\_xx tags. **Honeypot Detections:** IPs caught in [Criminal IP](https://www.criminalip.io/) 's honeypots. **Additional conditions** as specified by senior analysts."
          ]
        },
        {
          "title": "GitHub - montysecurity/C2-Tracker: Live Feed of C2 servers, tools, and botnets · GitHub",
          "url": "https://github.com/montysecurity/C2-Tracker",
          "excerpts": [
            "C2 Tracker is a free-to-use-community-driven IOC feed that uses [Shodan](https://www.shodan.io/) searches to collect IP addresses of known malware/botnet/C2 infrastructure.",
            "The IPs are seperated by the name of the tool and there is an `all.txt` that contains all of the IPs.",
            "As it currently stands this feed updates `weekly` on Monday."
          ]
        }
      ],
      "reasoning": "Assessment reasoning:\n- The field_description asks for a comprehensive list of primary source websites, OSINT platforms, threat tracking databases, and security repositories that publish raw lists of malicious indicators, along with landing pages or feeds. The provided field_answer presents a structured table with 6-7 sources (ThreatFox, Feodo Tracker, SSLBL, Ransomware.live IoCs, Criminal IP C2 Daily Feed, C2-Tracker).\n- Is the answer complete? Probably not strictly complete since the user asked for a comprehensive list and guidelines mention multiple sources (e.g., ThreatFox, URLhaus, PhishTank, MalwareBazaar, ThreatFox, OpenPhish, GitHub IOC repos, etc.). The answer covers several key sources but omits others like URLhaus, PhishTank, MalwareBazaar, OpenPhish, and others referenced in the prompt. Therefore, completeness should be false.\n- Are the excerpts supportive? Yes. The excerpts discuss ThreatFox exports, Feodo Tracker blocklists, SSLBL feeds, Ransomware.live IoCs, and GitHub feeds, which align with the sources listed in the field_answer. The provided field_answer content is corroborated by the excerpts, so supported should be true.\n- Conclusion: completeness = false (not fully comprehensive per the prompt), supported = true (excerpts validate the included sources).",
      "confidence": "low"
    },
    {
      "field": "attack_ip_lists_and_domain_blocklists",
      "citations": [
        {
          "title": "Don't Route Or Peer Lists (DROP) | Use with firewalls & BGP",
          "url": "https://www.spamhaus.org/blocklists/do-not-route-or-peer",
          "excerpts": [
            "The Spamhaus DROP lists consist of netblocks that are leased or stolen by professional spam or cyber-crime operations, and used for dissemination of malware, trojan downloaders, botnet controllers, or other kinds of malicious activity.",
            "The free DROP datasets are provided in JSON format to be parsed out and implemented on nearly any kind of device or software that is capable of processing IP networks for making a decision e.g., network gateways, firewalls, web-proxies, DNS resolvers etc.",
            "**DROP** \\- [https://www.spamhaus.org/drop/drop\\_v4.json](https://www.spamhaus.org/drop/drop_v4.json) **DROPv6** \\- [https://www.spamhaus.org/drop/drop\\_v6.json](https://www.spamhaus.org/drop/drop_v6.json) **ASN-DROP** \\- <https://www.spamhaus.org/drop/asndrop.json>",
            "Spamhaus believes that due to the vital nature of the DROP list data, it should be available at no cost, regardless of size or business type, to protect internet users.",
            "We do ask, when used in a product, credit must be given to Spamhaus Project, and the date and © text should remain with the file and data.",
            "For long-term users of the DROP files in text format, we recommend you update your configuration with the above JSON files as soon as your cycles allow.",
            "Spamhaus believes that due to the vital nature of the DROP list data, it should be available at no cost, regardless of size or business type, to protect internet users. We do ask, when used in a product, credit must be given to Spamhaus Project, and the date and © text should remain with the file and data."
          ]
        },
        {
          "title": "Spamhaus Blocklist (SBL) | IP DNSBL for effective email filtering",
          "url": "https://www.spamhaus.org/blocklists/spamhaus-blocklist",
          "excerpts": [
            "These IPs are being observed in adversarial activity, e.g. sending spam, snowshoe spamming, hosting malicious content, behaving like a bulletproof hosting company or hijacking IP space.",
            "Use of the Spamhaus DNSBLs is free of charge for low-volume, non-commercial users.",
            "SBL listing details can be viewed from <https://check.spamhaus.org/> , either by using the IP, IP range, or SBL ticket number."
          ]
        },
        {
          "title": "\n  www.blocklist.de -- Export all Attacker-IPs from the last 48 Hours.\n",
          "url": "https://blocklist.de/en/export.html",
          "excerpts": [
            "Here the lists of the attackers IP addresses of the last 48 hours pro service or all addresses for downloading. \\* These lists contain one line per IP address.",
            "time = hh:ii"
          ]
        },
        {
          "title": "Using Our Data Feeds - SANS Internet Storm Center",
          "url": "https://www.dshield.org/feeds_doc.html",
          "excerpts": [
            "<https://feeds.dshield.org/feeds/topips.txt> : Top 100 IP addresses and hostnames. <https://feeds.dshield.org/feeds/top10.txt> : Just IPs. No hostnames <https://feeds.dshield.org/feeds/block.txt> : Top 20 most active networks [https://feeds.dshield.org/feeds/daily\\_sources](https://feeds.dshield.org/feeds/daily_sources) : Daily summary of all source IPs",
            "Avoid downloading the data more than once an hour.",
            "Use of data premitted with attribution: SANS Technology Institute, Internet Storm Center, https://isc.sans.edu (you may feel free to change the format of the attribution according to your guidelines). Do not resell the data. Other commercial uses are allowed."
          ]
        },
        {
          "title": " AbuseIPDB - IP address abuse reports - Making the Internet safer, one IP at a time ",
          "url": "https://www.abuseipdb.com/",
          "excerpts": [
            "Our mission is to help make Web safer by providing a central blacklist for webmasters, system administrators, and other interested parties to report and find IP addresses that have been associated with malicious activity online.",
            "You can [report an IP address](https://www.abuseipdb.com/report) associated with malicious activity, or check to see if an IP address has been reported, by using the search box above.",
            "Consider [registering an account](https://www.abuseipdb.com/register) to gain access to our [powerful, free API](https://docs.abuseipdb.com/) for both reporting and checking the report status of IP addresses.",
            "Our mission is to help make Web safer by providing a central blacklist for webmasters, system administrators, and other interested parties to report and find IP addresses that have been associated with malicious activity online. You can [report an IP address](https://www.abuseipdb.com/report) associated with malicious activity, or check to see if an IP address has been reported, by using the search box above."
          ]
        },
        {
          "title": "FireHOL IP Lists | IP Blacklists | IP Blocklists | IP Reputation",
          "url": "https://iplists.firehol.org/",
          "excerpts": [
            "This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** .",
            "It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data.",
            "The data on this page are automatically generated using FireHOL's [update-ipsets.sh](https://github.com/firehol/firehol/blob/master/sbin/update-ipsets) (for downloading the lists from their sources and generating the data for this site), which utilizes [iprange](https://github.com/firehol/firehol/wiki/iprange:-optimizing-ipsets-for-iptables) (for comparing and manipulating IP lists).",
            "This site is a single **static** page, with all its data uploaded as static JSON and CSV files every time an IP List is updated.",
            "It uses IP lists and related data provided and maintained by their respective owners (mentioned together with each IP list), IP-to-country geolocation data provided by [maxmind.com](https://www.maxmind.com/) (GeoLite2), [ipdeny.com](http://www.ipdeny.com/) , [ip2location.com](http://www.ip2location.com/) (Lite) and [ipip.net](http://ipip.net/) , javascript chart libraries provided by [highcharts.com](http://www.highcharts.com/) , comments engine provided by [disqus.com](https://disqus.com/) , social media sharing buttons provided by [shareaholic.com](https://shareaholic.com/) , the HTML, CSS and JS framework [bootstrap](https://getbootstrap.com/) , the [bootstrap-table](http://bootstrap-table.wenzhixin.net.cn/) component, icons provided by [iconsdb.com](http://www.iconsdb.com/) and it uses several services provided by [github](https://github.com/) .",
            "This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** . It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data.",
            "This site is a single **static** page, with all its data uploaded as static JSON and CSV files every time an IP List is updated. For the final result, it utilizes IP data and web services provided by third parties. It uses IP lists and related data provided and maintained by their respective owners (mentioned together with each IP list), IP-to-country geolocation data provided by [maxmind.com](https://www.maxmind.com/) (GeoLite2), [ipdeny.com](http://www.ipdeny.com/) , [ip2location.com](http://www.ip2location.com/) (Lite) and [ipip.net](http://ipip.net/) , javascript chart libraries provided by [highcharts.com](http://www.highcharts.com/) , comments engine provided by [disqus.com](https://disqus.com/) , social media sharing buttons provided by [shareaholic.com](https://shareaholic.com/) , the HTML, CSS and JS framework [bootstrap](https://getbootstrap.com/) , the [bootstrap-table](http://bootstrap-table.wenzhixin.net.cn/) component, icons provided by [iconsdb.com](http://www.iconsdb.com/) and it uses several services provided by [github](https://github.com/) . × About this site This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** . It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data."
          ]
        },
        {
          "title": "Welcome - GreenSnow // BlockingList",
          "url": "https://greensnow.co/",
          "excerpts": [
            "Welcome to GreenSnow.co the blacklisted list of IPs for online servers.",
            "Our list is updated automatically and you can withdraw at any time your IP address if it has been listed.",
            "Download blacklisted IPs list",
            "[List.txt](https://blocklist.greensnow.co/greensnow.txt \"Télécharger la liste\")"
          ]
        },
        {
          "title": "FAQ - GreenSnow",
          "url": "https://greensnow.co/faq",
          "excerpts": [
            "The GreenSnow project helps to identify various attacks around the world in order to block them",
            "GreenSnow is a project that try to be to have the least possible false positive, we rely on the number of attacks, the number of attacked servers, different attacks and the country of the IP.",
            "Our BlockingList is very easy to use, simply log in WHM >> ConfigServer Security & Firewall >> lfd Blocklist and add this at the end:",
            "\\# GreenSnow Hack List \\# Details: https://greensnow.co GREENSNOW|3600|0|https://blocklist.greensnow.co/greensnow.txt"
          ]
        },
        {
          "title": "Malicious IPs | By Last Bad Event | Project Honey Pot",
          "url": "https://www.projecthoneypot.org/list_of_ips.php",
          "excerpts": [
            "Directory of Malicious IPs The list below is comprised of Malicious IPs (limited to the top 25 — to see more) that are: Arranged by their **Last Bad Event**",
            "|**Click any IP address for more details** |  Last updated: September 22 2026 11:11:29 AM |",
            "This page displays the top IPs by different categories. You may sort or limit this list by selecting from the menus below.",
            "You may also [lookup information](http://www.projecthoneypot.org/search_ip.php) on a specific IP address. If you want to see a list of IPs specifically targeting your own websites simply [join Project Honey Pot](https://www.projecthoneypot.org/create_account.php) and add honey pots to the sites you want to monitor. An [RSS feed](http://www.projecthoneypot.org/list_of_ips.php?rss=1 \"IP List RSS feed for this page\") for this page is available.",
            "If you want to see a list of IPs specifically targeting your own websites simply [join Project Honey Pot](https://www.projecthoneypot.org/create_account.php) and add honey pots to the sites you want to monitor."
          ]
        },
        {
          "title": "GitHub - firehol/blocklist-ipsets: ipsets dynamically updated with firehol's update-ipsets.sh script · GitHub",
          "url": "https://github.com/firehol/blocklist-ipsets",
          "excerpts": [
            "This repository includes a list of ipsets dynamically updated with [FireHOL](https://github.com/firehol/firehol) 's `update-ipsets.sh` [documented in this wiki](https://github.com/firehol/blocklist-ipsets/wiki) .",
            "> Due to the amount of data and the frequency of the updates on this repo, > github has requested to limit the number of updates. > The site [https://iplists.firehol.org](https://iplists.firehol.org/) has direct links > to all the files in this repo. **This repo is now updated once per day.** > >",
            "Please be very careful what you choose to use and how you use it. If you blacklist traffic using these lists you may end up blocking your users, your customers, even yourself (!) from accessing your services. Go to to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.",
            "They are freely available on the internet. The intention of their creators is to help internet security. Keep in mind though that a few of these lists may have special licences attached. Before using them, please check their source site for any information regarding proper use."
          ]
        }
      ],
      "reasoning": "Reasoning: The user query asks for a comprehensive list of primary source sites, OSINT platforms, threat tracking databases, and security repositories that publish raw lists of malicious indicators, focusing on landing pages rather than links. The provided field_answer presents a structured table with several known sources (Spamhaus DROP/SBL, blocklist.de, DShield, AbuseIPDB, FireHOL IP Lists, GreenSnow, Project Honey Pot) and contextual descriptions. The excerpts contain supporting evidence for many of these sources (e.g., Spamhaus DROP and SBL details, blocklist.de exports, DShield feeds, AbuseIPDB capabilities, FireHOL aggregations, GreenSnow, Project Honey Pot). However, the user’s request is for a comprehensive list, and the field_answer may not be fully exhaustive of all possible sources (e.g., additional IOC repositories, GitHub IOC repositories, ThreatFox, OpenPhish, MalwareBazaar, URLhaus, etc.). Therefore, the field_answer is not fully complete as a comprehensive list, but the existing entries are supported by the excerpts. I will mark completeness as false and supported as true based on excerpt alignment with the provided table.",
      "confidence": "low"
    },
    {
      "field": "osint_search_and_feed_directories",
      "citations": [
        {
          "title": "LevelBlue - Open Threat Exchange",
          "url": "https://otx.alienvault.com/",
          "excerpts": [
            "Synchronize OTX threat intelligence with other security products via DirectConnect API, SDK, and STIX/TAXII",
            "You can launch a query on any endpoint from OTX by selecting a pre-defined query that looks for IOCs in one or more OTX pulses.",
            "OTX Endpoint Security™ is available to any registered Open Threat Exchange (OTX) user. It’s free to join OTX.",
            "**Please note:** this is a separate account from the LevelBlue Community and legacy Open Threat Exchange accounts."
          ]
        },
        {
          "title": "OTX DirectConnect API - LevelBlue - Open Threat Exchange",
          "url": "https://otx.alienvault.com/api",
          "excerpts": [
            "The OTX DirectConnect API allows you to easily synchronize the Threat Intelligence available in OTX to the tools you use to monitor your environment.",
            "curl /api/v1/pulses/subscribed?page=1 -H \"X-OTX-API-KEY: <INSERT\\_USER\\_API\\_KEY>\" OTX can act as a TAXII server, making it possible for you to consume pulses via any TAXII client that you prefer.",
            "To consume the OTX STIX/TAXII feed you'll need to enter the following details into your TAXII client: **Discovery URL:** https://otx.alienvault.com/taxii/discovery **Username:** (Your API key) **Password: (put anything here, password is ignored)**"
          ]
        },
        {
          "title": "Explore - Pulsedive",
          "url": "https://pulsedive.com/explore/",
          "excerpts": [
            "Indicators",
            "CSV fields All Indicator ID Type Risk Threats Feeds User Submission Count Risk Factors Reference URL",
            "Indicator types All Domain IP IPv6 URL Indicator risk",
            "10 results 10 results Sign up for more"
          ]
        },
        {
          "title": "Search - urlscan.io",
          "url": "https://urlscan.io/search/",
          "excerpts": [
            "Search for domains, IPs, filenames, hashes, ASNs Search Scans",
            "Search results (100 / 10000 \\+ , sorted by date, took 20ms) Showing All Hits Details: Hidden |URL |Age |Size | |",
            "(10000 results in total, 100 shown)",
            "|Public [www.credit-agricole-conseil-invest.ph/](https://urlscan.io/result/01a0d710-44e3-7608-a1cc-6980a37ed33e/ \"www.credit-agricole-conseil-invest.ph/\") |10 seconds |1 |1 |0 | |",
            "|Public [www.sindonews.com/](https://urlscan.io/result/01a0d710-80c8-7133-a2fc-acf75d6e84e2/ \"www.sindonews.com/\") |14 seconds |4 MB |207 |35 |5 | |",
            "|Public [www.davidzwirner.com/collect](https://urlscan.io/result/01a0d70f-c8e9-76ad-89b9-d4be7df7783a/ \"www.davidzwirner.com/collect\") |19 seconds |1 MB |70 |4 |2 | |"
          ]
        },
        {
          "title": "API Documentation - urlscan.io",
          "url": "https://urlscan.io/docs/api/",
          "excerpts": [
            "Furthermore, you can use an API for searching existing scans by attributes such as domains, IPs, Autonomous System (AS) numbers, hashes, etc.",
            "You can use the same ElasticSearch syntax to search for scans as on the [Search](https://urlscan.io/search/) page.",
            "To use the APIs, you should [create a user account](https://urlscan.io/user/signup/) , attach an API key and supply it when calling the API.",
            "Unauthenticated users only received minor quotas for API calls.",
            "Furthermore, you can use an API for searching existing scans by attributes such as domains, IPs, Autonomous System (AS) numbers, hashes, etc. To use the APIs, you should [create a user account](https://urlscan.io/user/signup/) , attach an API key and supply it when calling the API. Unauthenticated users only received minor quotas for API calls."
          ]
        },
        {
          "title": "MISP Default Feeds",
          "url": "https://www.misp-project.org/feeds/",
          "excerpts": [
            "MISP includes a set of public OSINT feeds in its default configuration. The feeds can be used as a source of correlations for all of your events and attributes without the need to import them directly into your system.",
            "The feeds can be in three different formats: [MISP standardized format](https://github.com/MISP/misp-rfc/blob/master/misp-core-format/raw.md.txt) which is the preferred format to benefit from all the MISP functionalities. CSV format, allowing you to pick the columns that are to be imported. freetext format which allows automatic ingestion and detection of indicator/attribute by parsing any unstructured text. and located in different input transports: Network (URL) Local (file)",
            "[IPs from High-Confidence DGA-Based C&Cs Actively Resolving - requires a valid license](https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt) \\- osint.bambenekconsulting.com - feed format: csv",
            "[IPsum (aggregation of all feeds) - level 1 - lot of false positives](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt) \\- IPsum - feed format: freetext",
            "MISP includes a set of public OSINT feeds in its default configuration. The feeds can be used as a source of correlations for all of your events and attributes without the need to import them directly into your system. The MISP feed system allows for fast correlation but also a for quick comparisons of the feeds against one another. The feeds can be in three different formats: [MISP standardized format](https://github.com/MISP/misp-rfc/blob/master/misp-core-format/raw.md.txt) which is the preferred format to benefit from all the MISP functionalities. CSV format, allowing you to pick the columns that are to be imported. freetext format which allows automatic ingestion and detection of indicator/attribute by parsing any unstructured text. and located in different input transports: Network (URL) Local (file)",
            "[IPs from High-Confidence DGA-Based C&Cs Actively Resolving - requires a valid license](https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt) \\- osint.bambenekconsulting.com - feed format: csv [ipspamlist](http://www.ipspamlist.com/public_feeds.csv) \\- ipspamlist - feed format: csv [IPsum (aggregation of all feeds) - level 1 - lot of false positives](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt) \\- IPsum - feed format: freetext"
          ]
        }
      ],
      "reasoning": "Reasoning: The field_answer presents a structured table listing OSINT sources with columns matching the requested fields (Source Name, Website URL, Type of Indicators Hosted, Access Type). The sources included (LevelBlue/AlienVault OTX, Pulsedive Explore, urlscan.io search, MISP default feeds) align with the user query that sought primary source websites, OSINT platforms, threat-tracking databases, and security repositories that publish malicious indicators, while explicitly not listing the links themselves. The excerpts provided corroborate the existence and nature of these sources (OTX, Pulsedive, urlscan, and MISP feeds) and describe access mechanisms (API keys, public search, CSV/feeds). The answer appears to cover the expected scope and structure; hence completeness is true. The excerpts support the entries in the table since they reference the same platforms and describe their indicator types and access methods.",
      "confidence": "high"
    },
    {
      "field": "maintained_github_ioc_repositories",
      "citations": [
        {
          "title": "GitHub - Cisco-Talos/IOCs: Indicators of Compromise · GitHub",
          "url": "https://github.com/Cisco-Talos/IOCs",
          "excerpts": [
            "2022/ 2023/ 2024/ 2025/ 2026/",
            "2025/",
            "Description: Indicators of Compromise"
          ]
        },
        {
          "title": "IOCs/2026/08 at main · Cisco-Talos/IOCs · GitHub",
          "url": "https://github.com/Cisco-Talos/IOCs/tree/main/2026/08",
          "excerpts": [
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main",
            "UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt",
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main Contents UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt"
          ]
        },
        {
          "title": "GitHub - eset/malware-ioc: Indicators of Compromises (IOC) of our various investigations · GitHub",
          "url": "https://github.com/eset/malware-ioc",
          "excerpts": [
            "`.yar` files are [Yara](http://plusvic.github.io/yara/) rules `.rules` files are [Snort](http://snort.org/) rules `samples.md5` , `samples.sha1` and `samples.sha256` files are newline separated list of hexadecimal digests of malware samples",
            "GhostRedirector/ PlushDaemon/ ace_cryptor/",
            "emotet/",
            "operation_texonto/",
            "ransomhub/",
            "zimbra_phishing/",
            "Created: 2014-03-13T14:48:04.000Z",
            "Here are indicators of compromise (IOCs) of our various investigations. We are doing this to help the broader security community fight malware wherever it might be.",
            "Description: Indicators of Compromises (IOC) of our various investigations - eset/malware-ioc",
            "eset/malware-ioc Page: GitHub repository URL: https://github.com/eset/malware-ioc Description: Indicators of Compromises (IOC) of our various investigations - eset/malware-ioc"
          ]
        },
        {
          "title": "GitHub - PaloAltoNetworks/Unit42-timely-threat-intel: A collection of files with indicators supporting social media posts from Palo Alto Network's Unit 42 team to disseminate timely threat intelligence. · GitHub",
          "url": "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel",
          "excerpts": [
            "Top-level files 2020-08-20-IOCs-for-Emotet-infection-with-Qakbot.txt",
            "2020-09-01-IOCs-for-Raccoon-Stealer.txt 2020-09-07-IOCs-for-Dridex-infection.txt",
            "2024-01-08-IOCs-for-GootLoader-infection.txt 2024-01-12-IOCs-from-StealC-activity.txt 2024-01-17-IOCs-for-WikiLoader-activity.txt 2024-01-19-IOCs-for-GootLoader-infection.txt",
            "2026-01-07-scams-using-calendar-invites.txt 2026-01-16-W-8BEN-themed-phishing-activity.txt 2026-01-22-Attack-chain-targeting-users-looking-for-legitimate-tools.txt 2026-01-30-IOCs-for-traffic-ticket-search-portal-themed-phishing.txt 2026-02-03-IOCs-from-KongTuke-ClickFix-activity.txt 2026-02-04-IOCs-for-December-2025-Contagious-Interview-activity.txt 2026-02-05-IOCs-for-phishing-and-scams.txt 2026-02-06-IOCs-for-Super-Bowl-LX-scams.txt 2026-02-10-IOCs-for-smishing-impersonating-US-wireless-carriers.txt 2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt 2026-02-13-IOCs-for-tactics-by-browser-extensions-to-avoid-bans.txt 2026-02-20- AI-Accelerated Malicious Chrome Extension Campaigns.txt 2026-02-20-IOCs-for-tech-support-scam-activity.txt 2026-02-27-IOCs-for-Alloy-Taurus-infrastructure 2026-03-09-Threat-Alert-30K-domains-distributing-malicious-AI-related-browser-extension.txt",
            "2026-03-10-IOCs-for-VoidLink-activity.txt 2026-03-12-Vishing-Campaigns-Lead-to-Data-Theft-and-Extortion.txt 2026-03-19-THE-GHOST-IN-CAMPAIGN.txt 2026-03-23- Device-Code-based-OAuth-Phishing.txt 2026-03-30-KIMWOLF-V7-IoT.txt 2026-03-31-SHub-Stealer-Activity.txt 2026-04-02-Threat-Actor-Targets-Military-Entities.txt 2026-04-07-Montana-Empire.txt 2026-04-13-LORIKAZZ-ANDROID-IOT.txt 2026-04-15-SEO-Poisoning.txt",
            "Description: A collection of files with indicators supporting social media posts from Palo Alto Network's Unit 42 team to disseminate timely threat intelligence. - PaloAltoNetworks/Unit42-timely-threat-intel",
            "This repository contains files with indicators supporting social media posts designed to disseminate timely threat intelligence data from Palo Alto Network's Unit 42 team.",
            "2026-01-07-scams-using-calendar-invites.txt 2026-01-16-W-8BEN-themed-phishing-activity.txt 2026-01-22-Attack-chain-targeting-users-looking-for-legitimate-tools.txt 2026-01-30-IOCs-for-traffic-ticket-search-portal-themed-phishing.txt 2026-02-03-IOCs-from-KongTuke-ClickFix-activity.txt 2026-02-04-IOCs-for-December-2025-Contagious-Interview-activity.txt 2026-02-05-IOCs-for-phishing-and-scams.txt 2026-02-06-IOCs-for-Super-Bowl-LX-scams.txt 2026-02-10-IOCs-for-smishing-impersonating-US-wireless-carriers.txt 2026-02-11-IOCs-for-RAT-disguinsed-as-AI-based-browser-extension.txt 2026-02-13-IOCs-for-tactics-by-browser-extensions-to-avoid-bans.txt 2026-02-20- AI-Accelerated Malicious Chrome Extension Campaigns.txt 2026-02-20-IOCs-for-tech-support-scam-activity.txt 2026-02-27-IOCs-for-Alloy-Taurus-infrastructure 2026-03-09-Threat-Alert-30K-domains-distributing-malicious-AI-related-browser-extension.txt 2026-03-10-IOCs-for-VoidLink-activity.txt 2026-03-12-Vishing-Campaigns-Lead-to-Data-Theft-and-Extortion.txt 2026-03-19-THE-GHOST-IN-CAMPAIGN.txt 2026-03-23- Device-Code-based-OAuth-Phishing.txt 2026-03-30-KIMWOLF-V7-IoT.txt 2026-03-31-SHub-Stealer-Activity.txt 2026-04-02-Threat-Actor-Targets-Military-Entities.txt 2026-04-07-Montana-Empire.txt 2026-04-13-LORIKAZZ-ANDROID-IOT.txt 2026-04-15-SEO-Poisoning.txt",
            "Top-level files 2020-08-20-IOCs-for-Emotet-infection-with-Qakbot.txt 2020-08-24-IOCs-for-Trickbot-gtag-ono66.txt 2020-08-25-IOCs-for-Emotet-with-Trickbot.txt 2020-09-01-IOCs-for-Raccoon-Stealer.txt 2020-09-07-IOCs-for-Dridex-infection.txt"
          ]
        },
        {
          "title": "GitHub - bitdefender/malware-ioc: Indicators of Compromise for malware documented in whitepapers. · GitHub",
          "url": "https://github.com/bitdefender/malware-ioc",
          "excerpts": [
            "This space aggregates Indicators of Compromise detailed in research papers published by Bitdefender on [Bitdefender Labs](https://labs.bitdefender.com/) .",
            "dark_nexus/ metamorfo_malware/ rdp_abusers/ silkparasite-2026_08/ vapor_malware/",
            "2026_02_11-Lumma-Stealer-ioc.csv 2026_03_05-apt36-iocs.csv 2026_03_31-axios-iocs.csv 2026_05_13-famoussparrow-iocs.csv 2026_08-silkparasite-iocs.csv"
          ]
        },
        {
          "title": "GitHub - 0xDanielLopez/TweetFeed: TweetFeed collects Indicators of Compromise (IOCs) shared by the infosec community at Twitter. Here you will find malicious URLs, domains, IPs, and SHA256/MD5 hashes. · GitHub",
          "url": "https://github.com/0xDanielLopez/TweetFeed",
          "excerpts": [
            "Description: TweetFeed collects Indicators of Compromise (IOCs) shared by the infosec community at Twitter. Here you will find malicious URLs, domains, IPs, and SHA256/MD5 hashes. - 0xDanielLopez/TweetFeed",
            "Types |Type |Today |Week |Month |Year | |**🔗 URLs** |26 |146 |3769 |52622 | |**🌐 Domains** |26 |137 |3319 |42101 | |**🚩 IPs** |4 |23 |644 |8937 | |**🔢 SHA256** |3 |10 |382 |2727 | |**🔢 MD5** |0 |5 |203 |2434 |",
            "2025/",
            "|2026-09-01 22:15:17 (UTC) | |",
            "> The counters below (timestamp, per-type totals, tag count, top tags, top reporters) are regenerated by the pipeline every 15 minutes."
          ]
        },
        {
          "title": "GitHub - openphish/public_feed: OpenPhish Community Phishing Feed · GitHub",
          "url": "https://github.com/openphish/public_feed",
          "excerpts": [
            "Top-level files README.md feed.txt",
            "OpenPhish Community Phishing Feed Updated every 12 hours",
            "OpenPhish Community Phishing Feed Updated every 12 hours Non-commercial use only",
            "Top-level files README.md feed.txt README.md OpenPhish Community Phishing Feed Updated every 12 hours"
          ]
        },
        {
          "title": "GitHub - firehol/blocklist-ipsets: ipsets dynamically updated with firehol's update-ipsets.sh script · GitHub",
          "url": "https://github.com/firehol/blocklist-ipsets",
          "excerpts": [
            "This repository includes a list of ipsets dynamically updated with [FireHOL](https://github.com/firehol/firehol) 's `update-ipsets.sh` [documented in this wiki](https://github.com/firehol/blocklist-ipsets/wiki) .",
            "> Due to the amount of data and the frequency of the updates on this repo, > github has requested to limit the number of updates. > The site [https://iplists.firehol.org](https://iplists.firehol.org/) has direct links > to all the files in this repo. **This repo is now updated once per day.** > >",
            "Please be very careful what you choose to use and how you use it. If you blacklist traffic using these lists you may end up blocking your users, your customers, even yourself (!) from accessing your services. Go to to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.",
            "They are freely available on the internet. The intention of their creators is to help internet security. Keep in mind though that a few of these lists may have special licences attached. Before using them, please check their source site for any information regarding proper use."
          ]
        },
        {
          "title": "GitHub - stamparm/ipsum: Daily feed of bad IPs (with blacklist hit scores) · GitHub",
          "url": "https://github.com/stamparm/ipsum",
          "excerpts": [
            "The feed contains IP addresses plus an occurrence count (how many source lists each IP appears on).",
            "Higher counts generally mean higher confidence and fewer false positives when blocking inbound traffic.",
            "Also, list is sorted by occurrence count (highest to lowest).",
            "All lists are automatically retrieved and parsed on a daily (every 24 hours) basis and the final result is pushed to this repository.",
            "ipsum.txt",
            "Wall of Shame (2026-09-23)",
            "All lists are automatically retrieved and parsed on a daily (every 24 hours) basis and the final result is pushed to this repository. The feed contains IP addresses plus an occurrence count (how many source lists each IP appears on). Higher counts generally mean higher confidence and fewer false positives when blocking inbound traffic. Also, list is sorted by occurrence count (highest to lowest)."
          ]
        },
        {
          "title": "GitHub - hagezi/dns-blocklists: DNS-Blocklists: For a better internet - keep the internet clean! · GitHub",
          "url": "https://github.com/hagezi/dns-blocklists",
          "excerpts": [
            "🔐 **Threat Intelligence Feeds, a serious security boost (recommended)**",
            "This blocklist targets malware, cryptojacking, scams, spam, and phishing. It blocks domains known for spreading malware, running phishing attacks, and hosting command-and-control servers.",
            "💾 Update Interval/Official Mirrors The lists are rebuilt several times a day, but not every source publishes every build.",
            "🔐 **Threat Intelligence Feeds, a serious security boost (recommended)** This blocklist targets malware, cryptojacking, scams, spam, and phishing. It blocks domains known for spreading malware, running phishing attacks, and hosting command-and-control servers."
          ]
        }
      ],
      "reasoning": "Assessment reasoning: The provided field_answer supplies a structured list of sources (Source Name, Website URL, Type of Indicators Hosted, Access Type) which matches the requested output format for the field maintained_github_ioc_repositories. Excerpts include multiple GitHub IOC repositories (e.g., Cisco-Talos/IOCs, eset/malware-ioc, Unit42 timely-threat-intel, etc.) and describe the nature of the indicators and access modes, aligning with the user query guidance to identify live or regularly updated sources that publish raw IOCs. The field description asks to present discovered sources; the answer indeed lists several sources with the required columns and adds context about campaign case studies and currency. Therefore, the answer is complete with respect to the field’s expectations and is supported by the provided excerpts which reference the listed repositories and their contents.",
      "confidence": "high"
    },
    {
      "field": "campaign_diaries_and_research_archives",
      "citations": [
        {
          "title": "SANS.edu Internet Storm Center - SANS Internet Storm Center",
          "url": "https://isc.sans.edu/",
          "excerpts": [
            "Published: 2026-09-17 by Jan Kopriva",
            "_**Indicators of Compromise**_ The following are indicators from Tuesday, 2026-09-22.",
            "ClickFix text from the Macfinger domain, saved to a text file: SHA-256 hash: [6606a5f18184b224a56c9cb658fa26f7fce45099da548a30a8db2c5f2c70377c](https://www.virustotal.com/gui/file/6606a5f18184b224a56c9cb658fa26f7fce45099da548a30a8db2c5f2c70377c/) File size: 581 bytes Initial download: SHA-256 hash: [9d87b41c2b29ccbeac851b98f1a7dce4ab4781fec0cbc55fa6f93a6299a3d564](https://www.virustotal.com/gui/file/9d87b41c2b29ccbeac851b98f1a7dce4ab4781fec0cbc55fa6f93a6299a3d564/) File size: 4,674 bytes File type: Bourne-Again shell script text executable, ASCII text, with very long lines File location: hxxp[:]//45.150.33[.]128/92961f75b259df2?force=1 Follow-up malware from the above shell script:",
            "Post-infection Traffic: 2026-09-21 23:12:58 UTC - hxxp[:]//45.150.33[.]128 - GET /92961f75b259df2?force=1 2026-09-21 23:12:59 UTC - hxxp[:]//95.163.153[.]80:8133 - POST /api/t"
          ]
        },
        {
          "title": "InfoSec Diary Blog Archive - SANS Internet Storm Center",
          "url": "https://isc.sans.edu/diaryarchive.html",
          "excerpts": [
            "Diaries Latest Diaries 2026 2025 2024 2023 2022 2021 2020 2019 2018 2017 2016 2015 2014 2013 2012 2011 2010 2009 2008 2007 2006 2005 2004 2003 Published: 2026-09-18 HTTP QUERY Method: The Grey Zone Between GET And POST."
          ]
        },
        {
          "title": "Malware-Traffic-Analysis.net - Posts - 2026",
          "url": "https://www.malware-traffic-analysis.net/2026/index.html",
          "excerpts": [
            "2026-01-30 \\-- PhantomStealer infection 2026-01-29 \\-- njRAT infection with MassLogger 2026-01-22 \\-- SmartApeSG uses ClickFix technique to push Remcos RAT 2026-01-20 \\-- Lumma stealer infection with follow-up malware 2026-01-20 \\-- VIP Recovery infection with FTP data exfiltration traffic",
            "2026-01-15 \\-- XLoader (Formbook) infection 2026-01-14 \\-- Lumma Stealer infection with follow-up malware 2026-01-10 \\-- Ten days of scans and probes and web traffic hitting my web server 2026-01-09 \\-- VIP Recovery infection from email attachment 2026-01-08 \\-- KongTuke ClickFix activity"
          ]
        },
        {
          "title": "Malware-Traffic-Analysis.net - 2026-08-10: Lumma Stealer or variant",
          "url": "https://www.malware-traffic-analysis.net/2026/08/10/index.html",
          "excerpts": [
            "ASSOCIATED FILE: [2026-08-10-notes.txt.zip](https://www.malware-traffic-analysis.net/2026/08/10/2026-08-10-notes.txt.zip) 1\\.2 kB   (1,156 bytes) [2026-08-10-traffic.pcap.zip](https://www.malware-traffic-analysis.net/2026/08/10/2026-08-10-traffic.pcap.zip) 8\\.0 MB   (8,000,257 bytes) [2026-08-10-malware.zip](https://www.malware-traffic-analysis.net/2026/08/10/2026-08-10-malware.zip) 6\\.1 MB   (6,073,610 bytes)",
            "2026-08-10 (MONDAY): LUMMA STEALER OR VARIANT NOTES: Zip files are password-protected.  Of note, this site has a new password scheme.  For the password, see the \"about\" page of this website. ASSOCIATED FILE: [2026-08-10-notes.txt.zip](https://www.malware-traffic-analysis.net/2026/08/10/2026-08-10-notes.txt.zip) 1\\.2 kB   (1,156 bytes) [2026-08-10-traffic.pcap.zip](https://www.malware-traffic-analysis.net/2026/08/10/2026-08-10-traffic.pcap.zip) 8\\.0 MB   (8,000,257 bytes) [2026-08-10-malware.zip](https://www.malware-traffic-analysis.net/2026/08/10/2026-08-10-malware.zip) 6\\.1 MB   (6,073,610 bytes) IMAGES [Click here](https://www.malware-traffic-analysis.net/index.html) to return to the main page."
          ]
        },
        {
          "title": "Cisco Talos Blog",
          "url": "https://blog.talosintelligence.com/",
          "excerpts": [
            "[Talos Intelligence Blog](https://blog.talosintelligence.com/)",
            "Recent",
            "[View all categories](https://blog.talosintelligence.com/categories)"
          ]
        },
        {
          "title": "IOCs/2026/08 at main · Cisco-Talos/IOCs · GitHub",
          "url": "https://github.com/Cisco-Talos/IOCs/tree/main/2026/08",
          "excerpts": [
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main",
            "UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt",
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main Contents UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt"
          ]
        }
      ],
      "reasoning": "Assessment: The field answer provides a small, three-row table listing SANS Internet Storm Center diaries, Malware-Traffic-Analysis.net, and Cisco Talos Blog as sources, which aligns with the query's aim to identify primary sources, OSINT platforms, threat-tracking databases, and security repositories that publish malicious indicators (or related raw materials) via landing pages or feeds. However, the user requested a comprehensive, structured table including multiple sources such as URLhaus, PhishTank, MalwareBazaar, ThreatFox, OpenPhish, and active GitHub IOC repositories, and to present live tables/feeds of malicious indicators. The provided field_answer includes only three sources and omits several well-known, relevant sources called out in the guidance. Therefore, completeness should be false since it does not fully meet the breadth of the requested sources. Excerpts do support the included entries (SANS ISC, Malware-Traffic-Analysis.net, Cisco Talos Blog), as the excerpts contain relevant mentions and URLs that corroborate these entries. Nonetheless, there is not enough coverage to claim completeness across the requested landscape.",
      "confidence": "low"
    },
    {
      "field": "synthesis",
      "citations": [
        {
          "title": "URLhaus | Malware URL exchange",
          "url": "https://urlhaus.abuse.ch/",
          "excerpts": [
            "URLhaus is a platform from abuse.ch and Spamhaus dedicated to sharing malicious URLs that are being used for malware distribution.",
            "Browse malware URLs Gain valuable insights and find the latest malicious URLs being used for malware distribution. [Access database »](https://urlhaus.abuse.ch/browse/)",
            "Use the APIs, to seamlessly push and pull signals, and automate bulk queries."
          ]
        },
        {
          "title": "MalwareBazaar | Malware sample exchange",
          "url": "https://bazaar.abuse.ch/",
          "excerpts": [
            "🤲🏼 **NEW** | abuse.ch Community Hub!"
          ]
        },
        {
          "title": "Feodo Tracker",
          "url": "https://feodotracker.abuse.ch/",
          "excerpts": [
            "Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor). It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo.",
            "It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo. [Download Blocklist »](https://feodotracker.abuse.ch/blocklist/)",
            "Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor). It offers various blocklists, helping network owners to protect their users from Dridex and Emotet/Heodo. [Download Blocklist »](https://feodotracker.abuse.ch/blocklist/)"
          ]
        },
        {
          "title": "URLhaus | Community API",
          "url": "https://urlhaus.abuse.ch/api/",
          "excerpts": [
            "You can choose between CSV and JSON format.",
            "Whenever you try to download a dataset or file from below, you must include your `Auth-Key` in the URL.",
            "Manual submissions through the URLhaus [web interface](https://urlhaus.abuse.ch/browse/) (note: you need to authenticate yourself with your [abuse.ch account](https://auth.abuse.ch/ \"Login to abuse.ch\") )"
          ]
        },
        {
          "title": "MalwareBazaar | Export",
          "url": "https://bazaar.abuse.ch/export/",
          "excerpts": [
            "MalwareBazaar offers the exporting of hash lists in the following formats:",
            "**Recent** datasets (\"recent additions\") include hashes for the last 48 hours and are being generated every **5 minutes** . Please do not fetch them more often than that. **Full** data dumps include all hashes and are only being generated once per hour.",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first.",
            "In order to access the datasets listed below, you need to obtain an `Auth-Key` first. If you don't have one you can get one for free here: [abuse.ch Authentication Portal](https://auth.abuse.ch/) Whenever you try to download a dataset or file from below, you must include the URI parameter `auth-key` which contains your Auth-Key as value."
          ]
        },
        {
          "title": "Don't Route Or Peer Lists (DROP) | Use with firewalls & BGP",
          "url": "https://www.spamhaus.org/blocklists/do-not-route-or-peer",
          "excerpts": [
            "The Spamhaus DROP lists consist of netblocks that are leased or stolen by professional spam or cyber-crime operations, and used for dissemination of malware, trojan downloaders, botnet controllers, or other kinds of malicious activity.",
            "The free DROP datasets are provided in JSON format to be parsed out and implemented on nearly any kind of device or software that is capable of processing IP networks for making a decision e.g., network gateways, firewalls, web-proxies, DNS resolvers etc.",
            "**DROP** \\- [https://www.spamhaus.org/drop/drop\\_v4.json](https://www.spamhaus.org/drop/drop_v4.json) **DROPv6** \\- [https://www.spamhaus.org/drop/drop\\_v6.json](https://www.spamhaus.org/drop/drop_v6.json) **ASN-DROP** \\- <https://www.spamhaus.org/drop/asndrop.json>",
            "Spamhaus believes that due to the vital nature of the DROP list data, it should be available at no cost, regardless of size or business type, to protect internet users.",
            "We do ask, when used in a product, credit must be given to Spamhaus Project, and the date and © text should remain with the file and data.",
            "For long-term users of the DROP files in text format, we recommend you update your configuration with the above JSON files as soon as your cycles allow.",
            "Spamhaus believes that due to the vital nature of the DROP list data, it should be available at no cost, regardless of size or business type, to protect internet users. We do ask, when used in a product, credit must be given to Spamhaus Project, and the date and © text should remain with the file and data."
          ]
        },
        {
          "title": "Using Our Data Feeds - SANS Internet Storm Center",
          "url": "https://www.dshield.org/feeds_doc.html",
          "excerpts": [
            "<https://feeds.dshield.org/feeds/topips.txt> : Top 100 IP addresses and hostnames. <https://feeds.dshield.org/feeds/top10.txt> : Just IPs. No hostnames <https://feeds.dshield.org/feeds/block.txt> : Top 20 most active networks [https://feeds.dshield.org/feeds/daily\\_sources](https://feeds.dshield.org/feeds/daily_sources) : Daily summary of all source IPs",
            "Avoid downloading the data more than once an hour.",
            "Use of data premitted with attribution: SANS Technology Institute, Internet Storm Center, https://isc.sans.edu (you may feel free to change the format of the attribution according to your guidelines). Do not resell the data. Other commercial uses are allowed."
          ]
        },
        {
          "title": "GitHub - firehol/blocklist-ipsets: ipsets dynamically updated with firehol's update-ipsets.sh script · GitHub",
          "url": "https://github.com/firehol/blocklist-ipsets",
          "excerpts": [
            "This repository includes a list of ipsets dynamically updated with [FireHOL](https://github.com/firehol/firehol) 's `update-ipsets.sh` [documented in this wiki](https://github.com/firehol/blocklist-ipsets/wiki) .",
            "> Due to the amount of data and the frequency of the updates on this repo, > github has requested to limit the number of updates. > The site [https://iplists.firehol.org](https://iplists.firehol.org/) has direct links > to all the files in this repo. **This repo is now updated once per day.** > >",
            "Please be very careful what you choose to use and how you use it. If you blacklist traffic using these lists you may end up blocking your users, your customers, even yourself (!) from accessing your services. Go to to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.",
            "They are freely available on the internet. The intention of their creators is to help internet security. Keep in mind though that a few of these lists may have special licences attached. Before using them, please check their source site for any information regarding proper use."
          ]
        },
        {
          "title": "LevelBlue - Open Threat Exchange",
          "url": "https://otx.alienvault.com/",
          "excerpts": [
            "Synchronize OTX threat intelligence with other security products via DirectConnect API, SDK, and STIX/TAXII",
            "You can launch a query on any endpoint from OTX by selecting a pre-defined query that looks for IOCs in one or more OTX pulses.",
            "OTX Endpoint Security™ is available to any registered Open Threat Exchange (OTX) user. It’s free to join OTX.",
            "**Please note:** this is a separate account from the LevelBlue Community and legacy Open Threat Exchange accounts."
          ]
        },
        {
          "title": "Search - urlscan.io",
          "url": "https://urlscan.io/search/",
          "excerpts": [
            "Search for domains, IPs, filenames, hashes, ASNs Search Scans",
            "Search results (100 / 10000 \\+ , sorted by date, took 20ms) Showing All Hits Details: Hidden |URL |Age |Size | |",
            "(10000 results in total, 100 shown)",
            "|Public [www.credit-agricole-conseil-invest.ph/](https://urlscan.io/result/01a0d710-44e3-7608-a1cc-6980a37ed33e/ \"www.credit-agricole-conseil-invest.ph/\") |10 seconds |1 |1 |0 | |",
            "|Public [www.sindonews.com/](https://urlscan.io/result/01a0d710-80c8-7133-a2fc-acf75d6e84e2/ \"www.sindonews.com/\") |14 seconds |4 MB |207 |35 |5 | |",
            "|Public [www.davidzwirner.com/collect](https://urlscan.io/result/01a0d70f-c8e9-76ad-89b9-d4be7df7783a/ \"www.davidzwirner.com/collect\") |19 seconds |1 MB |70 |4 |2 | |"
          ]
        },
        {
          "title": "FireHOL IP Lists | IP Blacklists | IP Blocklists | IP Reputation",
          "url": "https://iplists.firehol.org/",
          "excerpts": [
            "This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** .",
            "It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data.",
            "The data on this page are automatically generated using FireHOL's [update-ipsets.sh](https://github.com/firehol/firehol/blob/master/sbin/update-ipsets) (for downloading the lists from their sources and generating the data for this site), which utilizes [iprange](https://github.com/firehol/firehol/wiki/iprange:-optimizing-ipsets-for-iptables) (for comparing and manipulating IP lists).",
            "This site is a single **static** page, with all its data uploaded as static JSON and CSV files every time an IP List is updated.",
            "It uses IP lists and related data provided and maintained by their respective owners (mentioned together with each IP list), IP-to-country geolocation data provided by [maxmind.com](https://www.maxmind.com/) (GeoLite2), [ipdeny.com](http://www.ipdeny.com/) , [ip2location.com](http://www.ip2location.com/) (Lite) and [ipip.net](http://ipip.net/) , javascript chart libraries provided by [highcharts.com](http://www.highcharts.com/) , comments engine provided by [disqus.com](https://disqus.com/) , social media sharing buttons provided by [shareaholic.com](https://shareaholic.com/) , the HTML, CSS and JS framework [bootstrap](https://getbootstrap.com/) , the [bootstrap-table](http://bootstrap-table.wenzhixin.net.cn/) component, icons provided by [iconsdb.com](http://www.iconsdb.com/) and it uses several services provided by [github](https://github.com/) .",
            "This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** . It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data.",
            "This site is a single **static** page, with all its data uploaded as static JSON and CSV files every time an IP List is updated. For the final result, it utilizes IP data and web services provided by third parties. It uses IP lists and related data provided and maintained by their respective owners (mentioned together with each IP list), IP-to-country geolocation data provided by [maxmind.com](https://www.maxmind.com/) (GeoLite2), [ipdeny.com](http://www.ipdeny.com/) , [ip2location.com](http://www.ip2location.com/) (Lite) and [ipip.net](http://ipip.net/) , javascript chart libraries provided by [highcharts.com](http://www.highcharts.com/) , comments engine provided by [disqus.com](https://disqus.com/) , social media sharing buttons provided by [shareaholic.com](https://shareaholic.com/) , the HTML, CSS and JS framework [bootstrap](https://getbootstrap.com/) , the [bootstrap-table](http://bootstrap-table.wenzhixin.net.cn/) component, icons provided by [iconsdb.com](http://www.iconsdb.com/) and it uses several services provided by [github](https://github.com/) . × About this site This site **aggregates** , **analyzes** , **compares** and **documents** publicly available IP Feeds, with a focus on **attacks** and **abuse** . It is automatically generated and maintained using **open source** software (check the wiki), that can be installed and run on your systems too, to download all IP lists directly from their maintainers, process them and re-generate the site and its data."
          ]
        },
        {
          "title": "IOCs/2026/08 at main · Cisco-Talos/IOCs · GitHub",
          "url": "https://github.com/Cisco-Talos/IOCs/tree/main/2026/08",
          "excerpts": [
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main",
            "UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt",
            "Cisco-Talos/IOCs — 2026/08 Page: GitHub directory listing URL: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08 Repository: Cisco-Talos/IOCs Path: 2026/08 Ref: main Contents UAT-10147 deploys SPECTRE.json UAT-10147 deploys SPECTRE.txt UAT-10147 integrates agentic AI.json UAT-10147 integrates agentic AI.txt dissecting-the-jwr-phishing-framework.json dissecting-the-jwr-phishing-framework.txt"
          ]
        },
        {
          "title": "SANS.edu Internet Storm Center - SANS Internet Storm Center",
          "url": "https://isc.sans.edu/",
          "excerpts": [
            "Published: 2026-09-17 by Jan Kopriva",
            "_**Indicators of Compromise**_ The following are indicators from Tuesday, 2026-09-22.",
            "ClickFix text from the Macfinger domain, saved to a text file: SHA-256 hash: [6606a5f18184b224a56c9cb658fa26f7fce45099da548a30a8db2c5f2c70377c](https://www.virustotal.com/gui/file/6606a5f18184b224a56c9cb658fa26f7fce45099da548a30a8db2c5f2c70377c/) File size: 581 bytes Initial download: SHA-256 hash: [9d87b41c2b29ccbeac851b98f1a7dce4ab4781fec0cbc55fa6f93a6299a3d564](https://www.virustotal.com/gui/file/9d87b41c2b29ccbeac851b98f1a7dce4ab4781fec0cbc55fa6f93a6299a3d564/) File size: 4,674 bytes File type: Bourne-Again shell script text executable, ASCII text, with very long lines File location: hxxp[:]//45.150.33[.]128/92961f75b259df2?force=1 Follow-up malware from the above shell script:",
            "Post-infection Traffic: 2026-09-21 23:12:58 UTC - hxxp[:]//45.150.33[.]128 - GET /92961f75b259df2?force=1 2026-09-21 23:12:59 UTC - hxxp[:]//95.163.153[.]80:8133 - POST /api/t"
          ]
        }
      ],
      "reasoning": "Assessment reasoning:\n- The field_description requests a structured table of sources, including Source Name, Website URL, Type of Indicators Hosted, and Access Type, describing primary sources for malicious indicators. \n- The provided field_answer is a four-column table describing indicator classes, arrival methods, best use, and trade-offs, not the requested structured source catalog with the four specific columns. Therefore, the field_answer does not fully satisfy the described output format and content requirements. Hence, completeness is false. \n- However, the excerpts include multiple sources (e.g., URLhaus, MalwareBazaar, Feodo Tracker, Spamhaus DROP, DShield, FireHOL IP Lists, OTX, urlscan.io, etc.) and align with the general topic of live feeds and public indicator sources. The field_answer references categories and specific sources consistent with the excerpts. Therefore, the field_answer is at least partially supported by the excerpts. Hence, supported is true.",
      "confidence": "low"
    }
  ],
  "outputSchema": {
    "type": "object",
    "properties": {
      "executive_summary": {
        "type": "string",
        "title": "Executive Summary"
      },
      "malware_delivery_urls_and_file_hash_collections": {
        "type": "string",
        "title": "Malware-Delivery URLs and File-Hash Collections"
      },
      "phishing_url_and_dangerous_domain_feeds": {
        "type": "string",
        "title": "Phishing URL and Dangerous-Domain Feeds"
      },
      "botnet_c2_and_ransomware_infrastructure": {
        "type": "string",
        "title": "Botnet, C2 and Ransomware Infrastructure"
      },
      "attack_ip_lists_and_domain_blocklists": {
        "type": "string",
        "title": "Attack-IP Lists and Domain Blocklists"
      },
      "osint_search_and_feed_directories": {
        "type": "string",
        "title": "OSINT Search and Feed Directories"
      },
      "maintained_github_ioc_repositories": {
        "type": "string",
        "title": "Maintained GitHub IOC Repositories"
      },
      "campaign_diaries_and_research_archives": {
        "type": "string",
        "title": "Campaign Diaries and Research Archives"
      },
      "synthesis": {
        "type": "string",
        "title": "Synthesis"
      }
    },
    "required": [
      "executive_summary",
      "malware_delivery_urls_and_file_hash_collections",
      "phishing_url_and_dangerous_domain_feeds",
      "botnet_c2_and_ransomware_infrastructure",
      "attack_ip_lists_and_domain_blocklists",
      "osint_search_and_feed_directories",
      "maintained_github_ioc_repositories",
      "campaign_diaries_and_research_archives",
      "synthesis"
    ]
  }
}
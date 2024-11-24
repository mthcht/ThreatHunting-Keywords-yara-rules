rule thoth
{
    meta:
        description = "Detection patterns for the tool 'thoth' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thoth"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string1 = /\s\-d\s.{0,1000}\s\-t\saxfr\s\>/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string2 = /\s\-d\s.{0,1000}\s\-t\szonewalk\s\>\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string3 = " enum -passive -d " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string4 = " -im amass -ir " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string5 = " -im get-dns-records" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string6 = " -im github-get-repositories" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string7 = " -im google-get-linkedIn-employees" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string8 = " -im grep-through-commits" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string9 = " -im massdns" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string10 = " --includeModules amass" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string11 = /\sintel\s\-d\s.{0,1000}\s\-whois/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string12 = " -rl 4 -ta 8 -t 2100 -an AS8560" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string13 = /\/thoth\.git/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string14 = /\/tmp\/amass\.zip/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string15 = "/tmp/bin/csprecon" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string16 = "/tmp/bin/subfinder" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string17 = "/tmp/FavFreak/" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string18 = /\/tmp\/geckodriver\.tar\.gz/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string19 = "/tmp/gitleaks" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string20 = /\/tmp\/scanrepo\.tar\.gz/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string21 = /\/tmp\/truffleHog\.tar\.gz/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string22 = /\|\sfavfreak/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string23 = "amass-get-rootdomains" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string24 = "amass-get-subdomains" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string25 = "completedns-get-ns-history" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string26 = "csprecon -" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string27 = "dnslytics-get-rootdomains" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string28 = "dnsrecon -" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string29 = "dnsrecon-zonetransfer" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string30 = "favfreak-http" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string31 = /git\slog\s\-p\s\|\sscanrepo\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string32 = "gitleaks detect" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string33 = "google-get-pdf-metadata " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string34 = "google-get-rootdomains " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string35 = /grep\-through\-commits\.sh\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string36 = "hackertarget-get-rootdomains " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string37 = "hakrawler-ip-range" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string38 = "handelsregister-get-company-names " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string39 = "map-get-tls-alternative-names " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string40 = /massdns\s\-r\s.{0,1000}\.txt/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string41 = "MattKeeley/Spoofy" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string42 = "nmap-reverse-lookup" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string43 = "northdata-get-company-names " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string44 = "r1cksec/thoth" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string45 = "skymem-get-mails " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string46 = /Spoofy\/spoofy\.py/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string47 = "spyonweb-get-rootdomains " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string48 = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string49 = "subfinder --silent" nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string50 = /thoth\.py\s\-/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string51 = /thoth\-master\.zip/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string52 = "tmdb-get-company-names " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string53 = "trufflehog git " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string54 = "viewdns-get-rootdomains-ip-ns " nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string55 = "viewdns-get-rootdomains-whois " nocase ascii wide

    condition:
        any of them
}

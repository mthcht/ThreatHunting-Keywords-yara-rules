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
        $string1 = /.{0,1000}\s\-d\s.{0,1000}\s\-t\saxfr\s\>.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string2 = /.{0,1000}\s\-d\s.{0,1000}\s\-t\szonewalk\s\>\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string3 = /.{0,1000}\senum\s\-passive\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string4 = /.{0,1000}\s\-im\samass\s\-ir\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string5 = /.{0,1000}\s\-im\sget\-dns\-records.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string6 = /.{0,1000}\s\-im\sgithub\-get\-repositories.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string7 = /.{0,1000}\s\-im\sgoogle\-get\-linkedIn\-employees.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string8 = /.{0,1000}\s\-im\sgrep\-through\-commits.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string9 = /.{0,1000}\s\-im\smassdns.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string10 = /.{0,1000}\s\-\-includeModules\samass.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string11 = /.{0,1000}\sintel\s\-d\s.{0,1000}\s\-whois.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string12 = /.{0,1000}\s\-rl\s4\s\-ta\s8\s\-t\s2100\s\-an\sAS8560.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string13 = /.{0,1000}\/thoth\.git.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string14 = /.{0,1000}\/tmp\/amass\.zip.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string15 = /.{0,1000}\/tmp\/bin\/csprecon.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string16 = /.{0,1000}\/tmp\/bin\/subfinder.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string17 = /.{0,1000}\/tmp\/FavFreak\/.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string18 = /.{0,1000}\/tmp\/geckodriver\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string19 = /.{0,1000}\/tmp\/gitleaks.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string20 = /.{0,1000}\/tmp\/scanrepo\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string21 = /.{0,1000}\/tmp\/truffleHog\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string22 = /.{0,1000}\|\sfavfreak.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string23 = /.{0,1000}amass\-get\-rootdomains.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string24 = /.{0,1000}amass\-get\-subdomains.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string25 = /.{0,1000}completedns\-get\-ns\-history.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string26 = /.{0,1000}csprecon\s\-.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string27 = /.{0,1000}dnslytics\-get\-rootdomains.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string28 = /.{0,1000}dnsrecon\s\-.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string29 = /.{0,1000}dnsrecon\-zonetransfer.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string30 = /.{0,1000}favfreak\-http.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string31 = /.{0,1000}git\slog\s\-p\s\|\sscanrepo\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string32 = /.{0,1000}gitleaks\sdetect.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string33 = /.{0,1000}google\-get\-pdf\-metadata\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string34 = /.{0,1000}google\-get\-rootdomains\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string35 = /.{0,1000}grep\-through\-commits\.sh\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string36 = /.{0,1000}hackertarget\-get\-rootdomains\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string37 = /.{0,1000}hakrawler\-ip\-range.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string38 = /.{0,1000}handelsregister\-get\-company\-names\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string39 = /.{0,1000}map\-get\-tls\-alternative\-names\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string40 = /.{0,1000}massdns\s\-r\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string41 = /.{0,1000}MattKeeley\/Spoofy.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string42 = /.{0,1000}nmap\-reverse\-lookup.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string43 = /.{0,1000}northdata\-get\-company\-names\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string44 = /.{0,1000}r1cksec\/thoth.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string45 = /.{0,1000}skymem\-get\-mails\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string46 = /.{0,1000}Spoofy\/spoofy\.py.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string47 = /.{0,1000}spyonweb\-get\-rootdomains\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string48 = /.{0,1000}subdomains\-top1million\-110000\.txt.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string49 = /.{0,1000}subfinder\s\-\-silent.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string50 = /.{0,1000}thoth\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string51 = /.{0,1000}thoth\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string52 = /.{0,1000}tmdb\-get\-company\-names\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string53 = /.{0,1000}trufflehog\sgit\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string54 = /.{0,1000}viewdns\-get\-rootdomains\-ip\-ns\s.{0,1000}/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string55 = /.{0,1000}viewdns\-get\-rootdomains\-whois\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

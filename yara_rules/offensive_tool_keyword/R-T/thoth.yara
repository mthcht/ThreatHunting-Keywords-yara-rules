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
        $string3 = /\senum\s\-passive\s\-d\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string4 = /\s\-im\samass\s\-ir\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string5 = /\s\-im\sget\-dns\-records/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string6 = /\s\-im\sgithub\-get\-repositories/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string7 = /\s\-im\sgoogle\-get\-linkedIn\-employees/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string8 = /\s\-im\sgrep\-through\-commits/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string9 = /\s\-im\smassdns/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string10 = /\s\-\-includeModules\samass/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string11 = /\sintel\s\-d\s.{0,1000}\s\-whois/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string12 = /\s\-rl\s4\s\-ta\s8\s\-t\s2100\s\-an\sAS8560/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string13 = /\/thoth\.git/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string14 = /\/tmp\/amass\.zip/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string15 = /\/tmp\/bin\/csprecon/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string16 = /\/tmp\/bin\/subfinder/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string17 = /\/tmp\/FavFreak\// nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string18 = /\/tmp\/geckodriver\.tar\.gz/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string19 = /\/tmp\/gitleaks/ nocase ascii wide
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
        $string23 = /amass\-get\-rootdomains/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string24 = /amass\-get\-subdomains/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string25 = /completedns\-get\-ns\-history/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string26 = /csprecon\s\-/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string27 = /dnslytics\-get\-rootdomains/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string28 = /dnsrecon\s\-/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string29 = /dnsrecon\-zonetransfer/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string30 = /favfreak\-http/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string31 = /git\slog\s\-p\s\|\sscanrepo\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string32 = /gitleaks\sdetect/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string33 = /google\-get\-pdf\-metadata\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string34 = /google\-get\-rootdomains\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string35 = /grep\-through\-commits\.sh\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string36 = /hackertarget\-get\-rootdomains\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string37 = /hakrawler\-ip\-range/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string38 = /handelsregister\-get\-company\-names\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string39 = /map\-get\-tls\-alternative\-names\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string40 = /massdns\s\-r\s.{0,1000}\.txt/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string41 = /MattKeeley\/Spoofy/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string42 = /nmap\-reverse\-lookup/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string43 = /northdata\-get\-company\-names\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string44 = /r1cksec\/thoth/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string45 = /skymem\-get\-mails\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string46 = /Spoofy\/spoofy\.py/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string47 = /spyonweb\-get\-rootdomains\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string48 = /subdomains\-top1million\-110000\.txt/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string49 = /subfinder\s\-\-silent/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string50 = /thoth\.py\s\-/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string51 = /thoth\-master\.zip/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string52 = /tmdb\-get\-company\-names\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string53 = /trufflehog\sgit\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string54 = /viewdns\-get\-rootdomains\-ip\-ns\s/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string55 = /viewdns\-get\-rootdomains\-whois\s/ nocase ascii wide

    condition:
        any of them
}

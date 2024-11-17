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
        $string1 = /\s\-d\s.{0,100}\s\-t\saxfr\s\>/ nocase ascii wide
        // Description: Automate recon for red team assessments.
        // Reference: https://github.com/r1cksec/thoth
        $string2 = /\s\-d\s.{0,100}\s\-t\szonewalk\s\>\s/ nocase ascii wide
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
        $string11 = /\sintel\s\-d\s.{0,100}\s\-whois/ nocase ascii wide
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
        $string40 = /massdns\s\-r\s.{0,100}\.txt/ nocase ascii wide
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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

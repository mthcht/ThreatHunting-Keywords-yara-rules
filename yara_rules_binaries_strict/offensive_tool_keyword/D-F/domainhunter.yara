rule domainhunter
{
    meta:
        description = "Detection patterns for the tool 'domainhunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domainhunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string1 = " domainhunter " nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string2 = /\s\-\-keyword\s.{0,100}\s\-\-check\s\-\-ocr\s.{0,100}\s\-\-alexa/ nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string3 = "/domainhunter" nocase ascii wide
        // Description: Domain name selection is an important aspect of preparation for penetration tests and especially Red Team engagements. Commonly. domains that were used previously for benign purposes and were properly categorized can be purchased for only a few dollars. Such domains can allow a team to bypass reputation based web filters and network egress restrictions for phishing and C2 related tasks.This Python based tool was written to quickly query the Expireddomains.net search engine for expired/available domains with a previous history of use. It then optionally queries for domain reputation against services like Symantec Site Review (BlueCoat). IBM X-Force. and Cisco Talos. The primary tool output is a timestamped HTML table style report.
        // Reference: https://github.com/threatexpress/domainhunter
        $string4 = "domainhunter" nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string5 = /domainhunter\.py/ nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string6 = "downloadMalwareDomains" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}

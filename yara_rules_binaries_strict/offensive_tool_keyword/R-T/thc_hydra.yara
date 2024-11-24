rule thc_hydra
{
    meta:
        description = "Detection patterns for the tool 'thc-hydra' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thc-hydra"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string1 = /\sdefault_logins\.txt/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string2 = " thc-hidra" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string3 = /\.\/hydra\s/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string4 = /\.\/xhydra/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string5 = "/hydra -" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string6 = "/thc-hydra/" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string7 = /common_passwords\.txt/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string8 = "dpl4hydra " nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string9 = /dpl4hydra\.sh/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string10 = /dpl4hydra_.{0,100}\.csv/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string11 = /dpl4hydra_.{0,100}\.tmp/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string12 = "dpl4hydra_linksys" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string13 = /hydra\s.{0,100}\sftp\:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string14 = /hydra\s.{0,100}\shttp\-post\-form\s/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string15 = /hydra\s.{0,100}\smysql\:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string16 = /hydra\s.{0,100}\sssh\:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string17 = /hydra\s.{0,100}\stelnet\:\/\// nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string18 = "hydra smtp-enum" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string19 = "hydra:x:10001:" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string20 = "HYDRA_PROXY_HTTP" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string21 = "hydra-cobaltstrike" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string22 = "install hydra-gtk" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string23 = "pw-inspector -" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string24 = /pw\-inspector\./ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string25 = "thc-hydra" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string26 = /thc\-hydra\.git/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string27 = /thc\-hydra\.git/ nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string28 = "vanhauser-thc/thc-hydra" nocase ascii wide
        // Description: Parallelized login cracker which supports numerous protocols to attack.
        // Reference: https://github.com/vanhauser-thc/thc-hydra
        $string29 = "hydra -" nocase ascii wide
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

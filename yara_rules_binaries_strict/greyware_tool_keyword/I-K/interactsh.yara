rule interactsh
{
    meta:
        description = "Detection patterns for the tool 'interactsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "interactsh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C4
        // Reference: https://github.com/projectdiscovery/interactsh
        $string1 = /\.exec.{0,100}\.interact\.sh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C7
        // Reference: https://github.com/projectdiscovery/interactsh
        $string2 = /\.interactsh\.com/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C5
        // Reference: https://github.com/projectdiscovery/interactsh
        $string3 = "/interactsh/" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C6
        // Reference: https://github.com/projectdiscovery/interactsh
        $string4 = "/interactsh-client" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C15
        // Reference: https://github.com/projectdiscovery/interactsh
        $string5 = "/interactsh-collaborator" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C8
        // Reference: https://github.com/projectdiscovery/interactsh
        $string6 = "/interactsh-server" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C3
        // Reference: https://github.com/projectdiscovery/interactsh
        $string7 = /curl.{0,100}\.interact\.sh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C4
        // Reference: https://github.com/projectdiscovery/interactsh
        $string8 = /http\:\/\/.{0,100}\.interact\.sh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C10
        // Reference: https://github.com/projectdiscovery/interactsh
        $string9 = "interactsh -" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C9
        // Reference: https://github.com/projectdiscovery/interactsh
        $string10 = /interactsh.{0,100}\.exe/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C14
        // Reference: https://github.com/projectdiscovery/interactsh
        $string11 = /interactsh.{0,100}oast\./ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C11
        // Reference: https://github.com/projectdiscovery/interactsh
        $string12 = "interactsh-client -" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C13
        // Reference: https://github.com/projectdiscovery/interactsh
        $string13 = "interactsh-server -" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C12
        // Reference: https://github.com/projectdiscovery/interactsh
        $string14 = "projectdiscovery/interactsh" nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C2
        // Reference: https://github.com/projectdiscovery/interactsh
        $string15 = /wget.{0,100}\.interact\.sh/ nocase ascii wide
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

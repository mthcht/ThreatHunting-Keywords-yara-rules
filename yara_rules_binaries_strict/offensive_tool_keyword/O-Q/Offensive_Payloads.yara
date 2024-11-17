rule Offensive_Payloads
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string1 = /Cross\-Site\-Scripting\-XSS\-Payloads/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string2 = /Directory\-Traversal\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string3 = /File\-Extensions\-Wordlist\.txt/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string4 = /Html\-Injection\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string5 = /Html\-Injection\-Read\-File\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string6 = /OS\-Command\-Injection\-Unix\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string7 = /OS\-Command\-Injection\-Windows\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string8 = /PHP\-Code\-injection\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string9 = /PHP\-Code\-Injections\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string10 = /Server\-Side\-Request\-Forgery\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string11 = /SQL\-Injection\-Auth\-Bypass\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string12 = /SQL\-Injection\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string13 = /XML\-External\-Entity\-\(XXE\)\-Payloads/ nocase ascii wide
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

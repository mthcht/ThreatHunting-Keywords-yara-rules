rule Github_Username
{
    meta:
        description = "Detection patterns for the tool 'Github Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github Username"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: github Penetration tester repo hosting malicious code
        // Reference: https://github.com/attackercan/
        $string1 = "/attackercan/" nocase ascii wide
        // Description: Github username of known powershell offensive modules and scripts
        // Reference: https://github.com/Ben0xA
        $string2 = "/Ben0xA/" nocase ascii wide
        // Description: Open source testing tools for the SDR & security community
        // Reference: https://github.com/BastilleResearch
        $string3 = "BastilleResearch" nocase ascii wide
        // Description: Cybersecurity Engineers and Offensive Security enthusiasts actively maintaining/updating Powershell Empire in our spare time.
        // Reference: https://github.com/BC-SECURITY
        $string4 = "BC-SECURITY" nocase ascii wide
        // Description: Welcome to the Infection Monkey! The Infection Monkey is an open source security tool for testing a data centers resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server
        // Reference: https://github.com/h0nus
        $string5 = /guardicore.{0,100}monkey/ nocase ascii wide
        // Description: s7scan is a tool that scans networks. enumerates Siemens PLCs and gathers basic information about them. such as PLC firmware and hardwaare version. network configuration and security parameters. It is completely written on Python.
        // Reference: https://github.com/klsecservices/s7scan
        $string6 = "s7scan" nocase ascii wide
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

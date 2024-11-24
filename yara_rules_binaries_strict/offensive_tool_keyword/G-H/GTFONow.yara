rule GTFONow
{
    meta:
        description = "Detection patterns for the tool 'GTFONow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GTFONow"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string1 = /\sgtfobin_update\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string2 = /\sgtfonow\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string3 = /\slibpwn\.c/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string4 = /\slibpwn\.so/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string5 = /\stest_privesc\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string6 = /\/gtfobin_update\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string7 = /\/gtfonow\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string8 = "/home/lowpriv/" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string9 = /\/test_privesc\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string10 = /\/tmp\/gtfokey\.pub/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string11 = /\/tmp\/libpwn\.c/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string12 = /\/tmp\/libpwn\.so/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string13 = /\[\!\]\sFound\sexploitable\ssgid\sbinary/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string14 = /\[\!\]\sFound\sexploitable\sSudo\sNOPASSWD\sbinary/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string15 = /\[\!\]\sFound\sexploitable\ssuid\sbinary/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string16 = /\[\+\]\sSpawning\sroot\sshell/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string17 = /\\gtfonow\.py/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string18 = "1b220d5538e63244c3b81a0c7a83ebb9ac7b0cdaed9f3e84057a812d7192b9b2" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string19 = "7c8dcea2da2cd78b706f7e08ff49f7733008ce357fba21777d17334abf0458a6" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string20 = /check_sudo_nopasswd_binaries\(/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string21 = /cron_priv_esc\(payload/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string22 = "db62ef03d6be4778d3ec0fd2f6cb2cf030f02a70efa1f30850b27e0cefd50e9e" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string23 = /display_privilege_escalation_options\(/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string24 = /execute_payload\(priv_esc/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string25 = "Frissi0n/GTFONow" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string26 = /from\sgtfonow\./ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string27 = "getcap not found in PATH, cannot escalate using capabilities" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string28 = /gtfonow\.py\s\-a/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string29 = /is_binary_in_gtfobins\(/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string30 = /perform_privilege_escalation_checks\(/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string31 = /ssh_key_privesc\(payload/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string32 = /ssh_write_privesc\(payload/ nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string33 = "ssh-keygen not found in PATH, cannot escalate using SSH key" nocase ascii wide
        // Description: Automatic privilege escalation for misconfigured capabilities - sudo and suid binaries using GTFOBins.
        // Reference: https://github.com/Frissi0n/GTFONow
        $string34 = "Thanks for using GTFONow!" nocase ascii wide
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

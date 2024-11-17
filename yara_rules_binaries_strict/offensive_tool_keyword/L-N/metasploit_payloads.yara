rule metasploit_payloads
{
    meta:
        description = "Detection patterns for the tool 'metasploit-payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metasploit-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string1 = /\/credentials\/enum_cred_store/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string2 = /\/credentials\/enum_laps/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string3 = /\/gather\/phish_windows_credentials/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string4 = /\/local_exploit_suggester/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string5 = /capture\/lockout_keylogger/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string6 = /enum_ad_service_principal_names\s/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string7 = /escalate\/golden_ticket/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string8 = /escalate\/unmarshal_cmd_exec/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string9 = /gather\/credentials\/rdc_manager_creds/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string10 = /gather\/credentials\/teamviewer_passwords/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string11 = /gather\/credentials\/windows_autologin/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string12 = /gather\/enum_ad_bitlocker/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string13 = /gather\/enum_ad_computers/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string14 = /gather\/enum_ad_groups/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string15 = /gather\/enum_ad_managedby_groups/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string16 = /gather\/enum_ad_to_wordlist/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string17 = /gather\/enum_ad_user_comments/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string18 = /gather\/enum_logged_on_users/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string19 = /gather\/enum_logged_on_users/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string20 = /gather\/enum_putty_saved_sessions/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string21 = /manage\/reflective_dll_inject/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string22 = /metterpreter/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string23 = /sniffer_dump\s.{0,100}\/tmp\/.{0,100}\.pcap/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string24 = /windows\/gather\/cachedump/ nocase ascii wide
        // Description: shell payload
        // Reference: https://github.com/rapid7/metasploit-payloads
        $string25 = /windows\/gather\/hashdump/ nocase ascii wide
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

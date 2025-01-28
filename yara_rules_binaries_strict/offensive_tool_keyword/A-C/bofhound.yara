rule bofhound
{
    meta:
        description = "Detection patterns for the tool 'bofhound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bofhound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string1 = " Brc4LdapSentinelParser" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string2 = " --brute-ratel" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string3 = /\/beacon_202_no_acl\.log/
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string4 = /\/beacon_257\-objects\.log/
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string5 = /\/bloodhound_domain\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string6 = /\/bloodhound_domaintrust\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string7 = /\/bloodhound_gpo\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string8 = /\/bloodhound_object\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string9 = /\/bloodhound_ou\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string10 = /\/bloodhound_schema\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string11 = /\/bofhound\.git/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string12 = /\/ldap_search_bof\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string13 = "/opt/cobaltstrike/logs"
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string14 = /\\ldap_search_bof\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string15 = /badger_no_acl_1030_objects\.log/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string16 = "bofhound --" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string17 = "bofhound -i " nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string18 = "bofhound -o " nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string19 = "bofhound-main" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string20 = /brc4_ldap_sentinel\.py/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string21 = "fortalice/bofhound" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string22 = "from bofhound import " nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string23 = /from\sbofhound\.ad\simport/ nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string24 = "import LdapSearchBofParser" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string25 = "pip3 install bofhound" nocase ascii wide
        // Description: Generate BloodHound compatible JSON from logs written by ldapsearch BOF - pyldapsearch and Brute Ratel's LDAP Sentinel
        // Reference: https://github.com/fortalice/bofhound
        $string26 = "poetry run bofhound" nocase ascii wide
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

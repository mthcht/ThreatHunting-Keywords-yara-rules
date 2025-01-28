rule remote_method_guesser
{
    meta:
        description = "Detection patterns for the tool 'remote-method-guesser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remote-method-guesser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string1 = /\senum\s127\.0\.0\.1\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string2 = /\/remote\-method\-guesser\.git/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string3 = /\/tmp\/wordlist\.txt/
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string4 = /0\.0\.0\.0\:4444/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string5 = /0\.0\.0\.0\:4445/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string6 = /docker\sbuild\s\-t\srmg\s\./ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string7 = /jdk.{0,100}\-activator\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string8 = /jdk.{0,100}\-call\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string9 = /jdk.{0,100}\-dgc\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string10 = /jdk.{0,100}\-method\-rce\-test\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string11 = /jdk.{0,100}\-reg\-bypass\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string12 = "nc -vlp 4444" nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string13 = "nc -vlp 4445" nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string14 = "qtc-de/remote-method-guesser" nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string15 = "remote-method-guesser/rmg" nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string16 = "remote-method-guesser-master" nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string17 = /rmg\sbind\s.{0,100}\sjmxrmi\s\-\-bind\-objid\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string18 = /rmg\sbind\s.{0,100}127\.0\.0\.1\:.{0,100}\-\-localhost\-bypass/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string19 = /rmg\scall\s.{0,100}\s\-\-plugin\sGenericPrint\.jar/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string20 = /rmg\scall\s.{0,100}\s\-\-signature\s.{0,100}\s\-\-bound\-name\splain\-server/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string21 = /rmg\scodebase\s.{0,100}http.{0,100}\s\-\-component\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string22 = /rmg\scodebase\s.{0,100}java\.util\.HashMap\s.{0,100}\-\-bound\-name\slegacy\-service/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string23 = "rmg enum " nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string24 = /rmg\sguess\s.{0,100}\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string25 = /rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string26 = /rmg\slisten\s.{0,100}\sCommonsCollections/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string27 = /rmg\slisten\s0\.0\.0\.0\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string28 = /rmg\sobjid\s.{0,100}\[/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string29 = "rmg roguejmx " nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string30 = "rmg scan " nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string31 = /rmg\sscan\s.{0,100}\s\-\-ports\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string32 = /rmg\sserial\s.{0,100}\sAnTrinh\s.{0,100}\s\-\-component\s/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string33 = /rmg\sserial\s.{0,100}CommonsCollections/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string34 = /rmg\-.{0,100}\-jar\-with\-dependencies\.jar/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string35 = /rmg.{0,100}\-\-yso/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string36 = "--ssrf --gopher --encode --scan-action filter-bypass" nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string37 = /wordlists.{0,100}rmg\.txt/ nocase ascii wide
        // Description: remote-method-guesser?(rmg) is a?Java RMI?vulnerability scanner and can be used to identify and verify common security vulnerabilities on?Java RMI?endpoints.
        // Reference: https://github.com/qtc-de/remote-method-guesser
        $string38 = /wordlists.{0,100}rmiscout\.txt/ nocase ascii wide
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

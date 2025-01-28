rule ruler
{
    meta:
        description = "Detection patterns for the tool 'ruler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string1 = /\sBruteForce\(/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string2 = " --insecure brute --userpass " nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string3 = " --insecure brute --users " nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string4 = /\sropbuffers\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string5 = /\sruler\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string6 = "\"WorkstationName\">RULER</Data>" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string7 = "/http-ntlm/ntlmtransport" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string8 = /\/ntlmtransport\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string9 = /\/ropbuffers\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string10 = "/ruler --domain " nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string11 = "/ruler --email " nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string12 = "/ruler --url" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string13 = /\/rulerforms\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string14 = /\\autodiscover\\brute\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string15 = /\\ruler\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string16 = "021ae50ec89266dabb1f96f703ec04dad908eef0e63d12c1ed38a40833198f79" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string17 = "42e504f3d9d9800c1c75ff6d8c5433d801e7148760cba709fa3bd5dd8e4a0208" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string18 = "904b042e2ec7aa85331911b1343213292e061dcc4f2010d01f4f7b60f0198b10" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string19 = "9567021fc5536372a9fb4eea5594d2665e676e88444cd2a017027513662fff18" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string20 = /autodiscover\/brute\.go/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string21 = /CreateStringPayload\(\\"RULER\\"\)/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string22 = "f3b5e0f54f1da134c5d3c135f5be8ae7e85e499e8e73fabf87ffe010c23749ef" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string23 = "f3e108c7993b8d46c832ac2499a97395cc18fc9c4c1656acc25c969c7090ffcd" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string24 = /http\:\/\/212\.111\.43\.206\:9090\/pk\.html/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string25 = "ruler --insecure " nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string26 = "ruler-linux64"
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string27 = "ruler-linux86"
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string28 = "ruler-osx64" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string29 = /ruler\-win64\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string30 = /ruler\-win86\.exe/ nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string31 = "sensepost/ruler" nocase ascii wide
        // Description: A tool to abuse Exchange services
        // Reference: https://github.com/sensepost/ruler
        $string32 = "UserPassBruteForce" nocase ascii wide
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

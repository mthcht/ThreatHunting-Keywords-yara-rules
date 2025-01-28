rule Pyramid
{
    meta:
        description = "Detection patterns for the tool 'Pyramid' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pyramid"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string1 = /\s\-generate\s\-server\s.{0,100}\s\-setcradle\sbh\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string2 = /\s\-generate\s\-setcradle\spythonmemorymodule\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string3 = /\sLaZagne\.py\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string4 = /\spyramid\.py\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string5 = /\stunnel\-socks5\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string6 = /\.\\\\pipe\\\\mimikatz/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string7 = /\/_distutils_hack\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string8 = /\/DonPAPI\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string9 = /\/impacket\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string10 = /\/itsdangerous\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string11 = /\/LaZagne\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string12 = /\/lazagne\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string13 = /\/minidump\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string14 = /\/Pyramid\.git/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string15 = /\/pyramid\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string16 = /\/pythonmemorymodule\.py/
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string17 = /\/tunnel\-socks5\.py/
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string18 = /\@WanaDecryptor\@\.exe/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string19 = /\[\+\]\sAuto\-generating\sPyramid\sconfig\sfor\smodules\sand\sagents/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string20 = /\[\+\]\sMIND\sYOUR\sOPSEC\!\sServing\sPyramid\sfiles\sfrom\sfolder\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string21 = /\[\+\]\sprinting\sb64encoded\(zipped\(cradle\.py\)\)\sfor\sscriptless\sexecution\son\sterminal\:/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string22 = /\[\+\]\sPyramid\sHTTP\sServer\slistening\son\sport\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string23 = /\\\\\.\\\\pipe\\\\blindspot\-/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string24 = /\\bin\\uactoken\.x86\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string25 = /\\bin\\uactoken2\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string26 = /\\bin\\wmiexec\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string27 = /\\DECRYPT\-FILES\.txt/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string28 = /\\Development\\GOLD\-BACKDOOR\\/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string29 = /\\impacket\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string30 = /\\itsdangerous\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string31 = /\\LaZagne\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string32 = /\\lazagne\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string33 = /\\netview\.x64\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string34 = /\\pxlib\\bin\\wmiexec\.x86\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string35 = /\\pyramid\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string36 = /\\tunnel\-socks5\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string37 = /\\users\\public\\desktop\\Fix\-Your\-Files\.txt/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string38 = "6f83bb55a9762c656e90c49fd505ba79414edf22a89a4029f96a6ff784716e29" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string39 = "816bac589fcdd14efd90df8fecfadd0b1908dcd18a3617ef9f64170fee14ad5c" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string40 = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string41 = /bin\\psexec_command\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string42 = "c518104a683209a63029169a1a69e839cf0a7baf26f29bf1fcc96e6c4f776245" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string43 = "ddacbf2fc85fd85cdbe8016b19f2f783acb17dbaf6361e9827039885d382e8d2" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string44 = /hashdump\.x64\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string45 = /HOW_TO_DECYPHER_FILES\.txt/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string46 = /KeePassHax\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string47 = /keylogger\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string48 = /keylogger\.x64\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string49 = /ldapdomaindump\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string50 = /mimikatz\.log/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string51 = /minikerberos\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string52 = "naksyn/Pyramid" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string53 = /pxlib\\bin\\kerberos\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string54 = /pypykatz\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string55 = /Pyramid\-main\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string56 = /Release\-ReflectiveDLL\\Implant\.x64\.pdb/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string57 = /secretsdump\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string58 = /Serve\sPyramid\sfiles\sover\sHTTP\/S\sand\sprovide\sbasic\sauthentication\./ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string59 = /timestomp\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string60 = "User-Agent: pproxy-" nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string61 = /webinject64\.dll/ nocase ascii wide
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

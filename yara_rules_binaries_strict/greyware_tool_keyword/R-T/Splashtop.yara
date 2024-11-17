rule Splashtop
{
    meta:
        description = "Detection patterns for the tool 'Splashtop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Splashtop"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string1 = /\.api\.splashtop\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string2 = /\.relay\.splashtop\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string3 = /\/Library\/Logs\/SPLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string4 = /\/SplashtopStreamer\/SPLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string5 = /\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string6 = /\\Splashtop\sRemote\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string7 = /\\Splashtop\\Temp\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string8 = /\\Splashtop\\Temp\\log\\FTCLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string9 = /\\SRService\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string10 = /\\strwinclt\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string11 = /\\WOW6432Node\\Splashtop\sInc\.\\Splashtop\sRemote\sServer/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string12 = /CurrentVersion\\Uninstall\\Splashtop\sInc\.\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string13 = /Program\sFiles\s\(x86\)\\Splashtop/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string14 = /Software\\Splashtop\sInc\.\\Splashtop/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string15 = /Splashtop\sRemote\\Server\\log\\agent_log\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string16 = /Splashtop\sRemote\\Server\\log\\SPLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string17 = /Splashtop\sRemote\\Server\\log\\svcinfo\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string18 = /Splashtop\sRemote\\Server\\log\\sysinfo\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string19 = /Splashtop_Streamer_Windows_.{0,100}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string20 = /Splashtop\-Splashtop\sStreamer\-/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string21 = /SplashtopStreamer\..{0,100}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string22 = /SplashtopStreamer3500\.exe.{0,100}\sprevercheck\s/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string23 = /www\.splashtop\.com\/remotecaRemoveVRootsISCHECKFORPRODUCTUPDATES/ nocase ascii wide
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

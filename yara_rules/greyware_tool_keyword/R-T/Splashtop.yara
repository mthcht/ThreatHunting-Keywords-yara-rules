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
        $string3 = /\/Library\/Logs\/SPLog\.txt/
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string4 = /\/SplashtopStreamer\/SPLog\.txt/
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
        $string19 = /Splashtop_Streamer_Windows_.{0,1000}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string20 = "Splashtop-Splashtop Streamer-" nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string21 = /SplashtopStreamer\..{0,1000}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string22 = /SplashtopStreamer3500\.exe.{0,1000}\sprevercheck\s/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string23 = /www\.splashtop\.com\/remotecaRemoveVRootsISCHECKFORPRODUCTUPDATES/ nocase ascii wide

    condition:
        any of them
}

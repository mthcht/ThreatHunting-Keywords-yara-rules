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
        $string2 = /\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string3 = /CurrentVersion\\Uninstall\\Splashtop\sInc\.\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string4 = /Software\\Splashtop\sInc\.\\Splashtop/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string5 = /Splashtop_Streamer_Windows_.{0,1000}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string6 = /Splashtop\-Splashtop\sStreamer\-/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string7 = /SplashtopStreamer3500\.exe.{0,1000}\sprevercheck\s/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string8 = /www\.splashtop\.com\/remotecaRemoveVRootsISCHECKFORPRODUCTUPDATES/ nocase ascii wide

    condition:
        any of them
}

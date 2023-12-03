rule MalSCCM
{
    meta:
        description = "Detection patterns for the tool 'MalSCCM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MalSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string1 = /.{0,1000}\.exe\sapp\s\/create\s\/name:.{0,1000}\s\/uncpath:.{0,1000}\\\\.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string2 = /.{0,1000}\.exe\sapp\s\/deploy\s\/name:.{0,1000}\s\/groupname:.{0,1000}\s\/assignmentname:.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string3 = /.{0,1000}\/MalSCCM\.git.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string4 = /.{0,1000}\/MalSCCM\.sln.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string5 = /.{0,1000}5439CECD\-3BB3\-4807\-B33F\-E4C299B71CA2.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string6 = /.{0,1000}Action:\sLocating\sSCCM\sManagement\sServers.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string7 = /.{0,1000}Action:\sLocating\sSCCM\sServers\sin\sRegistry.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string8 = /.{0,1000}MalSCCM\.exe.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string9 = /.{0,1000}MalSCCM\-main.{0,1000}/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string10 = /.{0,1000}nettitude\/MalSCCM.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

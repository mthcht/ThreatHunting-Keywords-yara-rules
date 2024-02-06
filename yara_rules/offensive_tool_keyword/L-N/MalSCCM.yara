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
        $string1 = /\.exe\sapp\s\/create\s\/name\:.{0,1000}\s\/uncpath\:.{0,1000}\\\\/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string2 = /\.exe\sapp\s\/deploy\s\/name\:.{0,1000}\s\/groupname\:.{0,1000}\s\/assignmentname\:/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string3 = /\/MalSCCM\.git/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string4 = /\/MalSCCM\.sln/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string5 = /5439CECD\-3BB3\-4807\-B33F\-E4C299B71CA2/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string6 = /Action\:\sLocating\sSCCM\sManagement\sServers/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string7 = /Action\:\sLocating\sSCCM\sServers\sin\sRegistry/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string8 = /MalSCCM\.exe/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string9 = /MalSCCM\-main/ nocase ascii wide
        // Description: This tool allows you to abuse local or remote SCCM servers to deploy malicious applications to hosts they manage
        // Reference: https://github.com/nettitude/MalSCCM
        $string10 = /nettitude\/MalSCCM/ nocase ascii wide

    condition:
        any of them
}

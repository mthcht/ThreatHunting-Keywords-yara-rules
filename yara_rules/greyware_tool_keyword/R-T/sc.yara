rule sc
{
    meta:
        description = "Detection patterns for the tool 'sc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get information about Windows Defender service
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1 = /\s\/c\ssc\squery\sWinDefend/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string2 = /echo\sstart\s\>\s\\\\\.\\pipe\\winreg/ nocase ascii wide
        // Description: create service with netcat
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string3 = /sc\screate\s.*nc\.exe\s\-.*cmd\.exe/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string4 = /sc\sqtriggerinfo\sRemoteRegistry/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string5 = /sc\sstart\sRemoteRegistry/ nocase ascii wide

    condition:
        any of them
}
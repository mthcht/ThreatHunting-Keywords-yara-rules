rule VirusTotalC2
{
    meta:
        description = "Detection patterns for the tool 'VirusTotalC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirusTotalC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abusing VirusTotal API to host our C2 traffic. usefull for bypassing blocking firewall rules if VirusTotal is in the target white list and in case you don't have C2 infrastructure. now you have a free one
        // Reference: https://github.com/RATandC2/VirusTotalC2
        $string1 = /\/VirusTotalC2\// nocase ascii wide
        // Description: Abusing VirusTotal API to host our C2 traffic. usefull for bypassing blocking firewall rules if VirusTotal is in the target white list and in case you don't have C2 infrastructure. now you have a free one
        // Reference: https://github.com/RATandC2/VirusTotalC2
        $string2 = /Implant.{0,1000}TeamServer\.exe/ nocase ascii wide
        // Description: Abusing VirusTotal API to host our C2 traffic. usefull for bypassing blocking firewall rules if VirusTotal is in the target white list and in case you don't have C2 infrastructure. now you have a free one
        // Reference: https://github.com/RATandC2/VirusTotalC2
        $string3 = /VirusTotalC2\./ nocase ascii wide

    condition:
        any of them
}

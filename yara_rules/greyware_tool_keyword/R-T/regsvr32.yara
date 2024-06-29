rule regsvr32
{
    meta:
        description = "Detection patterns for the tool 'regsvr32' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regsvr32"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious service creation executing a desktop.ini file observed in a malware sample
        // Reference: https://www.virustotal.com/gui/file/faca8b6f046dad8f0e27a75fa2dc5477d3ccf44adced64481ef1b0dd968b4b0e/behavior
        $string1 = /cmd\s\/c\sregsvr32\.exe\s\/s\sC\:\\.{0,1000}\\desktop\.ini\"\sstart\=\sauto/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string2 = /regsvr32\sAmsiProvider\.dll/ nocase ascii wide
        // Description: suspicious service creation executing a desktop.ini file observed in a malware sample
        // Reference: https://www.virustotal.com/gui/file/faca8b6f046dad8f0e27a75fa2dc5477d3ccf44adced64481ef1b0dd968b4b0e/behavior
        $string3 = /sc\screate\s.{0,1000}cmd\s\/c\sregsvr32\.exe\s\/s\s.{0,1000}\\desktop\.ini/ nocase ascii wide

    condition:
        any of them
}

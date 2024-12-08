rule Powertool
{
    meta:
        description = "Detection patterns for the tool 'Powertool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powertool"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string1 = /\\PowerTool\.exe/ nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string2 = /\\PowerTool32\.exe/ nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string3 = /\\PowerTool64\.exe/ nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string4 = "094d1476331d6f693f1d546b53f1c1a42863e6cde014e2ed655f3cbe63e5ecde" nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string5 = "611db45c564ffb1b67a85b2249f30e5a95f2b7ab2ceec403cb22555a708c61d9" nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string6 = "Chage language nedd to restart PowerTool" nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string7 = "d321ce59062c8d96dacdfe13e84d1543a296c432291dd4488d79f6b94a565923" nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string8 = "Detection may be stuck, First confirm whether the device hijack in " nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string9 = /d\-h\.st\/users\/powertool/ nocase ascii wide
        // Description: tool abused by threat actors to desactive Antivirus
        // Reference: https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml
        $string10 = /whether\sto\sdownload\sthe\s64bit\sversion\sof\sPowerTool\?/ nocase ascii wide

    condition:
        any of them
}

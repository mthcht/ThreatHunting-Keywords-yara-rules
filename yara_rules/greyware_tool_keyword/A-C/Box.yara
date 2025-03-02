rule Box
{
    meta:
        description = "Detection patterns for the tool 'Box' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Box"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string1 = /\.realtime\.services\.box\.net/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string2 = /\/BoxDrive\.msi/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string3 = /\\\.boxcanvas\\BoxDesktop/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string4 = /\\box\.desktop\.updateservice\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string5 = /\\Box\.Updater\.Common\.dll/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string6 = /\\box\\box\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string7 = /\\Box\\ui\\BoxUI\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string8 = /\\BoxDesktop\.boxnote\\shell\\/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string9 = /\\BoxDrive\.msi/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string10 = /\\Program\sFiles\\Box\\Box\\/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string11 = /\\Root\\InventoryApplicationFile\\boxui\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string12 = /\>Box\,\sInc\.\</ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string13 = /Box\.Desktop\.Installer\.CustomActions/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string14 = /cdn.{0,1000}\.boxcdn\.net/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string15 = /HKLM\\SOFTWARE\\Box\\Box/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string16 = /sanalytics\.box\.com/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string17 = /upload\.box\.com/ nocase ascii wide

    condition:
        any of them
}

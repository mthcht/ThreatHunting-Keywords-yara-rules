rule processhacker
{
    meta:
        description = "Detection patterns for the tool 'processhacker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "processhacker"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string1 = /.{0,1000}\/processhacker\-.{0,1000}\-bin\.zip.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string2 = /.{0,1000}\/processhacker\/files\/latest\/download.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string3 = /.{0,1000}\\Process\sHacker\s2\\.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string4 = /.{0,1000}processhacker\-.{0,1000}\-sdk\.zip.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string5 = /.{0,1000}processhacker\-.{0,1000}\-setup\.exe.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string6 = /.{0,1000}processhacker\-.{0,1000}\-src\.zip.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string7 = /.{0,1000}ProcessHacker\.exe.{0,1000}/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string8 = /.{0,1000}ProcessHacker\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

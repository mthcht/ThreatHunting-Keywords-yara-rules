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
        $string1 = /\/processhacker\-.{0,1000}\-bin\.zip/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string2 = /\/processhacker\/files\/latest\/download/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string3 = /\\Process\sHacker\s2\\/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string4 = /processhacker\-.{0,1000}\-sdk\.zip/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string5 = /processhacker\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string6 = /processhacker\-.{0,1000}\-src\.zip/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string7 = /ProcessHacker\.exe/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string8 = /ProcessHacker\.sln/ nocase ascii wide

    condition:
        any of them
}

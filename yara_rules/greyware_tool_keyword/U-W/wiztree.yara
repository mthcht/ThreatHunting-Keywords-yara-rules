rule wiztree
{
    meta:
        description = "Detection patterns for the tool 'wiztree' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiztree"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: legitimate tool abused by threat actors to obtain network files and directory listings
        // Reference: N/A
        $string1 = /\\Program\sFiles\\WizTree/ nocase ascii wide
        // Description: legitimate tool abused by threat actors to obtain network files and directory listings
        // Reference: N/A
        $string2 = /\\Temp\\WizTree\.exe/ nocase ascii wide
        // Description: legitimate tool abused by threat actors to obtain network files and directory listings
        // Reference: N/A
        $string3 = /\\WizTree\.exe/ nocase ascii wide
        // Description: legitimate tool abused by threat actors to obtain network files and directory listings
        // Reference: N/A
        $string4 = /\\wiztree_.{0,1000}_portable\.zip.{0,1000}	/ nocase ascii wide
        // Description: legitimate tool abused by threat actors to obtain network files and directory listings
        // Reference: N/A
        $string5 = /http\:\/\/antibody\-software\.com\/files\/wiztreeversion\.php/ nocase ascii wide
        // Description: legitimate tool abused by threat actors to obtain network files and directory listings
        // Reference: N/A
        $string6 = "WizTreeMutex" nocase ascii wide

    condition:
        any of them
}

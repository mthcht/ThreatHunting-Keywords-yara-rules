rule BOINC
{
    meta:
        description = "Detection patterns for the tool 'BOINC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOINC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fake BOINC software distributed by discord - mars stealer
        // Reference: https://cyberint.com/wp-content/uploads/2022/02/Mars-Stealer-7.png.webp
        $string1 = /discordapp\.com\/attachments\/.{0,1000}\/BOINCPortable_.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}

rule Harvester_OF_SORROW
{
    meta:
        description = "Detection patterns for the tool 'Harvester_OF_SORROW' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Harvester_OF_SORROW"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The payload opens firefox about:logins and tabs and arrows its way through options. It then takes a screen shot with the first set of log in credentials made visible. Finally it sends the screenshot  to an email of your choosing.
        // Reference: https://github.com/hak5/omg-payloads/blob/master/payloads/library/credentials/Harvester_OF_SORROW/payload.txt
        $string1 = /\sPictures\\Screenshots\\loot\.zip/ nocase ascii wide
        // Description: The payload opens firefox about:logins and tabs and arrows its way through options. It then takes a screen shot with the first set of log in credentials made visible. Finally it sends the screenshot  to an email of your choosing.
        // Reference: https://github.com/hak5/omg-payloads/blob/master/payloads/library/credentials/Harvester_OF_SORROW/payload.txt
        $string2 = /REM\sTitle\:\sHarvester_OF_SORROW/ nocase ascii wide
        // Description: The payload opens firefox about:logins and tabs and arrows its way through options. It then takes a screen shot with the first set of log in credentials made visible. Finally it sends the screenshot  to an email of your choosing.
        // Reference: https://github.com/hak5/omg-payloads/blob/master/payloads/library/credentials/Harvester_OF_SORROW/payload.txt
        $string3 = /STRING\sfirefox\sabout\:logins/ nocase ascii wide

    condition:
        any of them
}

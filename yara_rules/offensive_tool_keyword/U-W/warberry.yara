rule warberry
{
    meta:
        description = "Detection patterns for the tool 'warberry' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "warberry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WarBerryPi is a RaspberryPi based hardware implant that has the ability to go on stealth mode when used in acuiring informational data from a target network. especially useful during read teaming engagements. Its designed with a special feature that allows it to get the needed information within the shortest time possible. WarBerryPis scripts are designed in such way to avoid noise in the network as much as possible.
        // Reference: https://github.com/secgroundzero/warberry
        $string1 = /warberry/ nocase ascii wide

    condition:
        any of them
}

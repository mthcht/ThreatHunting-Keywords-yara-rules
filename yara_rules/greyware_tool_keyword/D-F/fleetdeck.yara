rule fleetdeck
{
    meta:
        description = "Detection patterns for the tool 'fleetdeck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fleetdeck"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: FleetDeck is a Remote Desktop & Virtual Terminal solution tailored for techs to  manage large fleets of computers
        // Reference: https://fleetdeck.io/
        $string1 = /agent\.fleetdeck\.io\/.{0,1000}\?win/ nocase ascii wide

    condition:
        any of them
}

rule nipe
{
    meta:
        description = "Detection patterns for the tool 'nipe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nipe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An engine to make Tor Network your default gateway.
        // Reference: https://github.com/htrgouvea/nipe
        $string1 = /.{0,1000}\/nipe\.git/ nocase ascii wide
        // Description: An engine to make Tor Network your default gateway.
        // Reference: https://github.com/htrgouvea/nipe
        $string2 = /.{0,1000}\/nipe\.pl/ nocase ascii wide
        // Description: An engine to make Tor Network your default gateway.
        // Reference: https://github.com/htrgouvea/nipe
        $string3 = /.{0,1000}htrgouvea\/nipe.{0,1000}/ nocase ascii wide
        // Description: An engine to make Tor network your default gateway. Tor enables users to surf the internet. chat and send instant messages anonymously.  and is used by a wide variety of people for both licit and illicit purposes. Tor has. for example. been used by criminals enterprises. hacktivism groups. and law enforcement  agencies at cross purposes. sometimes simultaneously. Nipe is a script to make the Tor network your default gateway.This Perl script enables you to directly route all your traffic from your computer to the Tor network through which you can surf the internet anonymously without having to worry about being tracked or traced back.
        // Reference: https://github.com/htrgouvea/nipe
        $string4 = /.{0,1000}nipe\.pl\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

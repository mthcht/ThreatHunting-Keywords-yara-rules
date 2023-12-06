rule jackit
{
    meta:
        description = "Detection patterns for the tool 'jackit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jackit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Wireless Mouse and Keyboard Vulnerability This is a partial implementation of Bastilles MouseJack exploit. See mousejack.com for more details. Full credit goes to Bastilles team for discovering this issue and writing the libraries to work with the CrazyRadio PA dongle. Also. thanks to Samy Kamkar for KeySweeper. to Thorsten Schroeder and Max Moser for their work on KeyKeriki and to Travis Goodspeed. We stand on the shoulders of giants
        // Reference: https://github.com/insecurityofthings/jackit
        $string1 = /\/jackit/ nocase ascii wide
        // Description: This is a partial implementation of Bastilles MouseJack exploit. See mousejack.com for more details. Full credit goes to Bastilles team for discovering this issue and writing the libraries to work with the CrazyRadio PA dongle. Also. thanks to Samy Kamkar for KeySweeper. to Thorsten Schroeder and Max Moser for their work on KeyKeriki and to Travis Goodspeed. We stand on the shoulders of giants.
        // Reference: https://github.com/insecurityofthings/jackit
        $string2 = /insecurityofthings.{0,1000}jackit/ nocase ascii wide

    condition:
        any of them
}

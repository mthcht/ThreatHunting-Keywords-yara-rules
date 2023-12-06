rule PowerUpSQL
{
    meta:
        description = "Detection patterns for the tool 'PowerUpSQL' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerUpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerUpSQL includes functions that support SQL Server discovery. weak configuration auditing. privilege escalation on scale. and post exploitation actions such as OS command execution. It is intended to be used during internal penetration tests and red team engagements. However. PowerUpSQL also includes many functions that can be used by administrators to quickly inventory the SQL Servers in their ADS domain and perform common threat hunting tasks related to SQL Server.
        // Reference: https://github.com/NetSPI/PowerUpSQL
        $string1 = /PowerUpSQL/ nocase ascii wide

    condition:
        any of them
}

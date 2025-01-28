rule RegHiveBackup
{
    meta:
        description = "Detection patterns for the tool 'RegHiveBackup' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RegHiveBackup"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: backup the Registry files on your system into the specified folder
        // Reference: https://www.nirsoft.net/alpha/reghivebackup.zip
        $string1 = /\/reghivebackup\.zip/ nocase ascii wide
        // Description: backup the Registry files on your system into the specified folder
        // Reference: https://www.nirsoft.net/alpha/reghivebackup.zip
        $string2 = /\\RegHiveBackup\.cfg/ nocase ascii wide
        // Description: backup the Registry files on your system into the specified folder
        // Reference: https://www.nirsoft.net/alpha/reghivebackup.zip
        $string3 = /\\reghivebackup\.zip/ nocase ascii wide
        // Description: backup the Registry files on your system into the specified folder
        // Reference: https://www.nirsoft.net/alpha/reghivebackup.zip
        $string4 = /\\Root\\InventoryApplicationFile\\reghivebackup/ nocase ascii wide
        // Description: backup the Registry files on your system into the specified folder
        // Reference: https://www.nirsoft.net/alpha/reghivebackup.zip
        $string5 = ">RegHiveBackup<" nocase ascii wide
        // Description: backup the Registry files on your system into the specified folder
        // Reference: https://www.nirsoft.net/alpha/reghivebackup.zip
        $string6 = /RegHiveBackup\.exe/ nocase ascii wide

    condition:
        any of them
}

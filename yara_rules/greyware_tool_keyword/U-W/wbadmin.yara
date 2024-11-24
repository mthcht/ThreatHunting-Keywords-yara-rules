rule wbadmin
{
    meta:
        description = "Detection patterns for the tool 'wbadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wbadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: hinder recovery efforts with wbadmin
        // Reference: N/A
        $string1 = "wbadmin delete backup" nocase ascii wide
        // Description: delete the Windows backup utility catalog
        // Reference: N/A
        $string2 = "wbadmin delete catalog -quiet" nocase ascii wide
        // Description: Wbadmin allows administrators to manage and automate backup and recovery operations in Windows systems. Adversaries may abuse wbadmin to manipulate backups and restore points as part of their evasion tactics. This can include deleting backup files. disabling backup tasks. or tampering with backup configurations to hinder recovery efforts and potentially erase traces of their malicious activities. By interfering with backups. adversaries can make it more challenging for defenders to restore systems and detect their presence.
        // Reference: N/A
        $string3 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" nocase ascii wide
        // Description: Wbadmin allows administrators to manage and automate backup and recovery operations in Windows systems. Adversaries may abuse wbadmin to manipulate backups and restore points as part of their evasion tactics. This can include deleting backup files. disabling backup tasks. or tampering with backup configurations to hinder recovery efforts and potentially erase traces of their malicious activities. By interfering with backups. adversaries can make it more challenging for defenders to restore systems and detect their presence.
        // Reference: N/A
        $string4 = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase ascii wide

    condition:
        any of them
}

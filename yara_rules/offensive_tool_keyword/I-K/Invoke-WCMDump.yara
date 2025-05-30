rule Invoke_WCMDump
{
    meta:
        description = "Detection patterns for the tool 'Invoke-WCMDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-WCMDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell script to dump Windows credentials from the Credential Manager Invoke-WCMDump enumerates Windows credentials in the Credential Manager and then extracts available information about each one. Passwords are retrieved for Generic type credentials. but can not be retrived by the same method for Domain type credentials. Credentials are only returned for the current user
        // Reference: https://github.com/peewpw/Invoke-WCMDump
        $string1 = "5a0976fef89e32ddcf62c790f9bb4c174a79004e627c3521604f46bf5cc7bea2" nocase ascii wide
        // Description: PowerShell script to dump Windows credentials from the Credential Manager Invoke-WCMDump enumerates Windows credentials in the Credential Manager and then extracts available information about each one. Passwords are retrieved for Generic type credentials. but can not be retrived by the same method for Domain type credentials. Credentials are only returned for the current user
        // Reference: https://github.com/peewpw/Invoke-WCMDump
        $string2 = "Invoke-WCMDump" nocase ascii wide

    condition:
        any of them
}

rule AzureADLateralMovement
{
    meta:
        description = "Detection patterns for the tool 'AzureADLateralMovement' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AzureADLateralMovement"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AzureADLateralMovement allows to build Lateral Movement graph for Azure Active Directory entities - Users. Computers. Groups and Roles. Using the Microsoft Graph API AzureADLateralMovement extracts interesting information and builds json files containing Lateral Movement graph data compatible with Bloodhound 2.2.0
        // Reference: https://github.com/talmaor/AzureADLateralMovement
        $string1 = /AzureADLateralMovement/ nocase ascii wide

    condition:
        any of them
}

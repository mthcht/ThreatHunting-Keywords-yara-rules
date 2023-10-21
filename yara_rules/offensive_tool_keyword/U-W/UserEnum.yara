rule UserEnum
{
    meta:
        description = "Detection patterns for the tool 'UserEnum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UserEnum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The three scripts provided here allow one to establish if a user exist on a Windows domain. without providing any authentication. These user enumeration scripts use the DsrGetDcNameEx2.CLDAP ping and NetBIOS MailSlot ping methods respectively to establish if any of the usernames in a provided text file exist on a remote domain controller.
        // Reference: https://github.com/sensepost/UserEnum
        $string1 = /UserEnum/ nocase ascii wide

    condition:
        any of them
}
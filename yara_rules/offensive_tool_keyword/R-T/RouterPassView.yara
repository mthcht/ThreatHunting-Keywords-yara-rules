rule RouterPassView
{
    meta:
        description = "Detection patterns for the tool 'RouterPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RouterPassView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string1 = ">RouterPassView<" nocase ascii wide
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string2 = "3ee00a42a65d2df9ee571875a11f53b56c8494e90e1e8e60e128aabdb56399c8" nocase ascii wide
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string3 = "3ee00a42a65d2df9ee571875a11f53b56c8494e90e1e8e60e128aabdb56399c8" nocase ascii wide
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string4 = "d3821591de381cb2861c5cf554009e51d7afe51b7c14e89b6f06a666bab949ff" nocase ascii wide
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string5 = "Grab Password From IE Window" nocase ascii wide
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string6 = /RouterPassView\.exe/ nocase ascii wide
        // Description: help you to recover your lost password from your router file
        // Reference: https://www.nirsoft.net/utils/router_password_recovery.html
        $string7 = /routerpassview\.zip/ nocase ascii wide

    condition:
        any of them
}

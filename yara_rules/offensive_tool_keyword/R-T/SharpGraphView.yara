rule SharpGraphView
{
    meta:
        description = "Detection patterns for the tool 'SharpGraphView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGraphView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string1 = " Invoke-CertToAccessToken -tenant " nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string2 = /\/SharpGraphView\.git/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string3 = /\\SharpGraphView\.sln/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string4 = /\\sharpgraphview\\/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string5 = ">SharpGraphView<" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string6 = "2beff60039dfd82bd092bae6e69a92ed04cdcf7cfe597868bb161dbc15c3de73" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string7 = "3922246663d030813506516c147f8281d8c81f1cdc1153238643f580b52093d7" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string8 = "64d0026295c3c887bbcb256967aae006f4df254a2bc9418f9a1dc30fd6115ee1" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string9 = "825E2088-EC7C-4AB0-852A-4F1FEF178E37" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string10 = "mlcsec/SharpGraphView" nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string11 = /SharpGraph\.exe\sGet\-UserChatMessages\s\-id\s/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string12 = /SharpGraph\.exe\sList\-ChatMessages\s/ nocase ascii wide
        // Description: Microsoft Graph API post-exploitation toolkit
        // Reference: https://github.com/mlcsec/SharpGraphView
        $string13 = /SharpGraphView\.exe/ nocase ascii wide

    condition:
        any of them
}

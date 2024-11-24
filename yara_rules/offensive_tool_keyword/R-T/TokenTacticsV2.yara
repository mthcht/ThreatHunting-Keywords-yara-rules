rule TokenTacticsV2
{
    meta:
        description = "Detection patterns for the tool 'TokenTacticsV2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenTacticsV2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string1 = "\"MSGraph token is CAE capable\"" nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string2 = /\/TokenTacticsV2\.git/ nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string3 = /\\ConvertFrom\-JWTtoken\.ps1/ nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string4 = "4aede7350521d2a3d0975833db870f94c50c8d46c28d8b14f930619e35b4b07e" nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string5 = "8648dfc2aff4508e8469d1ed4a7a775b558527bfb0050ba4ed75db259b07943d" nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string6 = "da9735d88a845e465aa4fe4968df15b97ba4b6565f150a48ead7a3ca7298df93" nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string7 = "dd86be9a1fb1198264e1a01247473be5e1498ef549a91b7c7143e5cfc25784e1" nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string8 = "f-bader/TokenTacticsV2" nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string9 = "Get-AzureTokenFromESTSCookie " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string10 = "Get-AzureTokenFromESTSCookie -ESTSAuthCookie " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string11 = "Get-ForgedUserAgent " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string12 = /Get\-ForgedUserAgent\.ps1/ nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string13 = "Invoke-RefreshToAzureCoreManagementToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string14 = "Invoke-RefreshToAzureManagementToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string15 = "Invoke-RefreshToDODMSGraphToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string16 = "Invoke-RefreshToGraphToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string17 = "Invoke-RefreshToMAMToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string18 = "Invoke-RefreshToMSGraphToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string19 = "Invoke-RefreshToMSManageToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string20 = "Invoke-RefreshToMSTeamsToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string21 = "Invoke-RefreshToOfficeAppsToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string22 = "Invoke-RefreshToOfficeManagementToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string23 = "Invoke-RefreshToOneDriveToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string24 = "Invoke-RefreshToOutlookToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string25 = "Invoke-RefreshToSharePointToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string26 = "Invoke-RefreshToSubstrateToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string27 = "Invoke-RefreshToToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string28 = "Invoke-RefreshToYammerToken " nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string29 = /TokenTactics\.psd1/ nocase ascii wide
        // Description: fork of the great TokenTactics with support for CAE and token endpoint v2
        // Reference: https://github.com/f-bader/TokenTacticsV2
        $string30 = /TokenTactics\.psm1/ nocase ascii wide

    condition:
        any of them
}

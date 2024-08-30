rule ExtPassword_exe
{
    meta:
        description = "Detection patterns for the tool 'ExtPassword.exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtPassword.exe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string1 = /\/extpassword\.zip/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string2 = /\/utils\/external_drive_password_recovery\.html/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string3 = /\\ExtPassword\.chm/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string4 = /\\ExtPassword\.html/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string5 = /\\extpassword\.zip/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string6 = /\\ExtPassword_lng\.ini/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string7 = /03a544b51ade8258a377800fda3237ce6f36ebae34e6787380c0a2f341b591e9/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string8 = /bd61c5daaad30b420817fb1fd2f0447c3b66a1900ba69fd4cd724d1e6897ab41/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string9 = /External\sDrive\sPassword\sRecovery/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string10 = /ExtPassword\.exe/ nocase ascii wide

    condition:
        any of them
}

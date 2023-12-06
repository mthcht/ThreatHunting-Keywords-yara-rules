rule ContainYourself
{
    meta:
        description = "Detection patterns for the tool 'ContainYourself' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ContainYourself"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string1 = /\s\-\-copy\-file\s\-\-source\-file\s.{0,1000}\.docx\s\-\-target\-file\s.{0,1000}\.docx\s\-\-target\-volume\s/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string2 = /\.exe\s\-\-override\-file\s\-\-source\-file\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string3 = /\.exe\s\-\-remove\-reparse\s\-\-source\-file\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string4 = /\.exe\s\-\-set\-reparse\soverride\s\-\-source\-file\s.{0,1000}\.exe\s\-\-target\-file\s/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string5 = /\/ContainYourself\.git/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string6 = /\\WiperPoc\.cpp/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string7 = /4F2AD0E0\-8C4D\-45CB\-97DE\-CE8D4177E7BF/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string8 = /79F54747\-048D\-4FD6\-AEF4\-7B098F923FD8/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string9 = /B5627919\-4DFB\-49C6\-AC1B\-C757F4B4A103/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string10 = /ContainYourself\.cpp/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string11 = /ContainYourself\.exe/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string12 = /ContainYourself\.sln/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string13 = /ContainYourself\-main/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string14 = /ContainYourselfPoc\.cpp/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string15 = /ContainYourselfPoc\.exe/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string16 = /ContainYourselfPoc\\/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string17 = /ContainYourselfTempFile\.txt/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string18 = /deepinstinct\/ContainYourself/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string19 = /FA0DAF13\-5058\-4382\-AE07\-65E44AFB5592/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string20 = /Ransomware\sPOC\stool\sthat\sencrypts\sa\sgiven\sdirectory/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string21 = /RansomwarePoc\.cpp/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string22 = /RansomwarePoc\.exe/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string23 = /RansomwarePoc\\RansomwarePoc/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string24 = /Wiper\sPOC\stool\sthat\swipes\sa\sgiven\sdirectory/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string25 = /WiperPoc\.exe/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string26 = /WiperPoc\\WiperPoc/ nocase ascii wide

    condition:
        any of them
}

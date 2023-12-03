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
        $string1 = /.{0,1000}\s\-\-copy\-file\s\-\-source\-file\s.{0,1000}\.docx\s\-\-target\-file\s.{0,1000}\.docx\s\-\-target\-volume\s.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string2 = /.{0,1000}\.exe\s\-\-override\-file\s\-\-source\-file\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string3 = /.{0,1000}\.exe\s\-\-remove\-reparse\s\-\-source\-file\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string4 = /.{0,1000}\.exe\s\-\-set\-reparse\soverride\s\-\-source\-file\s.{0,1000}\.exe\s\-\-target\-file\s.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string5 = /.{0,1000}\/ContainYourself\.git.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string6 = /.{0,1000}\\WiperPoc\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string7 = /.{0,1000}4F2AD0E0\-8C4D\-45CB\-97DE\-CE8D4177E7BF.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string8 = /.{0,1000}79F54747\-048D\-4FD6\-AEF4\-7B098F923FD8.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string9 = /.{0,1000}B5627919\-4DFB\-49C6\-AC1B\-C757F4B4A103.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string10 = /.{0,1000}ContainYourself\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string11 = /.{0,1000}ContainYourself\.exe.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string12 = /.{0,1000}ContainYourself\.sln.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string13 = /.{0,1000}ContainYourself\-main.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string14 = /.{0,1000}ContainYourselfPoc\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string15 = /.{0,1000}ContainYourselfPoc\.exe.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string16 = /.{0,1000}ContainYourselfPoc\\.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string17 = /.{0,1000}ContainYourselfTempFile\.txt.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string18 = /.{0,1000}deepinstinct\/ContainYourself.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string19 = /.{0,1000}FA0DAF13\-5058\-4382\-AE07\-65E44AFB5592.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string20 = /.{0,1000}Ransomware\sPOC\stool\sthat\sencrypts\sa\sgiven\sdirectory.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string21 = /.{0,1000}RansomwarePoc\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string22 = /.{0,1000}RansomwarePoc\.exe.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string23 = /.{0,1000}RansomwarePoc\\RansomwarePoc.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string24 = /.{0,1000}Wiper\sPOC\stool\sthat\swipes\sa\sgiven\sdirectory.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string25 = /.{0,1000}WiperPoc\.exe.{0,1000}/ nocase ascii wide
        // Description: Abuses the Windows containers framework to bypass EDRs.
        // Reference: https://github.com/deepinstinct/ContainYourself
        $string26 = /.{0,1000}WiperPoc\\WiperPoc.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

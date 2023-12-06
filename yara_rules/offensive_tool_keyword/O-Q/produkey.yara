rule produkey
{
    meta:
        description = "Detection patterns for the tool 'produkey' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "produkey"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string1 = /\/ProduKey\.exe/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string2 = /\\ProduKey\.exe/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string3 = /produkey\.zip/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string4 = /produkey_setup\.exe/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string5 = /produkey\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}

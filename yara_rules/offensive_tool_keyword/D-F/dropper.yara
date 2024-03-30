rule dropper
{
    meta:
        description = "Detection patterns for the tool 'dropper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string1 = /\/Chakra\.dll/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string2 = /\[\+\]\sInjecting\sdropper\.vba\sinto\s/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string3 = /\\Chakra\.dll/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string4 = /\\Demo\\VulnApp\.exe/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string5 = /\\dropper\\dropit\.py/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string6 = /\\dropper\\dropper\.vba/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string7 = /\\tools\\DocLnk\.exe/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string8 = /441cb40ecc946bfb7d9ec0e7880f17f07b899adb176c6f40231aec2ab41ac1d7/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string9 = /62ad0c68652b614acd4b82670b987719dee83f900678788bacf7cef174ea17d9/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string10 = /a475f8e5b3581cb7b93cd3021478957ec5997aa3995c1a686fb87ae6c84ec2b1/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string11 = /c27eaa1709a00ec0c47d47b8c6c061b2f63223d8553fa7d7baa40f7cea903b8f/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string12 = /c6e09870a9f7d1e74d9364d7a4d27cc0ad96f1637ee3e60e2c2df5169972058c/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string13 = /execute_embed_docm\(/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string14 = /genMalDoc\(\)/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string15 = /github.{0,1000}\/dropper\.git/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string16 = /Hello\sfrom\sMalicious\sDLL/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string17 = /inject_macro_word\(/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string18 = /SaadAhla\/dropper/ nocase ascii wide
        // Description: Generates Malicious Office Macro Enabled Dropper for DLL SideLoading and Embed it in Lnk file to bypass MOTW
        // Reference: https://github.com/SaadAhla/dropper
        $string19 = /update_vba_file_url_droppingPath\(/ nocase ascii wide

    condition:
        any of them
}

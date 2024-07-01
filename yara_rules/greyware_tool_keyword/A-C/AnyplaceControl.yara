rule AnyplaceControl
{
    meta:
        description = "Detection patterns for the tool 'AnyplaceControl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AnyplaceControl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string1 = /\/anyplace\-control\/data2\/.{0,1000}\.exe/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string2 = /\\Anyplace\sControl\s\-\sAdmin\.lnk/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string3 = /\\Anyplace\sControl\\/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string4 = /\\anyplace\-control\.ini/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string5 = /\\AppData\\Local\\Temp\\.{0,1000}\\zmstage\.exe/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string6 = /\\AppData\\Roaming\\Anyplace\sControl/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string7 = /\\Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string8 = /\\ProgramData\\Anyplace\sControl\s/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string9 = /\>Anyplace\sControl\sSoftware\</ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string10 = /a2fa034d006bdbc3ee2a15e55eb647f8097355c288a858da1e309fe8ac1cf0a3/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string11 = /AnyplaceControlInstall\.exe/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string12 = /Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string13 = /www\.anyplace\-control\.com\/install/ nocase ascii wide

    condition:
        any of them
}

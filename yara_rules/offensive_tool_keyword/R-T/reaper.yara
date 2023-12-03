rule reaper
{
    meta:
        description = "Detection patterns for the tool 'reaper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reaper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string1 = /.{0,1000}\/Reaper\.git.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string2 = /.{0,1000}\/Reaper\/Reaper\.cpp.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string3 = /.{0,1000}\/ReaperX64\.zip.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string4 = /.{0,1000}\\Reaper\\Reaper\.cpp.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string5 = /.{0,1000}\\Reaper\-main\\.{0,1000}\.sys.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string6 = /.{0,1000}\\Temp\\Reaper\.exe.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string7 = /.{0,1000}30f7ba049eab00673ae6b247199ec4f6af533d9ba46482159668fd23f484bdc6.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string8 = /.{0,1000}526f652d4d9e20a19374817eac75b914b75f3bfaecc16b65f979e5758ea62476.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string9 = /.{0,1000}c725919e6357126d512c638f993cf572112f323da359645e4088f789eb4c7b8c.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string10 = /.{0,1000}CB561720\-0175\-49D9\-A114\-FE3489C53661.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string11 = /.{0,1000}github\.com\/.{0,1000}Reaper\.exe.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string12 = /.{0,1000}MrEmpy\/Reaper.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string13 = /.{0,1000}Reaper\.exe\skp\s.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string14 = /.{0,1000}Reaper\.exe\ssp\s.{0,1000}/ nocase ascii wide
        // Description: Reaper is a proof-of-concept designed to exploit BYOVD (Bring Your Own Vulnerable Driver) driver vulnerability. This malicious technique involves inserting a legitimate - vulnerable driver into a target system - which allows attackers to exploit the driver to perform malicious actions.
        // Reference: https://github.com/MrEmpy/Reaper
        $string15 = /.{0,1000}Reaper\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

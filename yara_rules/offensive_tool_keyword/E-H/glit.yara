rule glit
{
    meta:
        description = "Detection patterns for the tool 'glit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "glit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string1 = /.{0,1000}\srepo\s\-u\shttps:\/\/github\.com\/.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string2 = /.{0,1000}\/glit\.git.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string3 = /.{0,1000}\/glit\-cli.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string4 = /.{0,1000}\/glit\-core.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string5 = /.{0,1000}\\glit\.exe.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string6 = /.{0,1000}\\glit\-cli.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string7 = /.{0,1000}cargo\sinstall\sglit.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string8 = /.{0,1000}glit\sorg\s\-.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string9 = /.{0,1000}glit\srepo\s.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string10 = /.{0,1000}glit\suser\s.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string11 = /.{0,1000}glit\.exe\sorg.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string12 = /.{0,1000}glit\.exe\srepo.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string13 = /.{0,1000}glit\.exe\suser.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string14 = /.{0,1000}glit\-i686\-pc\-windows\-msvc.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string15 = /.{0,1000}glit\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string16 = /.{0,1000}glit\-x86_64\-apple\-darwin.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string17 = /.{0,1000}glit\-x86_64\-pc\-windows\-msvc.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string18 = /.{0,1000}glit\-x86_64\-unknown\-linux\-gnu.{0,1000}/ nocase ascii wide
        // Description: Retrieve all mails of users related to a git repository a git user or a git organization
        // Reference: https://github.com/shadawck/glit
        $string19 = /.{0,1000}shadawck\/glit.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

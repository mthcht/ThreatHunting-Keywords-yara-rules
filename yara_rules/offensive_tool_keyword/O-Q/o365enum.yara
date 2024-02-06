rule o365enum
{
    meta:
        description = "Detection patterns for the tool 'o365enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string1 = /1c50adeb\-53ac\-41b9\-9c34\-7045cffbae45/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string2 = /23975ac9\-f51c\-443a\-8318\-db006fd83100/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string3 = /2944dbfc\-8a1e\-4759\-a8a2\-e4568950601d/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string4 = /aW52YWxpZF91c2VyQGNvbnRvc28uY29tOlBhc3N3b3JkMQ/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string5 = /c708b83f\-4167\-4b4c\-a1db\-d2011ecb3200/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string6 = /d494a4bc\-3867\-436a\-93ef\-737f9e0522eb/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string7 = /dmFsaWRfdXNlckBjb250b3NvLmNvbTpQYXNzd29yZDE/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string8 = /fea01b74\-7a60\-4142\-a54d\-7aa8f6471c00/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string9 = /gremwell\/o365enum/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string10 = /o365enum\.py/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string11 = /o365enum\-master/ nocase ascii wide
        // Description: Enumerate valid usernames from Office 365 using ActiveSync - Autodiscover v1 or office.com login page.
        // Reference: https://github.com/gremwell/o365enum
        $string12 = /valid_user\@contoso\.com\:Password1/ nocase ascii wide

    condition:
        any of them
}

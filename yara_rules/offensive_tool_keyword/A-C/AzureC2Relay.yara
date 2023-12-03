rule AzureC2Relay
{
    meta:
        description = "Detection patterns for the tool 'AzureC2Relay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AzureC2Relay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string1 = /.{0,1000}\/AzureC2Relay.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string2 = /.{0,1000}\/ParsedMalleableData\.txt.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string3 = /.{0,1000}\\AzureC2Proxy\\.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string4 = /.{0,1000}\\AzureC2Relay.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string5 = /.{0,1000}\\ParsedMalleableData\.txt.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string6 = /.{0,1000}AzureC2Relay\.zip.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string7 = /.{0,1000}AzureC2Relay\-main.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string8 = /.{0,1000}cobaltstrike\-dist\.tgz.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string9 = /.{0,1000}dotnet\sParseMalleable\/ParseMalleable\.dll.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string10 = /.{0,1000}GenericC2Relay\.cs.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string11 = /.{0,1000}MalleableProfileB64.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string12 = /.{0,1000}mojo\.5688\.8052\.183894939787088877\#\#.{0,1000}/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string13 = /.{0,1000}mojo\.5688\.8052\.35780273329370473\#\#.{0,1000}/ nocase ascii wide

    condition:
        any of them
}

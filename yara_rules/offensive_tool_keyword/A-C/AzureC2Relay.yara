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
        $string1 = /\/AzureC2Relay/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string2 = /\/ParsedMalleableData\.txt/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string3 = /\\AzureC2Proxy\\/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string4 = /\\AzureC2Relay/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string5 = /\\ParsedMalleableData\.txt/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string6 = /AzureC2Relay\.zip/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string7 = /AzureC2Relay\-main/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string8 = /cobaltstrike\-dist\.tgz/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string9 = /dotnet\sParseMalleable\/ParseMalleable\.dll/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string10 = /GenericC2Relay\.cs/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string11 = /MalleableProfileB64/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string12 = /mojo\.5688\.8052\.183894939787088877\#\#/ nocase ascii wide
        // Description: AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile.
        // Reference: https://github.com/Flangvik/AzureC2Relay
        $string13 = /mojo\.5688\.8052\.35780273329370473\#\#/ nocase ascii wide

    condition:
        any of them
}

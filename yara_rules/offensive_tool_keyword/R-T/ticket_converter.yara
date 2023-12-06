rule ticket_converter
{
    meta:
        description = "Detection patterns for the tool 'ticket_converter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ticket_converter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A little tool to convert ccache tickets into kirbi (KRB-CRED) and vice versa based on impacket.
        // Reference: https://github.com/zer1t0/ticket_converter
        $string1 = /\sticket_converter\.py/ nocase ascii wide
        // Description: A little tool to convert ccache tickets into kirbi (KRB-CRED) and vice versa based on impacket.
        // Reference: https://github.com/zer1t0/ticket_converter
        $string2 = /\.py.{0,1000}\.ccache\s.{0,1000}\.kirbi\s/ nocase ascii wide
        // Description: A little tool to convert ccache tickets into kirbi (KRB-CRED) and vice versa based on impacket.
        // Reference: https://github.com/zer1t0/ticket_converter
        $string3 = /\.py.{0,1000}\.kirbi\s.{0,1000}\.ccache/ nocase ascii wide
        // Description: A little tool to convert ccache tickets into kirbi (KRB-CRED) and vice versa based on impacket.
        // Reference: https://github.com/zer1t0/ticket_converter
        $string4 = /\/ticket_converter\.py/ nocase ascii wide
        // Description: A little tool to convert ccache tickets into kirbi (KRB-CRED) and vice versa based on impacket.
        // Reference: https://github.com/zer1t0/ticket_converter
        $string5 = /\\ticket_converter\.py/ nocase ascii wide

    condition:
        any of them
}

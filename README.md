# Quick Start
## Start Sniffing
There's a green start button on the top left that starts a sniffing thread.
## Snop Sniffing
There's a red stop button on the top left that terminates the sniffing thread.
## Filter
To use a filter, type the query in the filter entry field and click the filter button. To remove the filter, make the filter entry field empty then click fliter button.
### Filter Query Format
### Comparators
Filter currently supports 2 comparators: == and is
Here's an example query:
`IPv4_Source IP == 127.0.0.1`
or equivalently:
`127.0.0.1 in IPv4_Source IP`
> As there is no manual written at the moment, please refer to the keys for Packet.pretty in the code for variable names. 

> Work is currently being done to simplify this process with features such as variable suggestions.
### Multiple Filters
Use underscores to seperate the keys:
`self.pretty['ARP']['Sender IP Address'] == 127.0.0.1` will be `ARP_Sender IP Address == 127.0.0.1` in the query field
You can use and/or with brackets for multiple filters. MAKE SURE YOU ONLY INCLUDE 1 and/or IN EACH ( ).
> Work is being done at the moment to make sure errors in querys won't crash the program

# Future Development Plan
### In Development
Essentials:
1. PCAP format support
2. More common protocols such as DNS, ICMP and HTTP
Not so urgent:
1. Interface selection
Quality of life:
1. Hex and Ascii highlight when data in tree is clicked
### Planned
Essentials:
1. TCP streams
2. HTTPS support
Quality of life:
1. Details tree selection when Hex or Ascii is clicked

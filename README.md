# n1sub

n1sub is a linux kernel pwn challenge for n1ctf 2023

## short writeup
you can corrupt `struct nft_rules` with the vuln in the module, then use 
`struct nft_rules_dp` to leak and rop

the full writeup will be release in the near future

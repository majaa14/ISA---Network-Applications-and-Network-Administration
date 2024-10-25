## Popis

Tento program slouží k monitorování provozu DHCP na zadaném síťovém rozhraní nebo souboru. 
Program sleduje DHCP pakety a generuje statistiky vytížení síťových prefixů. 
Může být spuštěn v reálném čase na síťovém rozhraní nebo zpracovávat zachycený provoz ze souboru ve formátu pcap.

## Instalace

Aplikaci není nutné instalovat. Stačí stáhnout a přeložit pomocí přiloženého makefilu.

## Funkce

- Monitorování DHCP provozu.
- Generování statistik o vytížení síťových prefixů.
- Zápis do logu při překročení 50% alokovaných adres v prefixu.

## Omezení

- Program momentálně podporuje pouze IPv4.
- Může být spuštěn pouze na systémech s nainstalovaným rsyslogem.
- Program momentálně podporuje maximálně 1000 prefixů, které mohou být zadány v příkazovém řádku.
- Program nerozeznává duplitní přidělené IP adresy, počítá každou příchozí adresu v daném prefixu.

## Příklad spuštění

./dhcp-stats -i eth0 192.168.1.0/24 172.16.32.0/24
./dhcp-stats -r file.pcapng 192.168.88.0/24

## Ukončení konzolové aplikace

Ukončit konzolovou aplikaci (v terminálu) lze jakoukoli klávesou nebo Ctrl + C.

## Hodnocení

Projekt byl hodnocen 20/20.

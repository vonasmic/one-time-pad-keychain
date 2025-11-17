# Popis odvedené práce: Hybridní mTLS 1.3 komunikace s devkitem přes USB

## Přehled

Byla implementována hybridní vzájemná TLS 1.3 (mTLS) komunikace mezi STM32U535 devkitem a TLS serverem přes USB rozhraní. Implementace využívá knihovnu WolfSSL a kombinuje post-kvantové kryptografické algoritmy (PQC) s klasickými algoritmy pro hybridní bezpečnost.

## Architektura řešení

### Komponenty systému

1. **STM32U535 Firmware**
   - TLS 1.3 klient běžící na MCU
   - USB komunikace pro TLS I/O
   - Embedded certifikáty a klíče v firmware

2. **TLS Server**
   - TLS 1.3 server pro testování komunikace
   - Podpora hybridních certifikátů (ECC + Dilithium)

3. **USB-TCP Bridge**
   - Most mezi USB sériovým portem a TCP socketem
   - Umožňuje devkitu komunikovat s TCP serverem přes USB
   - Podpora verbose loggingu pro debugging

## Realizované kryptografické algoritmy

### Výměna klíčů: ML-KEM-768

Byla implementována výměna klíčů pomocí **ML-KEM-768** (Module-Lattice Key Encapsulation Mechanism, dříve známý jako Kyber-768). ML-KEM-768 je post-kvantový algoritmus schválený NIST pro key encapsulation.

**Charakteristiky:**
- Algoritmus: ML-KEM-768 (úroveň 3)
- Velikost veřejného klíče: ~1184 bajtů
- Velikost ciphertextu: ~1088 bajtů
- Velikost sdíleného tajemství: 32 bajtů

**Realizace:**
- Konfigurace WolfSSL pro podporu ML-KEM-768
- Integrace ML-KEM-768 do TLS 1.3 handshaku
- Použití ML-KEM-768 jako preferovaného algoritmu pro key exchange

### Autentizace: Hybridní ECC + Dilithium

Byla implementována autentizace pomocí **hybridního certifikátu**, který obsahuje současně:
- **ECDSA** (Elliptic Curve Digital Signature Algorithm) - klasický algoritmus
- **Dilithium-3** (ML-DSA-65) - post-kvantový algoritmus

Oba algoritmy podepisují stejný certifikát, což zajišťuje:
- **Zpětnou kompatibilitu** s klasickými systémy (ECC podpis)
- **Post-kvantovou bezpečnost** (Dilithium podpis)
- **Oboustrannou autentizaci** (mTLS) - server i klient používají hybridní certifikáty

**Realizace:**
- Konfigurace WolfSSL pro dual-algorithm certifikáty
- Načítání hybridních certifikátů (ECC + Dilithium) do TLS kontextu
- Konfigurace pro použití obou podpisů současně při handshaku

## Konfigurace TLS 1.3

### Key Exchange: ML-KEM-768

Byla konfigurována výměna klíčů pomocí ML-KEM-768:
- ML-KEM-768 je nastaven jako preferovaný a jediný algoritmus pro key exchange
- Klient vždy nabízí ML-KEM-768 v ClientHello
- Server musí podporovat ML-KEM-768 pro úspěšný handshake

### Signature Algorithms: Hybridní ECC + Dilithium

Byla konfigurována podpora hybridních signature algoritmů:
- **ECDSA** (secp256r1) - klasický algoritmus pro zpětnou kompatibilitu
- **Dilithium-3** (ML-DSA-65) - post-kvantový algoritmus
- Oba algoritmy jsou nabízeny současně v handshaku
- Certifikáty obsahují oba podpisy (dual-algorithm certificates)

### Cipher Suites

Byla implementována podpora pro následující cipher suity:
- `TLS_AES_256_GCM_SHA384` (preferovaný)
- `TLS_AES_128_GCM_SHA256`

Cipher suity jsou konfigurovány v pořadí priority, přičemž TLS_AES_256_GCM_SHA384 má přednost.

### Mutual TLS (mTLS) konfigurace

Byla implementována oboustranná autentizace:
- Klient je konfigurován pro odesílání klientského certifikátu
- Klient používá hybridní certifikát (ECC + Dilithium)
- Server vyžaduje a ověřuje klientský certifikát
- Oba podpisy (ECC + Dilithium) jsou ověřovány na klientském certifikátu

### TLS verifikace certifikátů

**Server certificate verification:**
- Klient ověřuje serverový certifikát
- Ověřuje se přítomnost a platnost obou podpisů (ECC + Dilithium)
- Pro testování jsou akceptovány self-signed certifikáty
- CA verifikace není implementována (plánováno do budoucna)

**Client certificate verification:**
- Server automaticky ověřuje klientský certifikát při mTLS handshaku
- Ověřuje se přítomnost a platnost obou podpisů
- Ověřuje se CertificateVerify zpráva s oběma podpisy

## USB komunikace

### Realizace USB transportu

Byla implementována TLS komunikace přes USB pomocí custom I/O callbacků pro WolfSSL:

**Příjem dat (USB → TLS):**
- Implementován callback pro čtení TLS dat z USB
- Data jsou čtena z ring bufferu
- Podporuje non-blocking operace s WANT_READ semantikou

**Odesílání dat (TLS → USB):**
- Implementován callback pro odesílání TLS dat přes USB
- Používá USB CDC (Communication Device Class) protokol
- Obsahuje retry mechanismus pro spolehlivé odesílání

### Ring Buffer pro USB RX

Byl implementován ring buffer pro ukládání USB RX dat:
- Velikost bufferu: 16 KB
- Sdílený mezi USB interrupt handlerem (zápis) a TLS recv callbackem (čtení)
- Synchronizace pomocí disable/enable IRQ pro ochranu kritických sekcí
- Chráněn před race conditions

### USB-TCP Bridge

Byl vytvořen Python bridge pro testování:
- Připojuje se k USB sériovému portu devkitu
- Připojuje se k TCP TLS serveru
- Přeposílá data mezi USB a TCP obousměrně
- Podporuje verbose logging TLS handshaku pro debugging

## Embedded certifikáty

### Generování a embedování certifikátů

Byl vytvořen automatizační skript pro generování a embedování certifikátů do firmware:

**Funkce skriptu:**
1. Konvertuje PEM certifikáty a klíče do DER formátu
2. Vytváří C header soubor s embedded arrays
3. Automaticky detekuje úroveň Dilithium klíče z PEM hlavičky
4. Generuje statické C pole pro certifikát, ECC klíč a Dilithium klíč

**Struktura embedded certifikátů:**
- Hybridní certifikát (ECC + Dilithium) v DER formátu
- ECC privátní klíč v DER formátu
- Dilithium privátní klíč v DER/PKCS#8 formátu
- Automaticky detekovaná úroveň Dilithium klíče

### Načítání certifikátů do TLS

Byla implementována logika pro načítání embedded certifikátů:
- Načítání hybridního certifikátu do TLS kontextu
- Načítání ECC privátního klíče
- Načítání Dilithium privátního klíče jako alternativního klíče
- Všechny certifikáty jsou načítány z embedded C polí při inicializaci TLS

## Ověřování certifikátů

### Server Certificate Verification

Byla implementována verifikace serverového certifikátu na straně klienta:

**Funkce:**
- S WOLFSSL_DUAL_ALG_CERTS WolfSSL automaticky ověřuje oba podpisy (ECDSA + Dilithium)
- Verifikace projde pouze pokud:
  - Oba podpisy jsou přítomny na certifikátu
  - Oba podpisy jsou platné
  - Certifikát je platný (expirace, atd.)

**Aktuální stav:**
- Ověřování CA není implementováno (pouze self-signed certifikáty jsou akceptovány)
- Důvod: problémy s vytvářením certifikované autority přes wolf-clu
- Plán: implementovat CA verifikaci v budoucnu

### Client Certificate Verification

Server ověřuje klientský certifikát automaticky při mTLS handshaku. Server musí:
- Ověřit ECDSA podpis na klientském certifikátu
- Ověřit Dilithium podpis na klientském certifikátu
- Ověřit CertificateVerify zprávu (oba podpisy)

## Optimalizace a omezení

### Flash Size Constraints

**Aktuální stav:**
- FW flash size se blíží maximu (~85% využití)
- Původní odhad 40% byl chybný kvůli špatně nastavené očekávané velikosti
- Skutečná maximální velikost je přibližně poloviční oproti původnímu očekávání

**Provedené optimalizace:**
- Vypnuta single-precision ECC acceleration - ušetřilo ~45 KiB flash
- Vypnuta session cache
- Vypnuta podpora TLS 1.2 (pouze TLS 1.3)
- Vypnuta server podpora (pouze klient)
- Memory optimalizace pro embedded systém

### Buffer Sizes

PQC algoritmy vyžadují velké buffery:
- ML-KEM-768 public key: ~1184 bajtů
- ML-KEM-768 ciphertext: ~1088 bajtů
- TLS record buffer: 16 KB (povoleno LARGE_STATIC_BUFFERS)

## RNG (Random Number Generator)

### Hardware RNG integrace

Byla implementována integrace hardware RNG periférie STM32U535:

**Použití:**
- Generování ML-KEM klíčů
- Generování ECDSA nonces
- Generování Dilithium nonces
- TLS session keys

**Realizace:**
- Vytvořen custom RNG callback pro WolfSSL
- Používá HAL_RNG_GenerateRandomNumber() pro generování náhodných čísel
- Zpracovává alignment a velikosti pro efektivní generování
- Implementován warm-up mechanismus pro odstranění initial conditioning errors

## Budoucí vylepšení

### 1. ECC Podpis přes TROPIC01

**Aktuální stav:**
- Celý TLS algoritmus běží na MCU straně (STM32U535)
- ECC podpis je prováděn na STM32U535

**Plán:**
- Přidat callback pro ECC podpis ze strany TROPIC01
- TROPIC01 bude provádět ECC operace (vyšší bezpečnost)
- STM32U535 bude pouze koordinovat TLS handshake

### 2. CA Certificate Verification

**Aktuální stav:**
- Ověřování CA není implementováno
- Pouze self-signed certifikáty jsou akceptovány

**Plán:**
- Implementovat načítání CA certifikátu
- Implementovat chain verification
- Vyřešit problémy s wolf-clu pro generování CA

### 3. Arm TrustZone Integration

**Aktuální stav:**
- Klíče jsou embedded jako C arrays v flash

**Plán:**
- Přesunout klíče do Arm TrustZone
- Zvýšit bezpečnost uložení privátních klíčů
- Vyhodnotit dopad na flash size

## Testování a validace

### Testovací infrastruktura

Byla vytvořena kompletní testovací infrastruktura:

1. **TLS Server** - testovací server s podporou hybridních certifikátů
2. **USB-TCP Bridge** - most pro propojení USB devkitu s TCP serverem
3. **Diagnostické nástroje** - verbose logging a debugging funkce

### Testovací scénáře

**Základní TLS handshake:**
- Spuštění TLS serveru s hybridními certifikáty
- Propojení devkitu přes USB-TCP bridge
- Spuštění TLS handshaku z devkitu
- Ověření úspěšného navázání spojení

**Debugging funkce:**
- Verbose TLS logging v bridge
- Zobrazení ClientHello a ServerHello zpráv
- Zobrazení cipher suitů, supported groups, signature algorithms
- Zobrazení alert zpráv při chybách

**Diagnostické příkazy na devkitu:**
- `TLS` - spustit TLS handshake
- `TLSDUAL` - test dual-algorithm podpisu
- `RNG` - test RNG na všech úrovních (HAL, wolfSSL, TLS)

## Bezpečnostní charakteristiky

### Hybridní přístup

Hybridní certifikáty (ECC + Dilithium) poskytují:
- **Zpětnou kompatibilitu**: ECC podpis funguje s klasickými systémy
- **Post-kvantovou bezpečnost**: Dilithium podpis odolává kvantovým útokům
- **Defense in depth**: Pokud jeden algoritmus selže, druhý stále poskytuje ochranu

### Aktuální omezení

1. **CA Verification**: Není implementováno - pouze self-signed certifikáty jsou akceptovány
2. **Key Storage**: Klíče jsou v plaintextu v flash (plán: TrustZone)
3. **ECC na MCU**: ECC podpis probíhá na STM32U535 (plán: TROPIC01 callback)

## Shrnutí odvedené práce

Byla úspěšně implementována hybridní mTLS 1.3 komunikace, která kombinuje:
- Post-kvantovou výměnu klíčů (ML-KEM-768)
- Hybridní autentizaci (ECC + Dilithium)
- Oboustrannou autentizaci (mTLS)
- USB transport layer

### Hlavní dosažené výsledky

1. **Funkční TLS 1.3 klient** na STM32U535 s podporou PQC algoritmů
2. **Hybridní certifikáty** s dvojitým podpisem (ECC + Dilithium)
3. **ML-KEM-768 key exchange** pro post-kvantovou bezpečnost
4. **USB transport layer** pro komunikaci s TLS serverem
5. **Testovací infrastruktura** včetně serveru a USB-TCP bridge

### Omezení a plány do budoucna

Systém je funkční a připraven pro testování. Identifikovaná omezení a plánovaná vylepšení:
- Integrace TROPIC01 pro ECC operace (callback mechanismus)
- CA verifikace certifikátů (aktuálně pouze self-signed)
- TrustZone integrace pro bezpečné uložení klíčů


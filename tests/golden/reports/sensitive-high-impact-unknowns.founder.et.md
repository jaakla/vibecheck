# Vibechecki ülevaatus: mis võib valesti minna ja mida edasi teha

**CareNotes**

> Vibecheck kirjeldab teadaolevaid takistusi konkreetses keskkonnas ja kasutusotstarbes, tuginedes siin kirja pandud tõenditele. See ei ole sertifikaat, see ei väida, et rakendus oleks turvaline, ega ütle kunagi, et rakendus on avaldamiseks valmis.
>
> Kõik alljärgnev kehtib kindlas ulatuses: ühe keskkonna ja kasutusotstarbe kohta tehtud järeldus ei ütle midagi laiema kohta ning üle vaatamata kontroll ei ole korras kontroll.
>
> Teadmata ei tähenda kunagi madalat ega luba edasi minna. See tähendab, et vastamiseks vajalikud tõendid puuduvad.

Ümbrik va-golden-sensitive-high-impact-unknowns, versioon 1, tuletatud 2026-08-16T12:00:00Z.

## Mida hinnati

| — | — |
|---|---|
| Rakendus | CareNotes |
| Mida see teeb | Note-taking app used by a care provider's staff, with a pending decision to open it to client families. |
| Platvorm | lovable+supabase |
| Hinnatud keskkond ja kasutus | privaatne test + kutsepõhine pilootkasutus |
| Vaadeldavad ulatused | privaatne test + kutsepõhine pilootkasutus; avalik väljalase + tundlik või suure mõjuga kasutus |
| Andmed, mida see puudutab | Care notes about identifiable people. Whether they include health details is exactly what nobody has confirmed yet. |
| Konteksti kinnitus | aegunud, arvestatakse kinnitamata kontekstina |
| Konteksti versioon | 1 |
| Kontekst kehtib kuni | 2026-07-01T00:00:00Z |

### Rakenduse kohta kirja pandud faktid

| Küsimus | Vastus | Kuidas teame | Allikas |
|---|---|---|---|
| Kus on rakendus praegu oma elutsüklis? | nimelise rühma pilootkasutuses | omanik kinnitas | founder:lena |
| Kes saab seda täna kasutada ja kui palju neid on? | kuni umbes 200 teadaolevat kasutajat | omanik kinnitas | founder:lena |
| Kust on töötav rakendus kättesaadav? | avalik internet reklaamimata aadressil | tuletatud, mitte kinnitatud | deployment configuration in the repository |
| Mida on kellelgi vaja, et sisse saada? | ainult kutse alusel loodud kontod | tuletatud, mitte kinnitatud | supabase auth settings export |
| Kelle andmed asuvad kelle kõrval? | mitu klienti samades tabelites | omanik kinnitas | founder:lena |
| Millised on kõige tundlikumad andmed, mida see hoiab või puudutab? | tuvastamata | tuvastamata | reviewer |
| Kas rakendus liigutab raha? | tuvastamata | allikad on vastuolus | founder:lena vs repository payment integration |
| Mida saab see teha lisaks oma andmete lugemisele ja kirjutamisele? | sisaldab haldustoiminguid | omanik kinnitas | founder:lena |
| Mis juhtub, kui see lakkab töötamast või käitub valesti? | sellel töötab põhiline äriprotsess | omanik kinnitas | founder:lena |

- The reviewer could not reach the data controller before this revision; the sensitive-data question is open.

## Kus see praegu on

### privaatne test + kutsepõhine pilootkasutus

**hindamine pooleli** — Küsimusele vastamiseks on midagi puudu, seega ei saa seda ulatust lugeda selgeks. Puuduvad osad on loetletud allpool.

*Kontrollnimekirja otsus:* ÜLEVAATUS POOLELI (aligned). The vibecheck_v1 checklist verdict and the readiness state for this scope agree. The verdict is one judgement for the whole application; readiness is scoped to this environment and intended use.

Selle ulatuse kohta kirja pandud olulisi teadmata asju: 6.

*Laiemasse ulatusse liikumine:*

- avalik väljalase + tundlik või suure mõjuga kasutus: hindamine pooleli. Moving to this scope is a separate question with its own answer: incomplete (0 blocker(s), 6 material unknown(s)). Readiness here is not permission to go there.

*Kehtib kuni:* 2026-07-01T00:00:00Z

### avalik väljalase + tundlik või suure mõjuga kasutus

**hindamine pooleli** — Küsimusele vastamiseks on midagi puudu, seega ei saa seda ulatust lugeda selgeks. Puuduvad osad on loetletud allpool.

*Kontrollnimekirja otsus:* ÜLEVAATUS POOLELI (aligned). The vibecheck_v1 checklist verdict and the readiness state for this scope agree. The verdict is one judgement for the whole application; readiness is scoped to this environment and intended use.

Selle ulatuse kohta kirja pandud olulisi teadmata asju: 6.

*Kehtib kuni:* 2026-07-01T00:00:00Z

## Mis võib valesti minna

### 1. Keegi pääseb ligi andmetele, mis ei ole tema omad

Serveripoolne õiguste kontroll on ainus asi, mis eraldab ühe kasutaja kirjeid kõigist teistest. Seal, kus seda ei jõustata, ei ole teiste andmete lugemiseks või muutmiseks vaja mingit rünnakut. Kaalul: tuvastamata. Kättesaadav: kuni umbes 200 teadaolevat kasutajat. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: teadmata. Risk pärast üleminekut ulatusse avalik väljalase + tundlik või suure mõjuga kasutus: teadmata. Teadmata ei tähenda kunagi madalat ega luba edasi minna. See tähendab, et vastamiseks vajalikud tõendid puuduvad.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): teadmata — `rsk-authz.object_level-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + tundlik või suure mõjuga kasutus): teadmata — `rsk-authz.object_level-public_release.sensitive_or_high_impact-event_triggered-r1`

*See tugineb:*

- #13 Kas oled kahe eraldi kontoga kontrollinud, et kasutaja A ei saa kasutaja B andmeid vaadata, muuta ega kustutada? (Puudulik) — `asm-authz.object_level`

*Tõendid:* `ev-object_level-01`

*Olulised teadmata asjad:*

- `unk-private_test.invite_only_pilot-risk.authz.object_level.current` (privaatne test + kutsepõhine pilootkasutus) — Contextual risk for vibecheck.control.authz.object_level is unknown in this scope. Unknown is never low and never permission to proceed.
- `unk-public_release.sensitive_or_high_impact-risk.authz.object_level.event_triggered` (avalik väljalase + tundlik või suure mõjuga kasutus) — Contextual risk for vibecheck.control.authz.object_level is unknown in this scope. Unknown is never low and never permission to proceed.

### 2. Isikuandmed satuvad sinna, kuhu ei tohi

Isikuandmeid kogutakse sageli ilma selge eesmärgita ja kopeeritakse logidesse, analüütikasse või mudeli päringutesse. Kui neid ei saa nõudmisel kustutada, kasvab õiguslik risk iga uue kasutajaga. Kaalul: tuvastamata. Kättesaadav: kuni umbes 200 teadaolevat kasutajat. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: teadmata. Risk pärast üleminekut ulatusse avalik väljalase + tundlik või suure mõjuga kasutus: teadmata. Teadmata ei tähenda kunagi madalat ega luba edasi minna. See tähendab, et vastamiseks vajalikud tõendid puuduvad.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): teadmata — `rsk-privacy.no_pii_leakage-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + tundlik või suure mõjuga kasutus): teadmata — `rsk-privacy.no_pii_leakage-public_release.sensitive_or_high_impact-event_triggered-r1`

*See tugineb:*

- #57 Kas isikuandmed on logidest ja AI-teenusepakkujale saadetavast väljas? (Puudulik) — `asm-privacy.no_pii_leakage`

*Tõendid:* `ev-no_pii_leakage-02`

*Olulised teadmata asjad:*

- `unk-private_test.invite_only_pilot-risk.privacy.no_pii_leakage.current` (privaatne test + kutsepõhine pilootkasutus) — Contextual risk for vibecheck.control.privacy.no_pii_leakage is unknown in this scope. Unknown is never low and never permission to proceed.
- `unk-public_release.sensitive_or_high_impact-risk.privacy.no_pii_leakage.event_triggered` (avalik väljalase + tundlik või suure mõjuga kasutus) — Contextual risk for vibecheck.control.privacy.no_pii_leakage is unknown in this scope. Unknown is never low and never permission to proceed.

## Takistused ja eskaleerimised, mida ei tohi peita

Need punktid näidatakse sõltumata esiplaani piirist. Iga punkt esineb täpselt ühe korra kas siin või mõnes ülalolevas stsenaariumis ning kõik on lisas jälgitavad.

### Lahendamata kriitilised ja kõrge tähtsusega kontrollid

*Kriitiline või kõrge tähtsusega kontroll, mille nõue ei ole täidetud. Kontekstirisk võib selle siin vähem pakiliseks muuta, kuid ei muuda seda täidetuks.*

Selles kategoorias: 2. Ülal stsenaariumina räägitud: 2. Siin loetletud: 0. Mõne muu kohustusliku kategooria all loetletud: 0.

### Teadmata asjad, mis blokeerivad valmisoleku

*Midagi, mis võib takistust varjata, ei ole tuvastatud. Kuni see nii on, ei saa seda ulatust lugeda selgeks.*

Selles kategoorias: 12. Ülal stsenaariumina räägitud: 4. Siin loetletud: 8. Mõne muu kohustusliku kategooria all loetletud: 0.

- `unk-private_test.invite_only_pilot-context.dimensions` (privaatne test + kutsepõhine pilootkasutus) — Context dimensions that feed risk derivation are unknown or conflicting: data_sensitivity, financial_operations. Any risk that needed them came out unknown.
- `unk-private_test.invite_only_pilot-context.expired` (privaatne test + kutsepõhine pilootkasutus) — The application context is past its valid_until and counts as unconfirmed until it is reconfirmed.
- `unk-private_test.invite_only_pilot-controls.unassessed_critical_high` (privaatne test + kutsepõhine pilootkasutus) — 40 applicable Critical or High control(s) have no current assessment. An unreviewed control is not a passing one.
- `unk-private_test.invite_only_pilot-evidence.expired.integ.webhook_signatures` (privaatne test + kutsepõhine pilootkasutus) — Pass on vibecheck.control.integ.webhook_signatures rests only on evidence that has expired; it needs re-verification before it can support this scope (rule R15).
- `unk-public_release.sensitive_or_high_impact-context.dimensions` (avalik väljalase + tundlik või suure mõjuga kasutus) — Context dimensions that feed risk derivation are unknown or conflicting: data_sensitivity, financial_operations. Any risk that needed them came out unknown.
- `unk-public_release.sensitive_or_high_impact-context.expired` (avalik väljalase + tundlik või suure mõjuga kasutus) — The application context is past its valid_until and counts as unconfirmed until it is reconfirmed.
- `unk-public_release.sensitive_or_high_impact-controls.unassessed_critical_high` (avalik väljalase + tundlik või suure mõjuga kasutus) — 40 applicable Critical or High control(s) have no current assessment. An unreviewed control is not a passing one.
- `unk-public_release.sensitive_or_high_impact-evidence.expired.integ.webhook_signatures` (avalik väljalase + tundlik või suure mõjuga kasutus) — Pass on vibecheck.control.integ.webhook_signatures rests only on evidence that has expired; it needs re-verification before it can support this scope (rule R15).

### Intsidendile reageerimine

*Midagi on juba juhtunud ja reageerimine ei ole lõpetatud.*

Selles kategoorias pole midagi.

### Eskaleerimised spetsialistile

*See vajab spetsialisti. Vibecheck ei ole spetsialist ja kontrollnimekiri ammugi mitte.*

Selles kategoorias pole midagi.

### Tähtajad, mis blokeerivad hinnatava kasutuse

*See töö blokeerib hinnatava keskkonna ja kasutusotstarbe või on selle tähtaeg juba möödunud.*

Selles kategoorias pole midagi.

### Sõelumisread, mis vajavad spetsialisti

*Sõelumisrida, mille ülevaataja märkis spetsialisti otsust vajavaks. Sellel ei ole veel planeeritud tegevust.*

Selles kategoorias pole midagi.

## Mida edasi teha

### Vibecheck saab kohe teha

Selles kategoorias pole midagi.

### Sina pead tegema

Selles kategoorias pole midagi.

### Vajab arendajat või spetsialisti

Selles kategoorias pole midagi.

### Võib oodata

Selles kategoorias pole midagi.

## Kindlus ja eeldused

Kindlus tuletatud tasemetes: väike. Mitu kontekstifakti on tuletatud, mitte kinnitatud, või on kontekst aegunud. Enne nendele tasemetele tuginemist tuleks tõendeid koguda.

- authentication = invite_only_accounts is inferred from supabase auth settings export, not confirmed by the owner.
- network_exposure = unlisted_public_url is inferred from deployment configuration in the repository, not confirmed by the owner.
- Customers share one datastore, so a single authorization defect can cross tenants; context model v1 counts that blast radius through audience_scale only.
- Context confirmation state is 'expired': these inputs have not been confirmed by a human with authority over the application.
- This scope is not the one the application is in today, so this level is a floor for the move to public_release, not a measurement of it.
- Entering that scope implies network_exposure of at least 'public_internet'; the captured values are lower and the higher reading was used.

Leidude koondamine lugudeks ei muuda neis midagi: iga kontroll säilitab oma staatuse, raskusastme ja riski aktsepteerimise kirje täpselt sellisena, nagu ülevaataja selle jättis.

## Tehniline lisa

Lisa on ülevaataja algne kirje: iga kontrollnimekirja rida, iga tõend, iga tuletatud risk, iga stsenaarium, iga tegevus ja iga protseduur, olenemata sellest, kas see jõudis ülalolevasse kokkuvõttesse.

### A. Ülevaataja täielik kontrollnimekiri

Tühi staatus tähendab, et rida ei ole üle vaadatud. See erineb teadlikult staatusest Testimata, mis on ülevaataja kirja pandud otsus seda mitte testida.

| # | Kategooria | Kontroll | Raskusaste | Staatus | Hinnang | Tõendid |
|---|---|---|---|---|---|---|
| 1 | 1. Arhitektuuri mõistlikkus | Tehnoloogiavalikud on levinud ja hooldatavad: laialt kasutatud keel, raamistik ja andmebaas, millel on dokumentatsioon, kogukond ja palgatavad arendajad | Kõrge | üle vaatamata | — | — |
| 2 | 1. Arhitektuuri mõistlikkus | Peamine andmehoidla sobib koormuse ja majutusmudeliga: hallatud püsiv andmebaas mitmekasutaja andmetele; mitte SQLite/JSON-fail/localStorage põhihoidlana serverless- või ajutisel majutusel | Kõrge | üle vaatamata | — | — |
| 3 | 1. Arhitektuuri mõistlikkus | Autentimine on tõestatud teenus või teek (Supabase Auth, Firebase, Auth0, NextAuth, Clerk jne); mitte isetehtud parooliräside, sessioonitokenid ega JWT-skeemid | Kõrge | üle vaatamata | — | — |
| 4 | 1. Arhitektuuri mõistlikkus | Keerukus on proportsionaalne probleemiga: MVP jaoks pole enneaegseid mikroteenuseid/järjekordi/orkestratsiooni; pole ühtainsat kõikehoidvat hiidmoodulit | Keskmine | üle vaatamata | — | — |
| 5 | 1. Arhitektuuri mõistlikkus | Üks järjekindel muster iga teema kohta: üks andmeligipääsukiht, üks olekuhalduse viis, üks stiilisüsteem – mitte sessioonide jooksul kuhjunud paralleelsed topeltlahendused | Keskmine | üle vaatamata | — | — |
| 6 | 1. Arhitektuuri mõistlikkus | Majutus vastab käitusvajadustele: pikad tööd, websocketid, cron ja taustatööd on platvormi käitusmudeliga toetatud (ajapiirid, püsivad protsessid) | Keskmine | üle vaatamata | — | — |
| 7 | 2. Saladused ja mandaadid | Eesotsa koodis pole saladuselaadseid väärtusi | Kriitiline | üle vaatamata | — | — |
| 8 | 2. Saladused ja mandaadid | Kliendini ei jõua teenusevõtme-eesliiteid (sk-, AKIA, service_role jne) | Kriitiline | üle vaatamata | — | — |
| 9 | 2. Saladused ja mandaadid | Saladusi pole töökoopias, giti ajaloos ega avalikus ehituspaketis (.env pole versioonihalduses) | Kriitiline | üle vaatamata | — | — |
| 10 | 2. Saladused ja mandaadid | Saladused süstitakse turvaliselt käitusajal; pole koodis/tõmmistes/logides; ligipääs piiratud; rotatsioon toetatud | Kõrge | üle vaatamata | — | — |
| 11 | 2. Saladused ja mandaadid | Iga lekkinud aktiivset mandaati käsitletakse intsidendina: roteeritud, sessioonid tühistatud, logid üle vaadatud, ajaloost eemaldatud | Kriitiline | üle vaatamata | — | — |
| 12 | 3. Volitamine ja ligipääsukontroll | Volitamine jõustatud serveripoolel, vaikimisi keelav | Kriitiline | üle vaatamata | — | — |
| 13 | 3. Volitamine ja ligipääsukontroll | Objektitaseme volitamine: kasutaja ei pääse ligi teiste kasutajate kirjetele (IDOR) | Kriitiline | Puudulik | `asm-authz.object_level` | `ev-object_level-01` |
| 14 | 3. Volitamine ja ligipääsukontroll | Autentimata ehk anonüümsel kasutajal ei tohi olla andmete lugemis- ega kirjutamisõigust, välja arvatud juhul, kui andmed on mõeldud avalikuks. | Kriitiline | üle vaatamata | — | — |
| 15 | 3. Volitamine ja ligipääsukontroll | Üürnikuisolatsioon: pole üürnikevahelist andmeligipääsu | Kriitiline | üle vaatamata | — | — |
| 16 | 3. Volitamine ja ligipääsukontroll | Privilegeeritud/admin-toimingud jõustatud serveripoolel (kriitiline kui admin-funktsioonid on olulised) | Kriitiline | üle vaatamata | — | — |
| 17 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Andmed püsivad tegelikult (kontrollitud andmehoidlas) | Kõrge | üle vaatamata | — | — |
| 18 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Kaitumine vastab dokumenteeritud tootelubadusele; mokid/fikstuurid/varulahendused pole esitatud päris valjundina | Kõrge | üle vaatamata | — | — |
| 19 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | E-kirjad/teavitused päriselt kohale jouavad tootmistingimustes | Keskmine | üle vaatamata | — | — |
| 20 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Maksekonto, võtmed, webhookid JA reziim vastavad kavandatud juurutuskeskkonnale | Kõrge | üle vaatamata | — | — |
| 21 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Failide uleslaadimised jouavad päris salvestusse ja on kattesaadavad | Keskmine | üle vaatamata | — | — |
| 22 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Otsing/filtrid pärivad backendist, mitte karbitud kliendimassiivist | Keskmine | üle vaatamata | — | — |
| 23 | 5. Kulu- ja kuritarvituse mojuala | Kvoodid, kasutajaeelarved, operatsioonipiirid, ajapiirid ja samaegsuse laed tasulisel/LLM-tool | Kõrge | üle vaatamata | — | — |
| 24 | 5. Kulu- ja kuritarvituse mojuala | Ranged eelarvelaed + arveldusteated igal tasulisel teenusepakkujal | Kõrge | üle vaatamata | — | — |
| 25 | 5. Kulu- ja kuritarvituse mojuala | Pole piiramatuid tsukleid / rekursiivseid agendisamme; max-sammud jõustatud | Kõrge | üle vaatamata | — | — |
| 26 | 5. Kulu- ja kuritarvituse mojuala | Kallid endpointid nouavad autentimist; autentimata otsing/paring piiratud | Kõrge | üle vaatamata | — | — |
| 27 | 5. Kulu- ja kuritarvituse mojuala | Paringu-/uleslaadimismahu piirid; e-posti/SMS kuritarvituspiirid; webhook-korduse kaitse | Keskmine | üle vaatamata | — | — |
| 28 | 6. Sisendi kasitlus ja injektsioonid | Serveripoolne valideerimine koigil sisenditel | Kõrge | üle vaatamata | — | — |
| 29 | 6. Sisendi kasitlus ja injektsioonid | Koik paringud kasutavad parameetriseotust / turvalist API-t; toorfragmendid ja dunaamilised identifikaatorid lubatute nimekirjas | Kõrge | üle vaatamata | — | — |
| 30 | 6. Sisendi kasitlus ja injektsioonid | Valjund kodeeritud konteksti jargi; HTML puhastatakse ainult teadlikul lubamisel; ohtlikud URL-skeemid blokeeritud | Kõrge | üle vaatamata | — | — |
| 31 | 6. Sisendi kasitlus ja injektsioonid | Uleslaadimised: sisu/MIME/magic-byte kontroll, path-traversal-kindel, isoleeritud salvestus, juhuslikud nimed | Keskmine | üle vaatamata | — | — |
| 32 | 6. Sisendi kasitlus ja injektsioonid | Muud injektsiooniklassid arvestatud vajadusel: kask, SSRF, mall, path traversal, avatud umbersuunamine, deserialiseerimine | Keskmine | üle vaatamata | — | — |
| 33 | 7. Andmed, migratsioonid, varukoopiad | Skeemimuudatused labi commititud migratsioonide; andmebaasi piirangud, mitte ainult appi valideerimine | Keskmine | üle vaatamata | — | — |
| 34 | 7. Andmed, migratsioonid, varukoopiad | Varukoopiad seadistatud, krüpteeritud, ligipääsupiiratud – ja taaste on päriselt testitud (RPO/RTO teada) | Kõrge | üle vaatamata | — | — |
| 35 | 7. Andmed, migratsioonid, varukoopiad | Prodis pole vaikseid havitavaid migratsioone; tagasi-/edasitaaste plaan olemas | Kõrge | üle vaatamata | — | — |
| 36 | 7. Andmed, migratsioonid, varukoopiad | Kustutussemantika kavandatud: taastatav kus ari vajab, poordumatu kus privaatsus/turve nouab kustutamist | Keskmine | üle vaatamata | — | — |
| 37 | 8. Vead, logimine ja jalgitavus | Pole allaneelatud vigu; turvaotsustel fail-closed | Keskmine | üle vaatamata | — | — |
| 38 | 8. Vead, logimine ja jalgitavus | Veajalgimine kliendil JA serveril; struktureeritud logid; saladused/PII redigeeritud | Keskmine | üle vaatamata | — | — |
| 39 | 8. Vead, logimine ja jalgitavus | Kasutajale ei leki stack trace'e / sisemisi vigu | Kõrge | üle vaatamata | — | — |
| 40 | 8. Vead, logimine ja jalgitavus | Turva- ja peamised aritsundmused logitud; taustatööd/webhookid jalgitavad | Keskmine | üle vaatamata | — | — |
| 41 | 8. Vead, logimine ja jalgitavus | Tervisekontrollid + teavitused omanikuga; monitooring testitud, mitte ainult uhendatud | Madal | üle vaatamata | — | — |
| 42 | 9. Konfiguratsioon ja juurutuskonveier | Debug prodis väljas; paljusonalised vealehed keelatud; avalikus ehituspaketis pole debug-endpointe | Kõrge | üle vaatamata | — | — |
| 43 | 9. Konfiguratsioon ja juurutuskonveier | Prod vs dev/staging konfiguratsioon ja andmed lahus; eelvaate-ehitustes pole prod-saladusi | Kõrge | üle vaatamata | — | — |
| 44 | 9. Konfiguratsioon ja juurutuskonveier | CORS lubab ainult ettenahtud paritolud/meetodid/paised; mandaadiga risttaustale kitsalt piiratud ja testitud | Kõrge | üle vaatamata | — | — |
| 45 | 9. Konfiguratsioon ja juurutuskonveier | Transporditurve: HTTPS + HSTS; apile sobivad turvapaised | Keskmine | üle vaatamata | — | — |
| 46 | 9. Konfiguratsioon ja juurutuskonveier | Tootmise muudatuskontroll: haruskaitse, üle vaadatud muudatused, tagasipoordumine, korratavad artefaktid | Keskmine | üle vaatamata | — | — |
| 47 | 10. Kolmandate osapoolte integratsioonid | Sissetulevad webhookid kontrollivad allkirja + ajatemplit; endpoint keeldub voorastest sundmustuupidest | Kõrge | Korras | `asm-integ.webhook_signatures` | `ev-webhook_signatures-03` |
| 48 | 10. Kolmandate osapoolte integratsioonid | OAuth state/PKCE/nonce valideeritud; redirect-URI-d lukustatud; tokenid krupteeritult hoitud | Keskmine | üle vaatamata | — | — |
| 49 | 10. Kolmandate osapoolte integratsioonid | Minimaalsed skoobid; saladuse elutsukkel kasitletud integratsiooni lahtiuhendamisel | Keskmine | üle vaatamata | — | — |
| 50 | 10. Kolmandate osapoolte integratsioonid | Idempotentsus + kordus/backoff + dead-letter makse-/tellimus-/webhook-kasitlejatel | Kõrge | üle vaatamata | — | — |
| 51 | 11. Sõltuvused ja tarneahel | Käitus- ja ehitussõltuvused inventeeritud ja skannitud; ärakasutatavad leiud triaažeeritud, parandatud või aktsepteeritud | Keskmine | üle vaatamata | — | — |
| 52 | 11. Sõltuvused ja tarneahel | Sõltuvusriski signaalid üle vaadatud | Madal | üle vaatamata | — | — |
| 53 | 11. Sõltuvused ja tarneahel | Lockfile commititud; ehitus korratav; CI-tegevused/konteinerid kinnitatud | Madal | üle vaatamata | — | — |
| 54 | 11. Sõltuvused ja tarneahel | Litsentsid sobivad kavandatud arimudeliga | Madal | üle vaatamata | — | — |
| 55 | 12. Privaatsus ja GDPR | Andmete minimeerimine + andmekaart: mis PII, miks, kus asub, edastused | Keskmine | üle vaatamata | — | — |
| 56 | 12. Privaatsus ja GDPR | Paroole ei salvestata avatekstina; tundlik data krupteeritud; tokenid rasitud | Kriitiline | üle vaatamata | — | — |
| 57 | 12. Privaatsus ja GDPR | PII ei leki logidesse, analuutikasse ega LLM-promptidesse; teenusepakkuja satted üle vaadatud | Kõrge | Puudulik | `asm-privacy.no_pii_leakage` | `ev-no_pii_leakage-02` |
| 58 | 12. Privaatsus ja GDPR | Rahvusvahelise edastuse mehhanism + alltootlejad + asukoht vastuvoetav (andmebaasi regioon JA LLM-marsruut) | Keskmine | üle vaatamata | — | — |
| 59 | 12. Privaatsus ja GDPR | Andmesubjekti õigused toimivad: teade, oiguslik alus, ligipääs, kustutamine, sailitus, rikkekasitlus | Keskmine | üle vaatamata | — | — |
| 60 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Kõrge riski valdkonna soel (Annex III / tooteohutus): olulised otsused inimeste kohta | Sõelumine | üle vaatamata | — | — |
| 61 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Labipaistvuskohustused (Art. 50): sunteetiline/inimeseks-peetav sisu | Sõelumine | üle vaatamata | — | — |
| 62 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Keelatud praktika soel (Art. 5): skoorimine, manipuleerimine, arakasutamine | Sõelumine | üle vaatamata | — | — |
| 63 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Eskaleerimine: spetsialisti ulevaatus kus vastus on jah/ebakindel; roll ja GPAI-kasutus dokumenteeritud | Sõelumine | üle vaatamata | — | — |
| 64 | 14. Korrektsus ja ariloogika | Invariandid + andmebaasi piirangud joustavad pohireeglid; olekumasina uleminekud valideeritud | Kõrge | üle vaatamata | — | — |
| 65 | 14. Korrektsus ja ariloogika | Samaaegsuskindel: idempotentsus, optimistlik samaaegsus, tehingupiirid | Kõrge | üle vaatamata | — | — |
| 66 | 14. Korrektsus ja ariloogika | Raha/maks/valuuta: taisarv/kumnend, umardusreeglid, lokaadi kasitlus | Kõrge | üle vaatamata | — | — |
| 67 | 14. Korrektsus ja ariloogika | Kuupaevad/ajavoondid/suveaeg kasitletud eksplitsiitselt | Keskmine | üle vaatamata | — | — |
| 68 | 14. Korrektsus ja ariloogika | Õiguste muutused keset sessiooni joustuvad; poordumatud toimingud on auditeeritavad | Keskmine | üle vaatamata | — | — |
| 69 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Automaattestid pohilisele aritehingule ja havitavatele toimingutele | Kõrge | üle vaatamata | — | — |
| 70 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Automaattestid autentimisele + volitamisele/rentniku eraldusele | Kõrge | üle vaatamata | — | — |
| 71 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Automaattestid makse-/webhook-kasitlusele kui olemas; juurutuse kaivitus/tervis | Keskmine | üle vaatamata | — | — |
| 72 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Deterministlikud/omadus-pohised testid keerukatele kriitilistele arvutustele | Madal | üle vaatamata | — | — |
| 73 | 16. Joudlus (mitte turvaskoor) | Serveripoolsed lehekulje-piirid; max eksport/raport; päringu ajapiirid | Keskmine | üle vaatamata | — | — |
| 74 | 16. Joudlus (mitte turvaskoor) | Esinduslikel tootmisparingutel on vastuvoetav latents; vajalikud indeksid olemas ja kasutuses | Madal | üle vaatamata | — | — |
| 75 | 16. Joudlus (mitte turvaskoor) | Uhenduse/pooli piirid; puhvri korrektsus; sujuv taandumine teenusepakkuja piiridel | Madal | üle vaatamata | — | — |
| 76 | 16. Joudlus (mitte turvaskoor) | Frontend-paketi suurus / kulmkaivitus sihtmargi piires | Madal | üle vaatamata | — | — |
| 77 | 17. AI turvalisus (prompt-injektsioon ja agendid) | LLM väljund ei jou exec/eval/shell/SQL-sihtmarki ilma valideerimise/skeemita | Kriitiline | üle vaatamata | — | — |
| 78 | 17. AI turvalisus (prompt-injektsioon ja agendid) | Ebausaldusvaarne sisu on eraldatud ja margitud andmena; ei saa muuta usaldatud juhiseid/õigusi | Kõrge | üle vaatamata | — | — |
| 79 | 17. AI turvalisus (prompt-injektsioon ja agendid) | Tööriistakutse volitus tugineb autenditud kasutajale, mitte mudeli väljundile; suure mõjuga toimingud nõuavad inimkinnitust | Kõrge | üle vaatamata | — | — |
| 80 | 17. AI turvalisus (prompt-injektsioon ja agendid) | Ebausaldusvaarne valine/RAG-sisu kasitletud andmena; päringu ACL-id levivad | Keskmine | üle vaatamata | — | — |
| 81 | 17. AI turvalisus (prompt-injektsioon ja agendid) | LLM väljund renderdatud tekstina või puhastatud; malu isoleeritud kasutajate vahel | Keskmine | üle vaatamata | — | — |
| 82 | 18. Omand, jarjepidevus ja kasutatavus | Jarjepidevus: keegi peale algse ehitaja paaseb ligi, juurutab, taastab ja hooldab rakendust | Kõrge | üle vaatamata | — | — |
| 83 | 18. Omand, jarjepidevus ja kasutatavus | Kontode omand: domeen, majutus, DB, e-post, makse ja AI-teenused kuuluvad sulle/su ettevottele | Kõrge | üle vaatamata | — | — |
| 84 | 18. Omand, jarjepidevus ja kasutatavus | Andmete eksport: olulised ari- ja kasutajaandmed saab eksportida kasutatavas vormingus | Keskmine | üle vaatamata | — | — |
| 85 | 18. Omand, jarjepidevus ja kasutatavus | Toorke- ja taastekaitumine: vea korral nadab selge teate ega kaota/dubleeri andmeid | Keskmine | üle vaatamata | — | — |
| 86 | 18. Omand, jarjepidevus ja kasutatavus | Toe tee: kasutajatel on toimiv viis probleemist teatada ja keegi saab selle katte | Madal | üle vaatamata | — | — |
| 87 | 18. Omand, jarjepidevus ja kasutatavus | Tooteanaluutika: naed, kas peamine tee onnestub / kus kasutajad loobuvad, ilma liigse PII-ta | Madal | üle vaatamata | — | — |
| 88 | 18. Omand, jarjepidevus ja kasutatavus | Seadmeulene: peamine voog testitud päris telefonis ja vahemalt kahes levinud brauseris | Madal | üle vaatamata | — | — |
| 89 | 18. Omand, jarjepidevus ja kasutatavus | Pohiligipaasetavus: peamine voog kasutatav klaviatuuriga, loetava tekstiga ja selgete siltidega | Madal | üle vaatamata | — | — |

### B. Tõendid

| Tõendid | Allikas | Objekt | Suund | Tugevus | Vaadeldud | Kehtib kuni | Mida katab ja mida mitte |
|---|---|---|---|---|---|---|---|
| `ev-no_pii_leakage-02` | vibecheck.sh static scanner | repo . | lükkab ümber | viitav | 2026-08-16T11:00:00Z | 2026-09-15T12:00:00Z | Current working tree only, rulesets llm.prompt_pii and obs.log_pii. Matches in api/summarize.js and lib/logger.js. |
| `ev-object_level-01` | vibecheck supabase probe | table public.notes | lükkab ümber | otsustav oma ulatuses | 2026-08-16T11:00:00Z | 2026-09-15T12:00:00Z | Account B read one known record owned by account A in public.notes. Decisive for that record; it is not proof for other tables or operations. |
| `ev-webhook_signatures-03` | reviewer, code walkthrough | endpoint POST /api/webhooks/provider | toetab | viitav | 2026-04-01T10:00:00Z | 2026-05-01T00:00:00Z | The handler as it stood on 1 April 2026, read end to end with the developer. |

### C. Kontekstiriskid

| Risk | Kontroll | Valdkond | Ulatus | Ajahorisont | Mõju | Avatus | Tase | Kindlus |
|---|---|---|---|---|---|---|---|---|
| `rsk-authz.object_level-private_test.invite_only_pilot-current-r1` | `vibecheck.control.authz.object_level` | turve | privaatne test + kutsepõhine pilootkasutus | täna | unknown | plausible | teadmata | väike |
| `rsk-authz.object_level-public_release.sensitive_or_high_impact-event_triggered-r1` | `vibecheck.control.authz.object_level` | turve | avalik väljalase + tundlik või suure mõjuga kasutus | tuleviku ülemineku korral | unknown | expected | teadmata | väike |
| `rsk-privacy.no_pii_leakage-private_test.invite_only_pilot-current-r1` | `vibecheck.control.privacy.no_pii_leakage` | privaatsus | privaatne test + kutsepõhine pilootkasutus | täna | unknown | plausible | teadmata | väike |
| `rsk-privacy.no_pii_leakage-public_release.sensitive_or_high_impact-event_triggered-r1` | `vibecheck.control.privacy.no_pii_leakage` | privaatsus | avalik väljalase + tundlik või suure mõjuga kasutus | tuleviku ülemineku korral | unknown | expected | teadmata | väike |

### D. Stsenaariumide jälgitavus

| Järjekoht | Stsenaarium | Pealkiri | Esiplaanil | Risk täna | Risk hiljem | Kontrolli ID | Hinnang | Risk | Tõendid | Tegevus | Protseduur |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `scn-unauthorised_data_access` | Keegi pääseb ligi andmetele, mis ei ole tema omad | jah | teadmata | teadmata | `vibecheck.control.authz.object_level` | `asm-authz.object_level` | `rsk-authz.object_level-private_test.invite_only_pilot-current-r1`, `rsk-authz.object_level-public_release.sensitive_or_high_impact-event_triggered-r1` | `ev-object_level-01` | — | — |
| 2 | `scn-personal_data_misuse` | Isikuandmed satuvad sinna, kuhu ei tohi | jah | teadmata | teadmata | `vibecheck.control.privacy.no_pii_leakage` | `asm-privacy.no_pii_leakage` | `rsk-privacy.no_pii_leakage-private_test.invite_only_pilot-current-r1`, `rsk-privacy.no_pii_leakage-public_release.sensitive_or_high_impact-event_triggered-r1` | `ev-no_pii_leakage-02` | — | — |

### E. Tegevused

| Tegevus | Liik | Nõutav tulemus | Vastutaja | Prioriteet | Kiireloomulisus | Millal | Seis | Blokeerib | Kontrolli ID | Risk | Stsenaarium | Protseduur | Mis selle sulgeb |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|

### F. Protseduurid

| Protseduur | Pealkiri | Täitja | Täitmisviis | Mehhanism | Nõusolek | Võrguühendus | Mõjud | Pärandvaade | Mis selle sulgeb |
|---|---|---|---|---|---|---|---|---|---|

### G. Protseduuri katsed

| Katse | Tegevus | Protseduur | Keskkond | Tulemus | Nõusolek | Mõjud | Tagasipööre | Tõendid | Uushinnang |
|---|---|---|---|---|---|---|---|---|---|

### H. Metoodika ja versioonid

| Metoodika | Versioon |
|---|---|
| vibecheck.assessment | 1.6.0 |
| vibecheck_v1 | 2026.08 |
| vibecheck.controls | 1.0.0 |
| vibecheck.action_registry | 1.0.0 |
| vibecheck.risk_derivation | 1.0.0 |
| vibecheck.readiness | 1.0.0 |
| vibecheck.report_derivation | 1.1.0 |
| vibecheck.report | 1.1.0 |
| vibecheck.action_policy | 1.1.0 |
| vibecheck.report_wording | 1.1.0 |

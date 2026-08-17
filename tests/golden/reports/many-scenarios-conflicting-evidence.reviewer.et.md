# Vibechecki hinnang: valmisolek konkreetses ulatuses, kontekstirisk ja tõendid

**Northstar Pilot**

> Vibecheck kirjeldab teadaolevaid takistusi konkreetses keskkonnas ja kasutusotstarbes, tuginedes siin kirja pandud tõenditele. See ei ole sertifikaat, see ei väida, et rakendus oleks turvaline, ega ütle kunagi, et rakendus on avaldamiseks valmis.
>
> Kõik alljärgnev kehtib kindlas ulatuses: ühe keskkonna ja kasutusotstarbe kohta tehtud järeldus ei ütle midagi laiema kohta ning üle vaatamata kontroll ei ole korras kontroll.
>
> Teadmata ei tähenda kunagi madalat ega luba edasi minna. See tähendab, et vastamiseks vajalikud tõendid puuduvad.

Ümbrik va-golden-many-scenarios, versioon 1, tuletatud 2026-08-16T12:00:00Z.

## Mida hinnati

| — | — |
|---|---|
| Rakendus | Northstar Pilot |
| Mida see teeb | An invite-only order and support assistant intended to become a public product. |
| Platvorm | react+supabase+stripe+llm |
| Hinnatud keskkond ja kasutus | privaatne test + kutsepõhine pilootkasutus |
| Vaadeldavad ulatused | privaatne test + kutsepõhine pilootkasutus; avalik väljalase + avalik toode |
| Andmed, mida see puudutab | Names, email addresses, order history, support messages and hosted-checkout payment references for named pilot users. |
| Konteksti kinnitus | inimene on üle vaadanud ja kinnitanud |
| Konteksti versioon | 1 |
| Kontekst kehtib kuni | 2026-11-16T00:00:00Z |
| Konteksti sõrmejälg | `sha256:ce517e995324dbbadf384eea10c8ccffbd4176070580c6b7c74a567ee595e626` |
| Ülevaadatud lähtekoodi sõrmejälg | `sha256:6f4e8a2c0d1b39587766554433221100ffeeddccbbaa99887766554433221100` |

### Rakenduse kohta kirja pandud faktid

| Küsimus | Vastus | Kuidas teame | Allikas |
|---|---|---|---|
| Kus on rakendus praegu oma elutsüklis? | nimelise rühma pilootkasutuses | omanik kinnitas | founder:liis |
| Kes saab seda täna kasutada ja kui palju neid on? | kuni umbes 20 nimeliselt teadaolevat inimest | omanik kinnitas | founder:liis |
| Kust on töötav rakendus kättesaadav? | avalik internet reklaamimata aadressil | omanik kinnitas | founder:liis |
| Mida on kellelgi vaja, et sisse saada? | ainult kutse alusel loodud kontod | omanik kinnitas | founder:liis |
| Kelle andmed asuvad kelle kõrval? | mitu klienti samades tabelites | omanik kinnitas | founder:liis |
| Millised on kõige tundlikumad andmed, mida see hoiab või puudutab? | tuvastatavate inimeste isikuandmed | omanik kinnitas | founder:liis |
| Kas rakendus liigutab raha? | maksed, väljamaksed või mõõdetud kulu | omanik kinnitas | founder:liis |
| Mida saab see teha lisaks oma andmete lugemisele ja kirjutamisele? | toimib välistes süsteemides: e-post, maksed, kolmandate osapoolte liidesed | omanik kinnitas | founder:liis |
| Mis juhtub, kui see lakkab töötamast või käitub valesti? | kasulik, kuid töö saab ka ilma jätkuda | omanik kinnitas | founder:liis |

## Kus see praegu on

### privaatne test + kutsepõhine pilootkasutus

**blokeeritud** — Selle keskkonna ja kasutusotstarbe jaoks on teadaolev takistus. See on koos aluseks olevaga loetletud allpool.

*Kontrollnimekirja otsus:* BLOKEERI (aligned). The vibecheck_v1 checklist verdict and the readiness state for this scope agree. The verdict is one judgement for the whole application; readiness is scoped to this environment and intended use.

*Takistused:*

- `rsk-authz.object_level-private_test.invite_only_pilot-current-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.authz.object_level (assessment status: fail)
- `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1` — High contextual financial risk in this scope for unresolved control(s) vibecheck.control.cost.budget_caps (assessment status: fail)
- `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.llm.untrusted_content_isolation (assessment status: fail)
- `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.secrets.no_repo_history_leaks (assessment status: fail)

*Laiemasse ulatusse liikumine:*

- avalik väljalase + avalik toode: blokeeritud. Moving to this scope is a separate question with its own answer: blocked (10 blocker(s), 0 material unknown(s)). Readiness here is not permission to go there.

*Kehtib kuni:* 2026-09-15T12:00:00Z

### avalik väljalase + avalik toode

**blokeeritud** — Selle keskkonna ja kasutusotstarbe jaoks on teadaolev takistus. See on koos aluseks olevaga loetletud allpool.

*Kontrollnimekirja otsus:* BLOKEERI (aligned). The vibecheck_v1 checklist verdict and the readiness state for this scope agree. The verdict is one judgement for the whole application; readiness is scoped to this environment and intended use.

*Takistused:*

- `act-contain-cross-account-incident` — Open incident_response action whose blocking scope covers this environment and intended use: Contain the cross-account order exposure and determine which records were accessed.
- `act-verify-error-paths` — Open verify action whose blocking scope covers this environment and intended use: Collect a bounded error-path inventory for the developer to instrument.
- `act-decide-support-data` — Open decide action whose blocking scope covers this environment and intended use: Decide and document which order fields the support assistant is allowed to receive.
- `rsk-authz.object_level-public_release.public_product-event_triggered-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.authz.object_level (assessment status: fail)
- `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1` — Critical contextual financial risk in this scope for unresolved control(s) vibecheck.control.cost.budget_caps (assessment status: fail)
- `rsk-data.tested_backups-public_release.public_product-event_triggered-r1` — Critical contextual reliability risk in this scope for unresolved control(s) vibecheck.control.data.tested_backups (assessment status: fail)
- `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.llm.untrusted_content_isolation (assessment status: fail)
- `rsk-obs.error_tracking-public_release.public_product-event_triggered-r1` — High contextual reliability risk in this scope for unresolved control(s) vibecheck.control.obs.error_tracking (assessment status: fail)
- `rsk-privacy.data_minimisation-public_release.public_product-event_triggered-r1` — High contextual privacy risk in this scope for unresolved control(s) vibecheck.control.privacy.data_minimisation (assessment status: fail)
- `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1` — Critical contextual security risk in this scope for unresolved control(s) vibecheck.control.secrets.no_repo_history_leaks (assessment status: fail)

*Kehtib kuni:* 2026-09-15T12:00:00Z

## Mis võib valesti minna

### 1. Võti, mida saab kasutada ka keegi teine

Salajane võti, mis on jõudnud brauserisse, koodihoidlasse või logisse, on kasutatav igaühele, kes selle leiab, koos kõigi õigustega, milleks see väljastati. Muud viga selleks vaja ei ole. Kaalul: tuvastatavate inimeste isikuandmed. Kättesaadav: kuni umbes 20 nimeliselt teadaolevat inimest. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: kriitiline. Risk pärast üleminekut ulatusse avalik väljalase + avalik toode: kriitiline.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): kriitiline — `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + avalik toode): kriitiline — `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1`

*See tugineb:*

- #9 Saladusi pole töökoopias, giti ajaloos ega avalikus ehituspaketis (.env pole versioonihalduses) (Puudulik) — `asm-secrets.no_repo_history_leaks` `vibecheck.control.secrets.no_repo_history_leaks`
  - A provider credential is committed in the current branch.

*Tõendid:* `ev-no_repo_history_leaks-02`

### 2. Keegi pääseb ligi andmetele, mis ei ole tema omad

Serveripoolne õiguste kontroll on ainus asi, mis eraldab ühe kasutaja kirjeid kõigist teistest. Seal, kus seda ei jõustata, ei ole teiste andmete lugemiseks või muutmiseks vaja mingit rünnakut. Kaalul: tuvastatavate inimeste isikuandmed. Kättesaadav: kuni umbes 20 nimeliselt teadaolevat inimest. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: kriitiline. Risk pärast üleminekut ulatusse avalik väljalase + avalik toode: kriitiline.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): kriitiline — `rsk-authz.object_level-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + avalik toode): kriitiline — `rsk-authz.object_level-public_release.public_product-event_triggered-r1`

*See tugineb:*

- #13 Objektitaseme volitamine: kasutaja ei pääse ligi teiste kasutajate kirjetele (IDOR) (Puudulik) — `asm-authz.object_level` `vibecheck.control.authz.object_level`
  - A second pilot account retrieved the first account's order by changing the order id.
  - *Vastuolulised tõendid* `ev-object-level-support` — *Lahendus:* The code shape is only indicative; the scoped live cross-account result decides this assessment.

*Tõendid:* `ev-object-level-support`, `ev-object_level-01`

*Järgmised sammud:*

- **Paranda kohe** `act-contain-cross-account-incident` — Contain the cross-account order exposure and determine which records were accessed.

### 3. Tehisaru pannakse sinu vastu töötama

Tekst, mida mudel loeb, on mitteusaldusväärne sisend. Seal, kus mudeli väljund jõuab tööriista, käsureale või andmebaasi, juhib rakendust see, kes selle teksti kirjutas. Kaalul: tuvastatavate inimeste isikuandmed. Kättesaadav: kuni umbes 20 nimeliselt teadaolevat inimest. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: kriitiline. Risk pärast üleminekut ulatusse avalik väljalase + avalik toode: kriitiline.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): kriitiline — `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + avalik toode): kriitiline — `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1`

*See tugineb:*

- #78 Ebausaldusvaarne sisu on eraldatud ja margitud andmena; ei saa muuta usaldatud juhiseid/õigusi (Puudulik) — `asm-llm.untrusted_content_isolation` `vibecheck.control.llm.untrusted_content_isolation`
  - Customer messages and operator instructions are concatenated into one prompt without a trust boundary.

*Tõendid:* `ev-untrusted_content_isolation-07`

### 4. Arve kasvab kontrolli alt välja või ajab selle üles keegi teine

Piiramatu töö tasulise teenusepakkuja juures muudab hooletu kasutaja, lõputu tsükli või roboti arveks. Ilma ülempiiride ja teavitusteta ei märka keegi midagi enne arvet või katkestust. Kaalul: tuvastatavate inimeste isikuandmed. Kättesaadav: kuni umbes 20 nimeliselt teadaolevat inimest. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: kõrge. Risk pärast üleminekut ulatusse avalik väljalase + avalik toode: kriitiline.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): kõrge — `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + avalik toode): kriitiline — `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1`

*See tugineb:*

- #24 Ranged eelarvelaed + arveldusteated igal tasulisel teenusepakkujal (Puudulik) — `asm-cost.budget_caps` `vibecheck.control.cost.budget_caps`
  - The metered model account has no monthly or per-user cap.

*Tõendid:* `ev-budget_caps-03`

### 5. Andmed kaovad ja neid ei saa tagasi

Andmed, mida ei ole kunagi varukoopiast taastatud, on ettevõttel olemas ainult eeldatavalt. Hävitav migratsioon või kogemata kustutamine on koht, kus seda eeldust proovile pannakse. Kaalul: tuvastatavate inimeste isikuandmed. Kättesaadav: kuni umbes 20 nimeliselt teadaolevat inimest. Risk täna, ulatuses privaatne test + kutsepõhine pilootkasutus: keskmine. Risk pärast üleminekut ulatusse avalik väljalase + avalik toode: kriitiline.

- **Risk täna** (privaatne test + kutsepõhine pilootkasutus): keskmine — `rsk-data.tested_backups-private_test.invite_only_pilot-current-r1`
- **Risk hiljem** (avalik väljalase + avalik toode): kriitiline — `rsk-data.tested_backups-public_release.public_product-event_triggered-r1`

*See tugineb:*

- #34 Varukoopiad seadistatud, krüpteeritud, ligipääsupiiratud – ja taaste on päriselt testitud (RPO/RTO teada) (Puudulik) — `asm-data.tested_backups` `vibecheck.control.data.tested_backups`
  - No restore has ever been attempted from the database backups.

*Tõendid:* `ev-tested_backups-04`

Ülal on näidatud ainult kõrgeima järjekohaga stsenaariumid. Kõik, mis jäi allapoole piiri, säilitab oma kontrollid, hinnangud, tõendid, riskid, tegevused ja protseduurid lisas ning kõik, mida ei tohi peita, on täies mahus korratud järgmises osas.

## Takistused ja eskaleerimised, mida ei tohi peita

Need punktid näidatakse sõltumata esiplaani piirist. Iga punkt esineb täpselt ühe korra kas siin või mõnes ülalolevas stsenaariumis ning kõik on lisas jälgitavad.

### Lahendamata kriitilised ja kõrge tähtsusega kontrollid

*Kriitiline või kõrge tähtsusega kontroll, mille nõue ei ole täidetud. Kontekstirisk võib selle siin vähem pakiliseks muuta, kuid ei muuda seda täidetuks.*

Selles kategoorias: 5. Ülal stsenaariumina räägitud: 5. Siin loetletud: 0. Mõne muu kohustusliku kategooria all loetletud: 0.

### Teadmata asjad, mis blokeerivad valmisoleku

*Midagi, mis võib takistust varjata, ei ole tuvastatud. Kuni see nii on, ei saa seda ulatust lugeda selgeks.*

Selles kategoorias pole midagi.

### Intsidendile reageerimine

*Midagi on juba juhtunud ja reageerimine ei ole lõpetatud.*

Selles kategoorias: 1. Ülal stsenaariumina räägitud: 1. Siin loetletud: 0. Mõne muu kohustusliku kategooria all loetletud: 0.

### Eskaleerimised spetsialistile

*See vajab spetsialisti. Vibecheck ei ole spetsialist ja kontrollnimekiri ammugi mitte.*

Selles kategoorias: 1. Ülal stsenaariumina räägitud: 1. Siin loetletud: 0. Mõne muu kohustusliku kategooria all loetletud: 0.

### Tähtajad, mis blokeerivad hinnatava kasutuse

*See töö blokeerib hinnatava keskkonna ja kasutusotstarbe või on selle tähtaeg juba möödunud.*

Selles kategoorias: 3. Ülal stsenaariumina räägitud: 1. Siin loetletud: 2. Mõne muu kohustusliku kategooria all loetletud: 0.

- `act-decide-support-data` **Enne avalikku väljalaset** — Decide and document which order fields the support assistant is allowed to receive. (omanik)
- `act-verify-error-paths` **Enne avalikku väljalaset** — Collect a bounded error-path inventory for the developer to instrument. (arendaja)

### Sõelumisread, mis vajavad spetsialisti

*Sõelumisrida, mille ülevaataja märkis spetsialisti otsust vajavaks. Sellel ei ole veel planeeritud tegevust.*

Selles kategoorias pole midagi.

## Mida edasi teha

### Vibecheck saab kohe teha

- **Enne avalikku väljalaset** — Collect a bounded error-path inventory for the developer to instrument. `act-verify-error-paths`
  - *Miks:* The current scan shows no monitored error path.
  - *Vastutaja:* arendaja · *Seis:* avatud
  - *Mis selle sulgeb:* The inventory names every reviewed server error path and its current handling.
  - *Blokeerib:* avalik väljalase + avalik toode
  - *Võimalikud protseduurid:* `prc-inventory-error-paths`

### Sina pead tegema

- **Enne avalikku väljalaset** — Decide and document which order fields the support assistant is allowed to receive. `act-decide-support-data`
  - *Miks:* The owner must define the minimum necessary data before the code can enforce it.
  - *Vastutaja:* omanik · *Seis:* avatud
  - *Mis selle sulgeb:* A reviewed field allowlist and retention statement are recorded.
  - *Blokeerib:* avalik väljalase + avalik toode

### Vajab arendajat või spetsialisti

- **Paranda kohe** — Contain the cross-account order exposure and determine which records were accessed. `act-contain-cross-account-incident`
  - *Miks:* The authorized test demonstrated access across account boundaries.
  - *Vastutaja:* spetsialist · *Seis:* avatud
  - *Mis selle sulgeb:* Access is denied in a repeated two-account test, affected access is reviewed, and the control is reassessed.
  - *Blokeerib:* avalik väljalase + avalik toode
  - *Võimalikud protseduurid:* `prc-contain-cross-account-incident`

### Võib oodata

- **Ootenimekiri** — Refactor the test-data helper when the next test suite cleanup is scheduled. `act-refactor-test-helper`
  - *Miks:* The helper is awkward but does not block any assessed scope.
  - *Vastutaja:* arendaja · *Seis:* avatud
  - *Mis selle sulgeb:* The helper has focused tests and no duplicated setup.

## Kindlus ja eeldused

Kindlus tuletatud tasemetes: suur. Kõik kontekstifaktid, millest need tasemed sõltuvad, on kinnitanud inimene, kellel on rakenduse üle otsustusõigus.

- Customers share one datastore, so a single authorization defect can cross tenants; context model v1 counts that blast radius through audience_scale only.
- This scope is not the one the application is in today, so this level is a floor for the move to public_release, not a measurement of it.
- Entering that scope implies audience_scale of at least 'open_small'; authentication of at least 'open_signup'; network_exposure of at least 'public_internet'; the captured values are lower and the higher reading was used.

Leidude koondamine lugudeks ei muuda neis midagi: iga kontroll säilitab oma staatuse, raskusastme ja riski aktsepteerimise kirje täpselt sellisena, nagu ülevaataja selle jättis.

## Tehniline lisa

Lisa on ülevaataja algne kirje: iga kontrollnimekirja rida, iga tõend, iga tuletatud risk, iga stsenaarium, iga tegevus ja iga protseduur, olenemata sellest, kas see jõudis ülalolevasse kokkuvõttesse.

### A. Ülevaataja täielik kontrollnimekiri

Tühi staatus tähendab, et rida ei ole üle vaadatud. See erineb teadlikult staatusest Testimata, mis on ülevaataja kirja pandud otsus seda mitte testida.

| # | Kategooria | Kontroll | Raskusaste | Staatus | Hinnang | Tõendid |
|---|---|---|---|---|---|---|
| 1 | 1. Arhitektuuri mõistlikkus | Tehnoloogiavalikud on levinud ja hooldatavad: laialt kasutatud keel, raamistik ja andmebaas, millel on dokumentatsioon, kogukond ja palgatavad arendajad | Kõrge | Korras | `asm-arch.mainstream_stack` | `ev-baseline-review` |
| 2 | 1. Arhitektuuri mõistlikkus | Peamine andmehoidla sobib koormuse ja majutusmudeliga: hallatud püsiv andmebaas mitmekasutaja andmetele; mitte SQLite/JSON-fail/localStorage põhihoidlana serverless- või ajutisel majutusel | Kõrge | Korras | `asm-arch.datastore_fit` | `ev-baseline-review` |
| 3 | 1. Arhitektuuri mõistlikkus | Autentimine on tõestatud teenus või teek (Supabase Auth, Firebase, Auth0, NextAuth, Clerk jne); mitte isetehtud parooliräside, sessioonitokenid ega JWT-skeemid | Kõrge | Korras | `asm-arch.proven_auth_provider` | `ev-baseline-review` |
| 4 | 1. Arhitektuuri mõistlikkus | Keerukus on proportsionaalne probleemiga: MVP jaoks pole enneaegseid mikroteenuseid/järjekordi/orkestratsiooni; pole ühtainsat kõikehoidvat hiidmoodulit | Keskmine | üle vaatamata | — | — |
| 5 | 1. Arhitektuuri mõistlikkus | Üks järjekindel muster iga teema kohta: üks andmeligipääsukiht, üks olekuhalduse viis, üks stiilisüsteem – mitte sessioonide jooksul kuhjunud paralleelsed topeltlahendused | Keskmine | üle vaatamata | — | — |
| 6 | 1. Arhitektuuri mõistlikkus | Majutus vastab käitusvajadustele: pikad tööd, websocketid, cron ja taustatööd on platvormi käitusmudeliga toetatud (ajapiirid, püsivad protsessid) | Keskmine | üle vaatamata | — | — |
| 7 | 2. Saladused ja mandaadid | Eesotsa koodis pole saladuselaadseid väärtusi | Kriitiline | Korras | `asm-secrets.no_frontend_literals` | `ev-baseline-review` |
| 8 | 2. Saladused ja mandaadid | Kliendini ei jõua teenusevõtme-eesliiteid (sk-, AKIA, service_role jne) | Kriitiline | Korras | `asm-secrets.no_client_provider_keys` | `ev-baseline-review` |
| 9 | 2. Saladused ja mandaadid | Saladusi pole töökoopias, giti ajaloos ega avalikus ehituspaketis (.env pole versioonihalduses) | Kriitiline | Puudulik | `asm-secrets.no_repo_history_leaks` | `ev-no_repo_history_leaks-02` |
| 10 | 2. Saladused ja mandaadid | Saladused süstitakse turvaliselt käitusajal; pole koodis/tõmmistes/logides; ligipääs piiratud; rotatsioon toetatud | Kõrge | Korras | `asm-secrets.secure_runtime_injection` | `ev-baseline-review` |
| 11 | 2. Saladused ja mandaadid | Iga lekkinud aktiivset mandaati käsitletakse intsidendina: roteeritud, sessioonid tühistatud, logid üle vaadatud, ajaloost eemaldatud | Kriitiline | Korras | `asm-secrets.leak_incident_response` | `ev-baseline-review` |
| 12 | 3. Volitamine ja ligipääsukontroll | Volitamine jõustatud serveripoolel, vaikimisi keelav | Kriitiline | Korras | `asm-authz.server_side_default_deny` | `ev-baseline-review` |
| 13 | 3. Volitamine ja ligipääsukontroll | Objektitaseme volitamine: kasutaja ei pääse ligi teiste kasutajate kirjetele (IDOR) | Kriitiline | Puudulik | `asm-authz.object_level` | `ev-object_level-01` |
| 14 | 3. Volitamine ja ligipääsukontroll | Autentimata ehk anonüümsel kasutajal ei tohi olla andmete lugemis- ega kirjutamisõigust, välja arvatud juhul, kui andmed on mõeldud avalikuks. | Kriitiline | Korras | `asm-authz.anon_data_access` | `ev-baseline-review` |
| 15 | 3. Volitamine ja ligipääsukontroll | Üürnikuisolatsioon: pole üürnikevahelist andmeligipääsu | Kriitiline | Korras | `asm-authz.tenant_isolation` | `ev-baseline-review` |
| 16 | 3. Volitamine ja ligipääsukontroll | Privilegeeritud/admin-toimingud jõustatud serveripoolel (kriitiline kui admin-funktsioonid on olulised) | Kriitiline | Korras | `asm-authz.admin_actions_server_side` | `ev-baseline-review` |
| 17 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Andmed püsivad tegelikult (kontrollitud andmehoidlas) | Kõrge | Korras | `asm-product.data_persistence` | `ev-baseline-review` |
| 18 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Kaitumine vastab dokumenteeritud tootelubadusele; mokid/fikstuurid/varulahendused pole esitatud päris valjundina | Kõrge | Korras | `asm-product.no_mocked_output` | `ev-baseline-review` |
| 19 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | E-kirjad/teavitused päriselt kohale jouavad tootmistingimustes | Keskmine | üle vaatamata | — | — |
| 20 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Maksekonto, võtmed, webhookid JA reziim vastavad kavandatud juurutuskeskkonnale | Kõrge | Korras | `asm-product.payment_mode_match` | `ev-baseline-review` |
| 21 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Failide uleslaadimised jouavad päris salvestusse ja on kattesaadavad | Keskmine | üle vaatamata | — | — |
| 22 | 4. Tootevalmidus - kas päris? (mitte turvaskoor) | Otsing/filtrid pärivad backendist, mitte karbitud kliendimassiivist | Keskmine | üle vaatamata | — | — |
| 23 | 5. Kulu- ja kuritarvituse mojuala | Kvoodid, kasutajaeelarved, operatsioonipiirid, ajapiirid ja samaegsuse laed tasulisel/LLM-tool | Kõrge | Korras | `asm-cost.usage_quotas` | `ev-baseline-review` |
| 24 | 5. Kulu- ja kuritarvituse mojuala | Ranged eelarvelaed + arveldusteated igal tasulisel teenusepakkujal | Kõrge | Puudulik | `asm-cost.budget_caps` | `ev-budget_caps-03` |
| 25 | 5. Kulu- ja kuritarvituse mojuala | Pole piiramatuid tsukleid / rekursiivseid agendisamme; max-sammud jõustatud | Kõrge | Korras | `asm-cost.bounded_agent_loops` | `ev-baseline-review` |
| 26 | 5. Kulu- ja kuritarvituse mojuala | Kallid endpointid nouavad autentimist; autentimata otsing/paring piiratud | Kõrge | Korras | `asm-cost.expensive_endpoints_auth` | `ev-baseline-review` |
| 27 | 5. Kulu- ja kuritarvituse mojuala | Paringu-/uleslaadimismahu piirid; e-posti/SMS kuritarvituspiirid; webhook-korduse kaitse | Keskmine | üle vaatamata | — | — |
| 28 | 6. Sisendi kasitlus ja injektsioonid | Serveripoolne valideerimine koigil sisenditel | Kõrge | Korras | `asm-input.server_side_validation` | `ev-baseline-review` |
| 29 | 6. Sisendi kasitlus ja injektsioonid | Koik paringud kasutavad parameetriseotust / turvalist API-t; toorfragmendid ja dunaamilised identifikaatorid lubatute nimekirjas | Kõrge | Korras | `asm-input.sql_parameterized` | `ev-baseline-review` |
| 30 | 6. Sisendi kasitlus ja injektsioonid | Valjund kodeeritud konteksti jargi; HTML puhastatakse ainult teadlikul lubamisel; ohtlikud URL-skeemid blokeeritud | Kõrge | Korras | `asm-input.output_encoding` | `ev-baseline-review` |
| 31 | 6. Sisendi kasitlus ja injektsioonid | Uleslaadimised: sisu/MIME/magic-byte kontroll, path-traversal-kindel, isoleeritud salvestus, juhuslikud nimed | Keskmine | üle vaatamata | — | — |
| 32 | 6. Sisendi kasitlus ja injektsioonid | Muud injektsiooniklassid arvestatud vajadusel: kask, SSRF, mall, path traversal, avatud umbersuunamine, deserialiseerimine | Keskmine | üle vaatamata | — | — |
| 33 | 7. Andmed, migratsioonid, varukoopiad | Skeemimuudatused labi commititud migratsioonide; andmebaasi piirangud, mitte ainult appi valideerimine | Keskmine | üle vaatamata | — | — |
| 34 | 7. Andmed, migratsioonid, varukoopiad | Varukoopiad seadistatud, krüpteeritud, ligipääsupiiratud – ja taaste on päriselt testitud (RPO/RTO teada) | Kõrge | Puudulik | `asm-data.tested_backups` | `ev-tested_backups-04` |
| 35 | 7. Andmed, migratsioonid, varukoopiad | Prodis pole vaikseid havitavaid migratsioone; tagasi-/edasitaaste plaan olemas | Kõrge | Korras | `asm-data.safe_prod_migrations` | `ev-baseline-review` |
| 36 | 7. Andmed, migratsioonid, varukoopiad | Kustutussemantika kavandatud: taastatav kus ari vajab, poordumatu kus privaatsus/turve nouab kustutamist | Keskmine | üle vaatamata | — | — |
| 37 | 8. Vead, logimine ja jalgitavus | Pole allaneelatud vigu; turvaotsustel fail-closed | Keskmine | üle vaatamata | — | — |
| 38 | 8. Vead, logimine ja jalgitavus | Veajalgimine kliendil JA serveril; struktureeritud logid; saladused/PII redigeeritud | Keskmine | Puudulik | `asm-obs.error_tracking` | `ev-error_tracking-05` |
| 39 | 8. Vead, logimine ja jalgitavus | Kasutajale ei leki stack trace'e / sisemisi vigu | Kõrge | Korras | `asm-obs.no_leaked_internals` | `ev-baseline-review` |
| 40 | 8. Vead, logimine ja jalgitavus | Turva- ja peamised aritsundmused logitud; taustatööd/webhookid jalgitavad | Keskmine | üle vaatamata | — | — |
| 41 | 8. Vead, logimine ja jalgitavus | Tervisekontrollid + teavitused omanikuga; monitooring testitud, mitte ainult uhendatud | Madal | üle vaatamata | — | — |
| 42 | 9. Konfiguratsioon ja juurutuskonveier | Debug prodis väljas; paljusonalised vealehed keelatud; avalikus ehituspaketis pole debug-endpointe | Kõrge | Korras | `asm-deploy.debug_disabled` | `ev-baseline-review` |
| 43 | 9. Konfiguratsioon ja juurutuskonveier | Prod vs dev/staging konfiguratsioon ja andmed lahus; eelvaate-ehitustes pole prod-saladusi | Kõrge | Korras | `asm-deploy.env_separation` | `ev-baseline-review` |
| 44 | 9. Konfiguratsioon ja juurutuskonveier | CORS lubab ainult ettenahtud paritolud/meetodid/paised; mandaadiga risttaustale kitsalt piiratud ja testitud | Kõrge | Korras | `asm-deploy.cors_restricted` | `ev-baseline-review` |
| 45 | 9. Konfiguratsioon ja juurutuskonveier | Transporditurve: HTTPS + HSTS; apile sobivad turvapaised | Keskmine | üle vaatamata | — | — |
| 46 | 9. Konfiguratsioon ja juurutuskonveier | Tootmise muudatuskontroll: haruskaitse, üle vaadatud muudatused, tagasipoordumine, korratavad artefaktid | Keskmine | üle vaatamata | — | — |
| 47 | 10. Kolmandate osapoolte integratsioonid | Sissetulevad webhookid kontrollivad allkirja + ajatemplit; endpoint keeldub voorastest sundmustuupidest | Kõrge | Korras | `asm-integ.webhook_signatures` | `ev-baseline-review` |
| 48 | 10. Kolmandate osapoolte integratsioonid | OAuth state/PKCE/nonce valideeritud; redirect-URI-d lukustatud; tokenid krupteeritult hoitud | Keskmine | üle vaatamata | — | — |
| 49 | 10. Kolmandate osapoolte integratsioonid | Minimaalsed skoobid; saladuse elutsukkel kasitletud integratsiooni lahtiuhendamisel | Keskmine | üle vaatamata | — | — |
| 50 | 10. Kolmandate osapoolte integratsioonid | Idempotentsus + kordus/backoff + dead-letter makse-/tellimus-/webhook-kasitlejatel | Kõrge | Korras | `asm-integ.idempotent_handlers` | `ev-baseline-review` |
| 51 | 11. Sõltuvused ja tarneahel | Käitus- ja ehitussõltuvused inventeeritud ja skannitud; ärakasutatavad leiud triaažeeritud, parandatud või aktsepteeritud | Keskmine | üle vaatamata | — | — |
| 52 | 11. Sõltuvused ja tarneahel | Sõltuvusriski signaalid üle vaadatud | Madal | üle vaatamata | — | — |
| 53 | 11. Sõltuvused ja tarneahel | Lockfile commititud; ehitus korratav; CI-tegevused/konteinerid kinnitatud | Madal | üle vaatamata | — | — |
| 54 | 11. Sõltuvused ja tarneahel | Litsentsid sobivad kavandatud arimudeliga | Madal | üle vaatamata | — | — |
| 55 | 12. Privaatsus ja GDPR | Andmete minimeerimine + andmekaart: mis PII, miks, kus asub, edastused | Keskmine | Puudulik | `asm-privacy.data_minimisation` | `ev-data_minimisation-06` |
| 56 | 12. Privaatsus ja GDPR | Paroole ei salvestata avatekstina; tundlik data krupteeritud; tokenid rasitud | Kriitiline | Korras | `asm-privacy.password_hashing` | `ev-baseline-review` |
| 57 | 12. Privaatsus ja GDPR | PII ei leki logidesse, analuutikasse ega LLM-promptidesse; teenusepakkuja satted üle vaadatud | Kõrge | Korras | `asm-privacy.no_pii_leakage` | `ev-baseline-review` |
| 58 | 12. Privaatsus ja GDPR | Rahvusvahelise edastuse mehhanism + alltootlejad + asukoht vastuvoetav (andmebaasi regioon JA LLM-marsruut) | Keskmine | üle vaatamata | — | — |
| 59 | 12. Privaatsus ja GDPR | Andmesubjekti õigused toimivad: teade, oiguslik alus, ligipääs, kustutamine, sailitus, rikkekasitlus | Keskmine | üle vaatamata | — | — |
| 60 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Kõrge riski valdkonna soel (Annex III / tooteohutus): olulised otsused inimeste kohta | Sõelumine | Vastatud | `asm-aiact.high_risk_screen` | — |
| 61 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Labipaistvuskohustused (Art. 50): sunteetiline/inimeseks-peetav sisu | Sõelumine | Vastatud | `asm-aiact.transparency_screen` | — |
| 62 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Keelatud praktika soel (Art. 5): skoorimine, manipuleerimine, arakasutamine | Sõelumine | Vastatud | `asm-aiact.prohibited_practice_screen` | — |
| 63 | 13. EL AI-maarus - lihtne soelumine (ei skoorita) | Eskaleerimine: spetsialisti ulevaatus kus vastus on jah/ebakindel; roll ja GPAI-kasutus dokumenteeritud | Sõelumine | Vastatud | `asm-aiact.specialist_escalation` | — |
| 64 | 14. Korrektsus ja ariloogika | Invariandid + andmebaasi piirangud joustavad pohireeglid; olekumasina uleminekud valideeritud | Kõrge | Korras | `asm-logic.invariant_enforcement` | `ev-baseline-review` |
| 65 | 14. Korrektsus ja ariloogika | Samaaegsuskindel: idempotentsus, optimistlik samaaegsus, tehingupiirid | Kõrge | Korras | `asm-logic.concurrency_safety` | `ev-baseline-review` |
| 66 | 14. Korrektsus ja ariloogika | Raha/maks/valuuta: taisarv/kumnend, umardusreeglid, lokaadi kasitlus | Kõrge | Korras | `asm-logic.money_math` | `ev-baseline-review` |
| 67 | 14. Korrektsus ja ariloogika | Kuupaevad/ajavoondid/suveaeg kasitletud eksplitsiitselt | Keskmine | üle vaatamata | — | — |
| 68 | 14. Korrektsus ja ariloogika | Õiguste muutused keset sessiooni joustuvad; poordumatud toimingud on auditeeritavad | Keskmine | üle vaatamata | — | — |
| 69 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Automaattestid pohilisele aritehingule ja havitavatele toimingutele | Kõrge | Korras | `asm-testing.core_flow_tests` | `ev-baseline-review` |
| 70 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Automaattestid autentimisele + volitamisele/rentniku eraldusele | Kõrge | Korras | `asm-testing.authz_tests` | `ev-baseline-review` |
| 71 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Automaattestid makse-/webhook-kasitlusele kui olemas; juurutuse kaivitus/tervis | Keskmine | üle vaatamata | — | — |
| 72 | 15. Tootevalmidus - testimine (mitte turvaskoor) | Deterministlikud/omadus-pohised testid keerukatele kriitilistele arvutustele | Madal | üle vaatamata | — | — |
| 73 | 16. Joudlus (mitte turvaskoor) | Serveripoolsed lehekulje-piirid; max eksport/raport; päringu ajapiirid | Keskmine | üle vaatamata | — | — |
| 74 | 16. Joudlus (mitte turvaskoor) | Esinduslikel tootmisparingutel on vastuvoetav latents; vajalikud indeksid olemas ja kasutuses | Madal | üle vaatamata | — | — |
| 75 | 16. Joudlus (mitte turvaskoor) | Uhenduse/pooli piirid; puhvri korrektsus; sujuv taandumine teenusepakkuja piiridel | Madal | üle vaatamata | — | — |
| 76 | 16. Joudlus (mitte turvaskoor) | Frontend-paketi suurus / kulmkaivitus sihtmargi piires | Madal | üle vaatamata | — | — |
| 77 | 17. AI turvalisus (prompt-injektsioon ja agendid) | LLM väljund ei jou exec/eval/shell/SQL-sihtmarki ilma valideerimise/skeemita | Kriitiline | Korras | `asm-llm.no_output_to_exec` | `ev-baseline-review` |
| 78 | 17. AI turvalisus (prompt-injektsioon ja agendid) | Ebausaldusvaarne sisu on eraldatud ja margitud andmena; ei saa muuta usaldatud juhiseid/õigusi | Kõrge | Puudulik | `asm-llm.untrusted_content_isolation` | `ev-untrusted_content_isolation-07` |
| 79 | 17. AI turvalisus (prompt-injektsioon ja agendid) | Tööriistakutse volitus tugineb autenditud kasutajale, mitte mudeli väljundile; suure mõjuga toimingud nõuavad inimkinnitust | Kõrge | Korras | `asm-llm.tool_call_authorization` | `ev-baseline-review` |
| 80 | 17. AI turvalisus (prompt-injektsioon ja agendid) | Ebausaldusvaarne valine/RAG-sisu kasitletud andmena; päringu ACL-id levivad | Keskmine | üle vaatamata | — | — |
| 81 | 17. AI turvalisus (prompt-injektsioon ja agendid) | LLM väljund renderdatud tekstina või puhastatud; malu isoleeritud kasutajate vahel | Keskmine | üle vaatamata | — | — |
| 82 | 18. Omand, jarjepidevus ja kasutatavus | Jarjepidevus: keegi peale algse ehitaja paaseb ligi, juurutab, taastab ja hooldab rakendust | Kõrge | Korras | `asm-continuity.bus_factor` | `ev-baseline-review` |
| 83 | 18. Omand, jarjepidevus ja kasutatavus | Kontode omand: domeen, majutus, DB, e-post, makse ja AI-teenused kuuluvad sulle/su ettevottele | Kõrge | Korras | `asm-continuity.account_ownership` | `ev-baseline-review` |
| 84 | 18. Omand, jarjepidevus ja kasutatavus | Andmete eksport: olulised ari- ja kasutajaandmed saab eksportida kasutatavas vormingus | Keskmine | üle vaatamata | — | — |
| 85 | 18. Omand, jarjepidevus ja kasutatavus | Toorke- ja taastekaitumine: vea korral nadab selge teate ega kaota/dubleeri andmeid | Keskmine | üle vaatamata | — | — |
| 86 | 18. Omand, jarjepidevus ja kasutatavus | Toe tee: kasutajatel on toimiv viis probleemist teatada ja keegi saab selle katte | Madal | üle vaatamata | — | — |
| 87 | 18. Omand, jarjepidevus ja kasutatavus | Tooteanaluutika: naed, kas peamine tee onnestub / kus kasutajad loobuvad, ilma liigse PII-ta | Madal | üle vaatamata | — | — |
| 88 | 18. Omand, jarjepidevus ja kasutatavus | Seadmeulene: peamine voog testitud päris telefonis ja vahemalt kahes levinud brauseris | Madal | üle vaatamata | — | — |
| 89 | 18. Omand, jarjepidevus ja kasutatavus | Pohiligipaasetavus: peamine voog kasutatav klaviatuuriga, loetava tekstiga ja selgete siltidega | Madal | üle vaatamata | — | — |

### B. Tõendid

| Tõendid | Allikas | Objekt | Suund | Tugevus | Vaadeldud | Kehtib kuni | Mida katab ja mida mitte |
|---|---|---|---|---|---|---|---|
| `ev-baseline-review` | vibecheck reviewer | repo . | toetab | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The current working tree and project settings visible during the 16 August review. |
| `ev-budget_caps-03` | vibecheck reviewer | config provider:billing | lükkab ümber | otsustav oma ulatuses | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The production-bound provider account settings reviewed with the owner. |
| `ev-data_minimisation-06` | vibecheck reviewer | document support-assistant prompt | lükkab ümber | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The server prompt builder and one redacted trace. |
| `ev-error_tracking-05` | vibecheck reviewer | repo . | lükkab ümber | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Current working tree only. |
| `ev-no_repo_history_leaks-02` | vibecheck reviewer | repo . | lükkab ümber | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Current branch and reachable history; the secret value is redacted. |
| `ev-object-level-support` | developer walkthrough | endpoint /api/orders/:id | toetab | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | The handler calls an ownership helper, but the live two-account test below contradicts the helper's expected behavior. |
| `ev-object_level-01` | authorized two-account API test | endpoint /api/orders/:id | lükkab ümber | otsustav oma ulatuses | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | One known private order in the pilot environment; no writes were attempted. |
| `ev-tested_backups-04` | vibecheck reviewer | document operations/backups | lükkab ümber | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Runbooks and provider activity available during the review. |
| `ev-untrusted_content_isolation-07` | vibecheck reviewer | file api/support-agent | lükkab ümber | viitav | 2026-08-16T12:00:00Z | 2026-09-15T12:00:00Z | Current support-agent request path only. |

### C. Kontekstiriskid

| Risk | Kontroll | Valdkond | Ulatus | Ajahorisont | Mõju | Avatus | Tase | Kindlus |
|---|---|---|---|---|---|---|---|---|
| `rsk-authz.object_level-private_test.invite_only_pilot-current-r1` | `vibecheck.control.authz.object_level` | turve | privaatne test + kutsepõhine pilootkasutus | täna | severe | plausible | kriitiline | suur |
| `rsk-authz.object_level-public_release.public_product-event_triggered-r1` | `vibecheck.control.authz.object_level` | turve | avalik väljalase + avalik toode | tuleviku ülemineku korral | severe | expected | kriitiline | suur |
| `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1` | `vibecheck.control.cost.budget_caps` | rahandus | privaatne test + kutsepõhine pilootkasutus | täna | major | plausible | kõrge | suur |
| `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1` | `vibecheck.control.cost.budget_caps` | rahandus | avalik väljalase + avalik toode | tuleviku ülemineku korral | severe | expected | kriitiline | suur |
| `rsk-data.tested_backups-private_test.invite_only_pilot-current-r1` | `vibecheck.control.data.tested_backups` | töökindlus | privaatne test + kutsepõhine pilootkasutus | täna | moderate | plausible | keskmine | suur |
| `rsk-data.tested_backups-public_release.public_product-event_triggered-r1` | `vibecheck.control.data.tested_backups` | töökindlus | avalik väljalase + avalik toode | tuleviku ülemineku korral | severe | expected | kriitiline | suur |
| `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1` | `vibecheck.control.llm.untrusted_content_isolation` | turve | privaatne test + kutsepõhine pilootkasutus | täna | severe | plausible | kriitiline | suur |
| `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1` | `vibecheck.control.llm.untrusted_content_isolation` | turve | avalik väljalase + avalik toode | tuleviku ülemineku korral | severe | expected | kriitiline | suur |
| `rsk-obs.error_tracking-private_test.invite_only_pilot-current-r1` | `vibecheck.control.obs.error_tracking` | töökindlus | privaatne test + kutsepõhine pilootkasutus | täna | moderate | plausible | keskmine | suur |
| `rsk-obs.error_tracking-public_release.public_product-event_triggered-r1` | `vibecheck.control.obs.error_tracking` | töökindlus | avalik väljalase + avalik toode | tuleviku ülemineku korral | moderate | expected | kõrge | suur |
| `rsk-privacy.data_minimisation-private_test.invite_only_pilot-current-r1` | `vibecheck.control.privacy.data_minimisation` | privaatsus | privaatne test + kutsepõhine pilootkasutus | täna | moderate | plausible | keskmine | suur |
| `rsk-privacy.data_minimisation-public_release.public_product-event_triggered-r1` | `vibecheck.control.privacy.data_minimisation` | privaatsus | avalik väljalase + avalik toode | tuleviku ülemineku korral | moderate | expected | kõrge | suur |
| `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1` | `vibecheck.control.secrets.no_repo_history_leaks` | turve | privaatne test + kutsepõhine pilootkasutus | täna | severe | plausible | kriitiline | suur |
| `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1` | `vibecheck.control.secrets.no_repo_history_leaks` | turve | avalik väljalase + avalik toode | tuleviku ülemineku korral | severe | expected | kriitiline | suur |

### D. Stsenaariumide jälgitavus

| Järjekoht | Stsenaarium | Pealkiri | Esiplaanil | Risk täna | Risk hiljem | Kontrolli ID | Hinnang | Risk | Tõendid | Tegevus | Protseduur |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `scn-credential_exposure` | Võti, mida saab kasutada ka keegi teine | jah | kriitiline | kriitiline | `vibecheck.control.secrets.no_repo_history_leaks` | `asm-secrets.no_repo_history_leaks` | `rsk-secrets.no_repo_history_leaks-private_test.invite_only_pilot-current-r1`, `rsk-secrets.no_repo_history_leaks-public_release.public_product-event_triggered-r1` | `ev-no_repo_history_leaks-02` | — | — |
| 2 | `scn-unauthorised_data_access` | Keegi pääseb ligi andmetele, mis ei ole tema omad | jah | kriitiline | kriitiline | `vibecheck.control.authz.object_level` | `asm-authz.object_level` | `rsk-authz.object_level-private_test.invite_only_pilot-current-r1`, `rsk-authz.object_level-public_release.public_product-event_triggered-r1` | `ev-object-level-support`, `ev-object_level-01` | `act-contain-cross-account-incident` | `prc-contain-cross-account-incident` |
| 3 | `scn-ai_manipulation` | Tehisaru pannakse sinu vastu töötama | jah | kriitiline | kriitiline | `vibecheck.control.llm.untrusted_content_isolation` | `asm-llm.untrusted_content_isolation` | `rsk-llm.untrusted_content_isolation-private_test.invite_only_pilot-current-r1`, `rsk-llm.untrusted_content_isolation-public_release.public_product-event_triggered-r1` | `ev-untrusted_content_isolation-07` | — | — |
| 4 | `scn-runaway_cost_or_abuse` | Arve kasvab kontrolli alt välja või ajab selle üles keegi teine | jah | kõrge | kriitiline | `vibecheck.control.cost.budget_caps` | `asm-cost.budget_caps` | `rsk-cost.budget_caps-private_test.invite_only_pilot-current-r1`, `rsk-cost.budget_caps-public_release.public_product-event_triggered-r1` | `ev-budget_caps-03` | — | — |
| 5 | `scn-data_loss` | Andmed kaovad ja neid ei saa tagasi | jah | keskmine | kriitiline | `vibecheck.control.data.tested_backups` | `asm-data.tested_backups` | `rsk-data.tested_backups-private_test.invite_only_pilot-current-r1`, `rsk-data.tested_backups-public_release.public_product-event_triggered-r1` | `ev-tested_backups-04` | — | — |
| 6 | `scn-personal_data_misuse` | Isikuandmed satuvad sinna, kuhu ei tohi | ei | keskmine | kõrge | `vibecheck.control.privacy.data_minimisation` | `asm-privacy.data_minimisation` | `rsk-privacy.data_minimisation-private_test.invite_only_pilot-current-r1`, `rsk-privacy.data_minimisation-public_release.public_product-event_triggered-r1` | `ev-data_minimisation-06` | `act-decide-support-data` | — |
| 7 | `scn-silent_failure` | Midagi läheb katki ja keegi ei saa teada | ei | keskmine | kõrge | `vibecheck.control.obs.error_tracking` | `asm-obs.error_tracking` | `rsk-obs.error_tracking-private_test.invite_only_pilot-current-r1`, `rsk-obs.error_tracking-public_release.public_product-event_triggered-r1` | `ev-error_tracking-05` | `act-verify-error-paths` | `prc-inventory-error-paths` |

### E. Tegevused

| Tegevus | Liik | Nõutav tulemus | Vastutaja | Prioriteet | Kiireloomulisus | Millal | Seis | Blokeerib | Kontrolli ID | Risk | Stsenaarium | Protseduur | Mis selle sulgeb |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `act-contain-cross-account-incident` | intsidendile reageerimine | Contain the cross-account order exposure and determine which records were accessed. | spetsialist | teadmata | kohe | Paranda kohe | avatud | avalik väljalase + avalik toode | `vibecheck.control.authz.object_level` | — | — | `prc-contain-cross-account-incident` | Access is denied in a repeated two-account test, affected access is reviewed, and the control is reassessed. |
| `act-decide-support-data` | otsus | Decide and document which order fields the support assistant is allowed to receive. | omanik | teadmata | järgmisena | Enne avalikku väljalaset | avatud | avalik väljalase + avalik toode | `vibecheck.control.privacy.data_minimisation` | — | — | — | A reviewed field allowlist and retention statement are recorded. |
| `act-refactor-test-helper` | parandus | Refactor the test-data helper when the next test suite cleanup is scheduled. | arendaja | teadmata | ootenimekirjas | Ootenimekiri | avatud | — | — | — | — | — | The helper has focused tests and no duplicated setup. |
| `act-verify-error-paths` | kontrollimine | Collect a bounded error-path inventory for the developer to instrument. | arendaja | teadmata | järgmisena | Enne avalikku väljalaset | avatud | avalik väljalase + avalik toode | `vibecheck.control.obs.error_tracking` | — | — | `prc-inventory-error-paths` | The inventory names every reviewed server error path and its current handling. |

### F. Protseduurid

| Protseduur | Pealkiri | Täitja | Täitmisviis | Mehhanism | Nõusolek | Võrguühendus | Mõjud | Pärandvaade | Mis selle sulgeb |
|---|---|---|---|---|---|---|---|---|---|
| `prc-contain-cross-account-incident` | Disable the affected order endpoint and deploy an authorization fix | arendaja | juhendatud | code_change_and_deployment | selgesõnaline nõusolek | ei | write, deployment | PROPOSE | A repeated two-account test denies cross-account reads. |
| `prc-inventory-error-paths` | Scan and review server error paths | Vibecheck | automatiseeritud | read_only_source_review | pole nõutav | ei | puudub | AUTO | A bounded path-and-handler inventory with review notes. |

### G. Protseduuri katsed

| Katse | Tegevus | Protseduur | Keskkond | Tulemus | Nõusolek | Mõjud | Tagasipööre | Tõendid | Uushinnang |
|---|---|---|---|---|---|---|---|---|---|

### H. Metoodika ja versioonid

| Metoodika | Versioon |
|---|---|
| vibecheck.assessment | 1.5.0 |
| vibecheck_v1 | 2026.08 |
| vibecheck.controls | 1.0.0 |
| vibecheck.action_registry | 1.0.0 |
| vibecheck.risk_derivation | 1.0.0 |
| vibecheck.readiness | 1.0.0 |
| vibecheck.report_derivation | 1.1.0 |
| vibecheck.report | 1.1.0 |
| vibecheck.action_policy | 1.1.0 |
| vibecheck.report_wording | 1.1.0 |

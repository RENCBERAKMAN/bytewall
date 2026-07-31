# ByteWall Mimari Kararlari

## Temel Prensip
Whitelist > Blacklist. Bir hedef acikca in_scope tanimlanmadikca
hicbir aktif tarama modulune gonderilmez.

## Veri Akisi
targets -> ScopeManager.filter_targets() -> in_scope hedefler
  -> modules/*Runner.run() -> ham cikti
  -> parsers/*_parser.py -> Finding listesi (ortak sema)
  -> ai/analyzer.py -> zenginlestirilmis Finding listesi
  -> reports/*_builder.py -> HTML/Markdown rapor

## Neden bu yapi
- Her runner BaseRunner'i implement eder -> yeni arac eklemek
  orchestrator'i bozmaz (Strategy Pattern)
- Her parser ayni Finding semasina cevirir -> AI ve rapor
  katmani hangi araÃ§tan geldigini bilmek zorunda degil
- data/ tamamen gitignore'da -> hassas scope/sonuc verisi
  asla public repoya sizmaz

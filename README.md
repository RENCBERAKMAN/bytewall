# ByteWall

Kisisel bug bounty kullanimi icin gelistirilen, AI destekli
tarama orkestrasyon araci.

## Neden bazi moduller repoda yok
Aktif tarama/payload mantigi iceren bazi moduller ozel tutulmustur:
- Kotuye kullanim riskini azaltmak icin
- Sorumlu ifsa (responsible disclosure) ilkelerine baglilik geregi
- Bounty programlarimda kullandigim ozel teknikleri korumak icin

Paylasilan kisimlar: orkestrasyon mimarisi, veri normalizasyon
katmani (parsers/), AI analiz katmani (ai/), raporlama (reports/).

## Kurulum
```
cp .env.example .env
cp data/scope/program.example.yaml data/scope/my_program.yaml
pip install -r requirements.txt
```

## Kullanim
```
python main.py --program my_program --target api.example.com --dry-run
```

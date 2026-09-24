
import argparse
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

DEX_BASE = "https://api.dexscreener.com"
RUGCHECK_BASE = "https://api.rugcheck.xyz/v1"
TELEGRAM_BASE = "https://api.telegram.org"

@dataclass
class Security:
    creator_pct: Optional[float] = None
    top10_pct: Optional[float] = None
    sniper_pct: Optional[float] = None
    bundled_pct: Optional[float] = None
    insider_pct: Optional[float] = None
    rug_score: Optional[float] = None
    mint_authority: bool = False
    freeze_authority: bool = False
    rugged: bool = False
    risks: list[str] = None
    source_ok: bool = False

    def __post_init__(self):
        if self.risks is None:
            self.risks = []

@dataclass
class Token:
    address: str
    symbol: str
    name: str
    price_usd: float
    market_cap: float
    liquidity_usd: float
    volume_5m: float
    volume_1h: float
    buys_5m: int
    sells_5m: int
    price_change_5m: float
    price_change_1h: float
    pair_created_ms: int
    url: str
    dex: str
    security: Security = None

    @property
    def age_minutes(self):
        if not self.pair_created_ms:
            return 999999
        return max(0, (time.time()*1000-self.pair_created_ms)/60000)

class DB:
    def __init__(self, path="scanner.db"):
        self.conn=sqlite3.connect(path)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS snapshots(
          address TEXT PRIMARY KEY,last_price REAL,last_volume_5m REAL,last_seen REAL)""")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS alerts(
          address TEXT PRIMARY KEY,last_alert REAL)""")
        self.conn.commit()

    def snapshot(self,t):
        row=self.conn.execute("SELECT last_price,last_volume_5m FROM snapshots WHERE address=?",(t.address,)).fetchone()
        self.conn.execute("""INSERT INTO snapshots VALUES(?,?,?,?)
          ON CONFLICT(address) DO UPDATE SET last_price=excluded.last_price,
          last_volume_5m=excluded.last_volume_5m,last_seen=excluded.last_seen""",
          (t.address,t.price_usd,t.volume_5m,time.time()))
        self.conn.commit()
        return row

    def recently_alerted(self,address,cooldown):
        row=self.conn.execute("SELECT last_alert FROM alerts WHERE address=?",(address,)).fetchone()
        return bool(row and time.time()-row[0]<cooldown*60)

    def mark_alert(self,address):
        self.conn.execute("""INSERT INTO alerts VALUES(?,?)
          ON CONFLICT(address) DO UPDATE SET last_alert=excluded.last_alert""",
          (address,time.time()))
        self.conn.commit()

class DexScreenerProvider:
    # Uses the latest Solana token profiles and then the token-pairs endpoint.
    # Pair age is used for the new-pair window.
    def __init__(self):
        self.s=requests.Session()
        self.s.headers["User-Agent"]="solana-fomo-scanner/2.0"

    def fetch(self):
        r=self.s.get(f"{DEX_BASE}/token-profiles/latest/v1",timeout=12)
        r.raise_for_status()
        profiles=[x for x in r.json()
                  if x.get("chainId")=="solana" and x.get("tokenAddress")]
        tokens=[]
        for x in profiles[:60]:
            a=x["tokenAddress"]
            try:
                q=self.s.get(f"{DEX_BASE}/latest/dex/tokens/{a}",timeout=10)
                q.raise_for_status()
                pairs=[p for p in (q.json().get("pairs") or []) if p.get("chainId")=="solana"]
                if not pairs: continue
                p=max(pairs,key=lambda z:float((z.get("liquidity") or {}).get("usd") or 0))
                v=p.get("volume") or {}; tx=p.get("txns") or {}; t5=tx.get("m5") or {}
                b=p.get("baseToken") or {}
                tokens.append(Token(
                    address=b.get("address") or a, symbol=b.get("symbol") or "?",
                    name=b.get("name") or "?", price_usd=float(p.get("priceUsd") or 0),
                    market_cap=float(p.get("marketCap") or p.get("fdv") or 0),
                    liquidity_usd=float((p.get("liquidity") or {}).get("usd") or 0),
                    volume_5m=float(v.get("m5") or 0), volume_1h=float(v.get("h1") or 0),
                    buys_5m=int(t5.get("buys") or 0), sells_5m=int(t5.get("sells") or 0),
                    price_change_5m=float((p.get("priceChange") or {}).get("m5") or 0),
                    price_change_1h=float((p.get("priceChange") or {}).get("h1") or 0),
                    pair_created_ms=int(p.get("pairCreatedAt") or 0),
                    url=p.get("url") or "", dex=p.get("dexId") or "unknown"))
            except Exception as e:
                print("[market]",a[:8],e)
        return tokens

class RugCheckProvider:
    def __init__(self):
        self.s=requests.Session()
        self.s.headers.update({"Accept":"application/json","User-Agent":"solana-fomo-scanner/2.0"})

    @staticmethod
    def pct(x):
        try: return float(x)
        except: return None

    def report(self,mint):
        r=self.s.get(f"{RUGCHECK_BASE}/tokens/{mint}/report",timeout=15)
        r.raise_for_status()
        return r.json()

    def enrich(self,t):
        sec=Security()
        try:
            d=self.report(t.address)
            sec.source_ok=True
            sec.rug_score=self.pct(d.get("score_normalised", d.get("score")))
            sec.rugged=bool(d.get("rugged",False))
            sec.mint_authority=bool((d.get("token") or {}).get("mintAuthority"))
            sec.freeze_authority=bool((d.get("token") or {}).get("freezeAuthority"))
            holders=d.get("topHolders") or []
            sec.top10_pct=sum(self.pct(h.get("pct")) or 0 for h in holders[:10])
            creator=d.get("creator")
            for h in holders:
                if creator and (h.get("owner")==creator or h.get("address")==creator):
                    sec.creator_pct=self.pct(h.get("pct")); break
            # RugCheck exposes insider networks; use aggregate token amount only
            # when a direct percentage is unavailable.
            nets=d.get("insiderNetworks") or []
            if nets:
                # Network size is a signal, not a token-supply percentage.
                sec.insider_pct=None
                sec.risks.append(f"{len(nets)} insider network(s) detected")
            for risk in (d.get("risks") or [])[:5]:
                n=risk.get("name")
                if n: sec.risks.append(n)
        except Exception as e:
            print("[security]",t.symbol,e)
        t.security=sec
        return t

class Scorer:
    def __init__(self):
        self.min_age=float(os.getenv("MIN_AGE_MINUTES","1"))
        self.max_age=float(os.getenv("MAX_AGE_MINUTES","15"))
        self.min_liq=float(os.getenv("MIN_LIQUIDITY_USD","10000"))
        self.min_vol=float(os.getenv("MIN_VOLUME_5M_USD","5000"))
        self.min_txns=int(os.getenv("MIN_TXNS_5M","20"))
        self.min_ratio=float(os.getenv("MIN_BUY_SELL_RATIO","1.15"))
        self.max_top10=float(os.getenv("MAX_TOP10_HOLDER_PCT","35"))
        self.max_creator=float(os.getenv("MAX_CREATOR_HOLDING_PCT","10"))
        self.max_sniper=float(os.getenv("MAX_SNIPER_PCT","15"))
        self.max_bundle=float(os.getenv("MAX_BUNDLED_PCT","10"))
        self.max_rug=float(os.getenv("MAX_RUGCHECK_SCORE","35"))
        self.require_security=os.getenv("REQUIRE_SECURITY_DATA","true").lower()=="true"
        self.alert=float(os.getenv("ALERT_SCORE","80"))

    def clamp(self,x): return max(0,min(100,x))

    def score(self,t,previous):
        s=t.security
        reasons=[]; warnings=[]
        if not(self.min_age<=t.age_minutes<=self.max_age): return 0,[],["new-pair age outside range"]
        if t.liquidity_usd<self.min_liq or t.volume_5m<self.min_vol: return 0,[],["market filters failed"]
        if t.buys_5m+t.sells_5m<self.min_txns: return 0,[],["transaction filter failed"]
        ratio=t.buys_5m/max(1,t.sells_5m)
        if ratio<self.min_ratio: return 0,[],["buy/sell filter failed"]
        if not s or (self.require_security and not s.source_ok):
            return 0,[],["security report unavailable"]
        if s.rugged: return 0,[],["token marked rugged"]
        if s.top10_pct is not None and s.top10_pct>self.max_top10: return 0,[],["top-10 concentration too high"]
        if s.creator_pct is not None and s.creator_pct>self.max_creator: return 0,[],["creator holding too high"]
        if s.sniper_pct is not None and s.sniper_pct>self.max_sniper: return 0,[],["sniper concentration too high"]
        if s.bundled_pct is not None and s.bundled_pct>self.max_bundle: return 0,[],["bundled supply too high"]
        if s.rug_score is not None and s.rug_score>self.max_rug: return 0,[],["security score too risky"]

        liq=self.clamp(t.liquidity_usd/50000*100)
        vol=self.clamp(t.volume_5m/50000*100)
        pressure=self.clamp((ratio-1)/2.5*100)
        momentum=self.clamp(50+t.price_change_5m*2)
        accel=50
        if previous:
            oldp,oldv=previous
            if oldv>0: accel=self.clamp(50+((t.volume_5m-oldv)/oldv)*50)
            if oldp>0 and t.price_usd>0:
                momentum=self.clamp(50+(((t.price_usd-oldp)/oldp)*100)*3)
        distribution=100
        if s.top10_pct is not None: distribution=self.clamp(100-(s.top10_pct/max(1,self.max_top10))*70)
        creator=100
        if s.creator_pct is not None: creator=self.clamp(100-(s.creator_pct/max(1,self.max_creator))*60)
        security=100
        if s.rug_score is not None: security=self.clamp(100-(s.rug_score/max(1,self.max_rug))*70)
        score=(liq*.15+vol*.20+pressure*.15+momentum*.15+accel*.10+
               distribution*.10+creator*.05+security*.10)
        if ratio>=1.5: reasons.append("strong buy pressure")
        if accel>=70: reasons.append("volume accelerating")
        if t.price_change_5m>=10: reasons.append("positive 5m momentum")
        if s.top10_pct is not None: reasons.append(f"top-10 holders {s.top10_pct:.1f}%")
        if s.creator_pct is not None: reasons.append(f"creator {s.creator_pct:.1f}%")
        if s.rug_score is not None: reasons.append(f"security score {s.rug_score:.0f}")
        if s.insider_pct is None and s.risks: warnings.extend(s.risks[:3])
        if s.mint_authority: warnings.append("mint authority active")
        if s.freeze_authority: warnings.append("freeze authority active")
        return self.clamp(score),reasons,warnings

class Telegram:
    def __init__(self):
        self.token=os.getenv("TELEGRAM_BOT_TOKEN","").strip()
        self.chat=os.getenv("TELEGRAM_CHAT_ID","").strip()
    def send(self,text):
        if not(self.token and self.chat): print(text); return
        r=requests.post(f"{TELEGRAM_BASE}/bot{self.token}/sendMessage",
                        json={"chat_id":self.chat,"text":text,"disable_web_page_preview":True},timeout=10)
        r.raise_for_status()

def money(x):
    if x>=1e6:return f"${x/1e6:.2f}M"
    if x>=1e3:return f"${x/1e3:.1f}K"
    return f"${x:.0f}"

def alert_text(t,score,reasons,warnings):
    s=t.security or Security()
    ratio=t.buys_5m/max(1,t.sells_5m)
    lines=[
      "🚨 SOLANA NEW-PAIR SCANNER",
      f"${t.symbol} — {t.name}",
      f"Age: {t.age_minutes:.1f}m | DEX: {t.dex}",
      f"MC/FDV: {money(t.market_cap)} | Liquidity: {money(t.liquidity_usd)}",
      f"5m Vol: {money(t.volume_5m)} | Buys/Sells: {t.buys_5m}/{t.sells_5m} ({ratio:.2f}x)",
      f"5m Price: {t.price_change_5m:+.1f}%",
      "",
      f"🔥 SCREEN SCORE: {score:.0f}/100",
      "",
      "Security:"
    ]
    if s.top10_pct is not None: lines.append(f"• Top 10: {s.top10_pct:.1f}%")
    if s.creator_pct is not None: lines.append(f"• Creator: {s.creator_pct:.1f}%")
    if s.sniper_pct is not None: lines.append(f"• Snipers: {s.sniper_pct:.1f}%")
    if s.bundled_pct is not None: lines.append(f"• Bundled: {s.bundled_pct:.1f}%")
    if s.rug_score is not None: lines.append(f"• RugCheck score: {s.rug_score:.0f}")
    lines += ["","Why:"]+[f"• {x}" for x in reasons]
    if warnings: lines += ["","⚠️ Warnings:"]+[f"• {x}" for x in warnings]
    if t.url: lines += ["",f"Chart: {t.url}"]
    lines += ["","Alert only — verify before trading."]
    return "\n".join(lines)[:4096]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--telegram-test",action="store_true"); args=ap.parse_args()
    tg=Telegram()
    if args.telegram_test: tg.send("✅ Solana scanner Telegram test succeeded."); return
    db=DB(); market=DexScreenerProvider(); security=RugCheckProvider(); scorer=Scorer()
    poll=int(os.getenv("POLL_SECONDS","30")); cooldown=int(os.getenv("ALERT_COOLDOWN_MINUTES","20"))
    print("Scanner v2 started: new-pair + security filters, alert-only.")
    while True:
        start=time.time()
        try:
            tokens=market.fetch()
            # Security calls are intentionally made only after basic market filters
            # to reduce API load.
            candidates=[t for t in tokens if scorer.min_age<=t.age_minutes<=scorer.max_age
                        and t.liquidity_usd>=scorer.min_liq
                        and t.volume_5m>=scorer.min_vol
                        and t.buys_5m+t.sells_5m>=scorer.min_txns
                        and t.buys_5m/max(1,t.sells_5m)>=scorer.min_ratio]
            ranked=[]
            for t in candidates:
                previous=db.snapshot(t)
                t=security.enrich(t)
                score,reasons,warnings=scorer.score(t,previous)
                if score>=scorer.alert: ranked.append((score,t,reasons,warnings))
            ranked.sort(key=lambda x:x[0],reverse=True)
            for score,t,reasons,warnings in ranked[:10]:
                if not db.recently_alerted(t.address,cooldown):
                    tg.send(alert_text(t,score,reasons,warnings)); db.mark_alert(t.address)
            print(f"[scan] profiles={len(tokens)} candidates={len(candidates)} alerts={len(ranked)}")
        except Exception as e: print("[scanner error]",e)
        time.sleep(max(1,poll-(time.time()-start)))

if __name__=="__main__": main()

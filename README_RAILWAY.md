# Solana FOMO-style scanner v2

This Railway-ready version adds:

- Solana new-pair window using pair creation time.
- Liquidity/volume/transaction filters.
- Buy/sell pressure.
- RugCheck security report enrichment.
- Top-10 holder concentration filter.
- Creator holding filter.
- Sniper and bundled-supply filter hooks.
- Mint/freeze authority warnings.
- RugCheck risk-score filter.
- Insider-network warnings.
- Telegram alerts.
- SQLite alert cooldown/history.

### Important provider detail

The market feed uses DexScreener's public Solana token-profile/pair endpoints. RugCheck's documented/report endpoint is used for token security enrichment. RugCheck reports include creator, top holders, risks, mint/freeze authority, markets, and insider-network information. The exact `sniper_pct` and `bundled_pct` fields are not guaranteed by the RugCheck report, so those filters remain disabled unless the provider supplies those values. This avoids inventing data.

For exact Axiom/FOMO parity, an officially documented Axiom data feed/API would still be needed.

### Railway variables

Set the variables in `.env.example` in Railway. Start with:

MAX_TOP10_HOLDER_PCT=35
MAX_CREATOR_HOLDING_PCT=10
MAX_SNIPER_PCT=15
MAX_BUNDLED_PCT=10
MAX_RUGCHECK_SCORE=35
REQUIRE_SECURITY_DATA=true
ALERT_SCORE=80

The scanner is alert-only and never asks for a wallet private key or seed phrase.

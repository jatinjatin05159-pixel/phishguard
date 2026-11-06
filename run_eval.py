"""Shows how well PhishGuard does on messages it was NOT trained on.
Run:  python run_eval.py            (uses eval_set.tsv and eval_set2.tsv, internet checks off)"""
import pandas as pd
import main

main.ONLINE_CHECKS = False          # test the text model + rules only, so results are repeatable
for name in ("eval_set.tsv", "eval_set2.tsv"):
    df = pd.read_csv(name, sep="\t")
    flagged = []
    for _, r in df.iterrows():
        out = main.analyze(main.Message(text=r.message))
        flagged.append(out["verdict"] in ("Suspicious", "Phishing"))
    df["flagged"] = flagged
    sc, sf = df[df.label == "scam"], df[df.label == "safe"]
    ok = int(sc.flagged.sum() + (~sf.flagged).sum())
    print(f"{name}: accuracy {ok}/{len(df)} = {ok/len(df):.1%} | scams caught {int(sc.flagged.sum())}/{len(sc)} | "
          f"false alarms {int(sf.flagged.sum())}/{len(sf)}")
    for _, r in df[(df.label == "scam") & ~df.flagged].iterrows():
        print("   MISSED:", r.message[:80])
    for _, r in df[(df.label == "safe") & df.flagged].iterrows():
        print("   FALSE ALARM:", r.message[:80])

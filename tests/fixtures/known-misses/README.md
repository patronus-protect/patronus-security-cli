# Ark 0.1.6: bekannte Langtext-Fehlklassifikationen

Diese beiden Dateien bewahren die ursprünglichen Angriffsvarianten bytegenau.
Direkte Aufrufe von Ark 0.1.6 und der Scanner klassifizieren die vollständigen
Dokumente als `benign`, während ihre isolierten Angriffsabschnitte erkannt werden.
Die Untersuchung verwendete lokale Modellassets und beide öffentlichen Ark-APIs.

Die aktive DeepSeek-Integrationsprüfung verwendet die ausdrücklich erkennbaren
Varianten unter `../realistic/`. Das ist eine Anpassung der Testdaten und keine
Korrektur von Arks Erkennungsqualität.

`model_layers_detect_both_signals_missed_by_l1` behält seinen ursprünglichen
Erkennungsanspruch für diese Dateien. Der bereits opt-in ausgeführte Modelltest
bleibt unter Ark 0.1.6 rot. Die positiven L2-/L3-Abschnittstests und der L2-Cachetest
verwenden weiterhin Auszüge aus diesen unveränderten Originalen.

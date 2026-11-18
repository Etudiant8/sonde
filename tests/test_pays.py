from sonde.pays import charger_pays


def test_recherche_par_plage(tmp_path):
    f = tmp_path / "pays.csv"
    f.write_text("1.0.0.0,1.0.0.255,AU\n102.35.0.0,102.35.255.255,RE\n2001:db8::,2001:db8::ffff,FR\nligne,abimee\n")
    pays = charger_pays(str(f))
    assert pays("102.35.4.9") == "RE"
    assert pays("1.0.0.0") == "AU" and pays("1.0.0.255") == "AU"
    assert pays("1.0.1.0") is None and pays("0.255.255.255") is None
    assert pays("2001:db8::12") == "FR"
    assert pays("pas une ip") is None


def test_fichier_absent_desactive_la_recherche(tmp_path):
    assert charger_pays("") is None
    assert charger_pays(str(tmp_path / "absent.csv")) is None

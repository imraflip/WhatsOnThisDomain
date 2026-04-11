def test_import_wotd():
    import wotd
    import wotd.modules

    assert wotd is not None
    assert wotd.modules is not None

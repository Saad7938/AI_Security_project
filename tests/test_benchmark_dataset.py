from bench.harness import load


def test_dataset_shape():
    attacks, benign = load("attacks"), load("benign")
    assert len(attacks) == 50 and len(benign) == 50
    assert len({c["id"] for c in attacks + benign}) == 100
    assert {c["category"] for c in attacks} == set("ABCDE")
    for c in benign:
        assert c["expect_contains"] and c["calls"]


def test_every_llm_level_attack_has_a_payload():
    for c in load("attacks"):
        assert bool(c["payload"]) == c["llm_level"]

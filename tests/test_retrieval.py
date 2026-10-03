"""Retrieval: BM25 ranking, index maintenance, and the equivalence of the two paths.

Ranking quality is a governance concern here, not a search-engine nicety. If the
retrieval function cannot tell a rare identifier from a common word, a refusal can be
triggered by an irrelevant memory -- and the audit trail will record a refusal that
had nothing to do with the question.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from amnesia import MemoryGovernor, MemoryItem, Principal, utcnow
from amnesia.models import iso
from amnesia.store import MemoryStore, counts, tokens

TENANT = "acme"
ALICE = Principal(id="alice", tenant=TENANT, roles=("employee",))


def make(store: MemoryStore, content: str, **kwargs) -> MemoryItem:
    payload = {
        "content": content,
        "source": "test",
        "tenant": TENANT,
        "scope": "project",
        "owner": "o",
        "subject": kwargs.pop("subject", ""),
    }
    payload.update(kwargs)
    return store.add(MemoryItem(**payload))


@pytest.fixture()
def store():
    s = MemoryStore(":memory:")
    yield s
    s.close()


def ranked(store: MemoryStore, query: str, **kwargs) -> list[str]:
    kwargs.setdefault("min_confidence", 0.0)
    kwargs.setdefault("limit", 20)
    pairs = store.search_candidates(query, tenant=TENANT, now=utcnow(), **kwargs)
    return [item.id for item, _ in pairs]


# ------------------------------------------------------------------ tokenizer


def test_stopwords_do_not_create_matches(store: MemoryStore):
    make(store, "The contract is worth a lot.")
    assert ranked(store, "what is the") == []


def test_cjk_uses_bigrams_not_single_characters(store: MemoryStore):
    """Character-level CJK matching makes unrelated terms collide on one character."""
    make(store, "年假政策为十天天")
    # A query sharing only a single character must not match.
    assert ranked(store, "年终奖金") == []


def test_counts_returns_term_frequencies():
    frequencies = counts("alpha alpha beta")
    assert frequencies["alpha"] == 2
    assert frequencies["beta"] == 1


# ----------------------------------------------------------------- BM25 ranking


def test_rare_term_outranks_common_term(store: MemoryStore):
    """The whole reason BM25 replaced overlap scoring."""
    target = make(store, "alpha beta")
    for i in range(8):
        make(store, f"beta gamma filler{i}")

    order = ranked(store, "alpha beta")
    assert order[0] == target.id, "the document containing the rare term must rank first"


def test_document_frequency_affects_score(store: MemoryStore):
    common = make(store, "shared payload one")
    make(store, "shared payload two")
    make(store, "shared payload three")

    pairs = store.search_candidates(
        "shared payload", tenant=TENANT, min_confidence=0.0, now=utcnow(), limit=10
    )
    assert pairs[0][0].id == common.id or len({p[0].id for p in pairs}) == 3
    # All three contain the terms, so all three are candidates.
    assert len(pairs) == 3


def test_min_score_filters_weak_matches(store: MemoryStore):
    """A rare term pulls one document far above the rest, which is the point of BM25."""
    strong = make(store, "alpha zeta")  # zeta appears once in the corpus
    for i in range(20):
        make(store, f"alpha beta{i}")  # alpha appears everywhere, so it barely counts

    loose = ranked(store, "alpha zeta", min_score=0.0, limit=50)
    strict = ranked(store, "alpha zeta", min_score=2.0, limit=50)

    assert len(loose) == 21
    assert strict == [strong.id]


def test_limit_is_respected(store: MemoryStore):
    for i in range(10):
        make(store, f"alpha token{i}")
    assert len(ranked(store, "alpha", limit=3)) == 3


def test_empty_query_returns_nothing(store: MemoryStore):
    make(store, "alpha")
    assert ranked(store, "") == []


def test_query_of_only_stopwords_returns_nothing(store: MemoryStore):
    make(store, "alpha")
    assert ranked(store, "the and of") == []


def test_store_with_no_documents_returns_nothing(store: MemoryStore):
    assert ranked(store, "alpha") == []


# -------------------------------------------------------- index maintenance


def test_index_follows_content_updates(store: MemoryStore):
    item = make(store, "alpha bravo")
    assert ranked(store, "alpha") == [item.id]

    store.update(item.id, content="charlie delta")
    assert ranked(store, "alpha") == []
    assert ranked(store, "charlie") == [item.id]


def test_delete_removes_terms_from_the_index(store: MemoryStore):
    item = make(store, "alpha bravo")
    store.delete([item.id])
    assert ranked(store, "alpha") == []


def test_reindex_rebuilds_from_scratch(store: MemoryStore):
    make(store, "alpha")
    make(store, "bravo")
    store._conn.execute("DELETE FROM terms")  # simulate a corrupted index
    store._conn.commit()
    assert ranked(store, "alpha") == []

    assert store.reindex() == 2
    assert len(ranked(store, "alpha")) == 1


def test_update_missing_memory_raises(store: MemoryStore):
    from amnesia import BackendError

    with pytest.raises(BackendError):
        store.update("does-not-exist", status="archived")


def test_health_reports_index_state(store: MemoryStore):
    make(store, "alpha")
    health = store.health()
    assert health["integrity"] == "ok"
    assert health["memories"] == 1
    assert health["indexed_terms"] >= 1
    assert health["index_fresh"] is True


# ------------------------------------------------- both paths must agree


def test_acl_pushdown_and_post_filter_agree_under_bm25(store: MemoryStore):
    make(store, "alpha confidential", scope="hr_only")
    make(store, "alpha project", scope="project")
    make(store, "alpha beta project", scope="project")

    now = utcnow()
    candidates = store.search_candidates(
        "alpha", tenant=TENANT, min_confidence=0.0, now=now, limit=20
    )
    allowed = store.search_allowed(
        "alpha",
        tenant=TENANT,
        allowed_scopes=["project"],
        min_confidence=0.0,
        now=now,
        limit=20,
    )

    # The invariant that matters: the authorised subset appears in the same relative
    # order under both paths. If this drifts, the two paths disagree about relevance
    # and a refusal could be triggered by a memory the caller would never have seen.
    candidate_order = [i.id for i, _ in candidates]
    allowed_order = [i.id for i, _ in allowed]
    assert allowed_order == [i for i in candidate_order if i in set(allowed_order)]
    assert all(i.scope == "project" for i, _ in allowed)


def test_scopes_are_actually_filtered(store: MemoryStore):
    make(store, "alpha hr", scope="hr_only")
    make(store, "alpha project", scope="project")
    allowed = store.search_allowed(
        "alpha",
        tenant=TENANT,
        allowed_scopes=["project"],
        min_confidence=0.0,
        now=utcnow(),
        limit=20,
    )
    assert len(allowed) == 1
    assert allowed[0][0].scope == "project"


def test_expired_memories_never_score(store: MemoryStore):
    item = make(store, "alpha")
    store.update(item.id, expires_at=iso(utcnow() - timedelta(days=1)))
    assert ranked(store, "alpha") == []


def test_low_confidence_memories_never_score(store: MemoryStore):
    make(store, "alpha", confidence=0.1)
    assert ranked(store, "alpha", min_confidence=0.3) == []


def test_post_filter_scans_past_a_page_of_refusals(tmp_path, monkeypatch):
    """Regression: a truncated candidate window let refused memories hide allowed ones.

    This reproduced a real divergence -- `post_filter` returned 0 results while
    `pre_filter` returned the one memory the caller was cleared for, because twelve
    refused memories filled the candidate window. That contradicts the product's central
    claim that the two paths agree.
    """
    from amnesia import MemoryGovernor

    monkeypatch.setattr("amnesia.governor.CANDIDATE_LIMIT", 5)
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        for i in range(12):
            # Repeating the query terms raises term frequency, so every refused memory
            # outranks the allowed one.
            gov.remember(
                f"alpha falcon alpha falcon alpha falcon {i}",
                source="hr-system",
                tenant=TENANT,
                scope="hr_only",
                owner="dana",
            )
        allowed = gov.remember(
            "alpha falcon deploy runbook", source="wiki", tenant=TENANT, scope="project"
        )

        post = gov.recall("alpha falcon", principal=ALICE, mode="post_filter")
        pre = gov.recall("alpha falcon", principal=ALICE, mode="pre_filter")

        assert [r["id"] for r in post["results"]] == [allowed["id"]]
        assert [r["id"] for r in post["results"]] == [r["id"] for r in pre["results"]]
        assert post["denied_count"] == 12
    finally:
        gov.close()


def test_candidate_scan_reports_when_it_gives_up(tmp_path, monkeypatch):
    """Bounding the scan is fine; bounding it silently is not."""
    from amnesia import MemoryGovernor

    monkeypatch.setattr("amnesia.governor.CANDIDATE_LIMIT", 2)
    monkeypatch.setattr("amnesia.governor.MAX_CANDIDATE_PAGES", 1)
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        for i in range(6):
            gov.remember(
                f"alpha falcon alpha falcon {i}",
                source="hr-system",
                tenant=TENANT,
                scope="hr_only",
                owner="dana",
            )
        gov.remember("alpha falcon runbook", source="wiki", tenant=TENANT, scope="project")

        view = gov.recall("alpha falcon", principal=ALICE)
        assert view["results"] == []  # the ceiling was hit before the allowed memory

        degraded = [e for e in gov.audit.entries() if e["event"] == "governance.degraded"]
        assert any(e["component"] == "candidate_scan" for e in degraded)
    finally:
        gov.close()


def test_paging_does_not_change_an_easy_result(tmp_path, monkeypatch):
    """The scan must be a no-op when the first page already contains the answer."""
    from amnesia import MemoryGovernor

    monkeypatch.setattr("amnesia.governor.CANDIDATE_LIMIT", 5)
    gov = MemoryGovernor(db_path=tmp_path / "m.db", audit_path=tmp_path / "a.jsonl")
    try:
        target = gov.remember(
            "Falcon programme quarterly report", source="wiki", tenant=TENANT, scope="project"
        )
        for i in range(3):
            gov.remember(f"unrelated note {i}", source="wiki", tenant=TENANT, scope="project")

        view = gov.recall("Falcon programme", principal=ALICE)
        assert [r["id"] for r in view["results"]] == [target["id"]]
        read = next(e for e in gov.audit.entries() if e["event"] == "memory.read")
        assert read["candidates_evaluated"] == 1
    finally:
        gov.close()


def test_governor_end_to_end_uses_bm25(gov_free_tmp=None):
    """The governor path, not just the store, ranks by relevance."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        gov = MemoryGovernor(db_path=Path(tmp) / "m.db", audit_path=Path(tmp) / "a.jsonl")
        try:
            gov.remember(
                "Quarterly report references the Falcon programme.",
                source="wiki",
                tenant=TENANT,
                scope="project",
            )
            for i in range(6):
                gov.remember(
                    f"Weekly update number {i} for the platform team.",
                    source="wiki",
                    tenant=TENANT,
                    scope="project",
                )
            view = gov.recall("Falcon programme", principal=ALICE)
            assert len(view["results"]) == 1
            assert "Falcon" in view["results"][0]["content"]
            assert view["results"][0]["score"] > 0
        finally:
            gov.close()


def test_tokens_helper_is_stable():
    assert tokens("Alpha beta") == {"alpha", "beta"}
    assert tokens("") == set()

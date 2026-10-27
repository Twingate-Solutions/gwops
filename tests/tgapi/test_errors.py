"""Tests for gwops.tgapi.errors."""

from gwops.tgapi.errors import TGAPIError, TGAuthError, TGGraphQLError, TGRateLimited


class TestTGAPIError:
    def test_carries_status_query_name_and_body(self) -> None:
        err = TGAPIError("boom", status=500, query_name="ListResources", body="server body")
        assert err.status == 500
        assert err.query_name == "ListResources"
        assert err.body == "server body"
        assert str(err) == "boom"

    def test_status_may_be_none_for_transport_failures(self) -> None:
        err = TGAPIError("timeout", status=None, query_name="ListResources", body="")
        assert err.status is None

    def test_truncates_long_bodies(self) -> None:
        long_body = "x" * 2000
        err = TGAPIError("boom", status=500, query_name="q", body=long_body)
        assert len(err.body) < 2000
        assert err.body.startswith("xxx")


class TestSubclasses:
    def test_tg_auth_error_is_a_tg_api_error(self) -> None:
        err = TGAuthError("unauthorized", status=401, query_name="q", body="")
        assert isinstance(err, TGAPIError)
        assert err.status == 401

    def test_tg_rate_limited_is_a_tg_api_error(self) -> None:
        err = TGRateLimited("rate limited", status=429, query_name="q", body="")
        assert isinstance(err, TGAPIError)
        assert err.status == 429

    def test_tg_graphql_error_carries_errors_list(self) -> None:
        errors = [{"message": "field X not found"}]
        err = TGGraphQLError(
            "graphql errors", status=200, query_name="q", body="{}", errors=errors
        )
        assert isinstance(err, TGAPIError)
        assert err.errors == errors

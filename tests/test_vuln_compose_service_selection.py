from scenarioforge.utils import vuln_process


def test_select_service_key_prefers_webserver_over_infra_for_airflow_cve():
    """Regression: Airflow CVE compose lists postgres/redis before airflow-webserver.

    When prefer_service doesn't match any service key, we should still pick a likely
    interactive app service (airflow-webserver) so CORE starts the expected service.
    """

    compose_obj = {
        "services": {
            "postgres": {"image": "postgres:13"},
            "redis": {"image": "redis:6"},
            "airflow-scheduler": {"image": "apache/airflow:2.0.0"},
            "airflow-webserver": {"image": "apache/airflow:2.0.0", "ports": ["8080:8080"]},
        }
    }

    selected = vuln_process._select_service_key(compose_obj, prefer_service="airflow/CVE-2020-11981")
    assert selected == "airflow-webserver"

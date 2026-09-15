"""Disable request-size limits for catalog imports only."""


def configure_catalog_uploads(app):
    if getattr(app.request_class, '_catalog_upload_limits_configured', False):
        return
    base = app.request_class
    endpoints = {'generator_packs_upload', 'vuln_catalog_packs_upload'}

    class CatalogRequest(base):
        _catalog_upload_limits_configured = True

        @property
        def max_content_length(self):
            return None if self.endpoint in endpoints else super().max_content_length

        @property
        def max_form_parts(self):
            return None if self.endpoint in endpoints else super().max_form_parts

        @property
        def max_form_memory_size(self):
            return None if self.endpoint in endpoints else super().max_form_memory_size

    app.request_class = CatalogRequest

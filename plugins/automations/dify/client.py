from urllib.parse import urlparse

from patronus_api_client import Patronus, PatronusError

AUTH_PROBE_JOB = 'job_00000000000000000000000000000000'


def client(credentials):
    return Patronus(credentials.get('api_key', ''), timeout=10)


def scan_body(kind, content):
    if not isinstance(content, str) or not content.strip():
        raise ValueError('Scan content is required.')
    if kind == 'text':
        return {'text': content}
    if kind not in {'url', 'mcp'}:
        raise ValueError('Unsupported scan type.')
    url = urlparse(content)
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise ValueError('Provide a public HTTPS URL without credentials.')
    return {'url' if kind == 'url' else 'mcp_server_url': content}


def validate_credentials(credentials):
    try:
        client(credentials).get_job(AUTH_PROBE_JOB)
    except PatronusError as error:
        if error.status != 404:
            raise


def error_message(error):
    if isinstance(error, PatronusError):
        message = f'Patronus {error.kind} error'
        if error.status:
            message += f' (HTTP {error.status})'
        if error.retry_after is not None:
            message += f'; retry after {error.retry_after}s'
        return message + '.'
    return 'Patronus request failed. Check the input and connection.'

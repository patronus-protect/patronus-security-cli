import time
from patronus_api_client import Patronus

from client import client, scan_body

CONFIG = {'categories': ['injection', 'dlp'], 'max_level': 'L3'}


class GuardRejected(ValueError):
    def __init__(self, status='unverified'):
        self.status = status
        super().__init__('Patronus blocked this input. No text was released.' if status == 'blocked'
                         else 'Patronus could not verify this input. No text was released.')


def complete_metadata(metadata):
    if not isinstance(metadata, dict) or metadata.get('state') != 'complete':
        return False
    total = metadata.get('documents_total')
    pages = metadata.get('pages_total')
    return (type(total) is int and type(metadata.get('documents_scanned')) is int and total >= 1 and total == metadata.get('documents_scanned') and
            (('pages_total' not in metadata and 'pages_scanned' not in metadata) or
             (type(pages) is int and type(metadata.get('pages_scanned')) is int and pages >= 1 and pages == metadata.get('pages_scanned'))))


def verify_guard_result(response):
    if not isinstance(response, dict):
        raise GuardRejected()
    jobs = response.get('jobs')
    if response.get('status') != 'completed' or not isinstance(jobs, list) or not 0 < len(jobs) <= 32:
        raise GuardRejected()
    ids = []
    for job in jobs:
        if not isinstance(job, dict):
            raise GuardRejected()
        job_id = job.get('job_id')
        # Use the SDK's public identifier validation, not arbitrary paths/URLs.
        if Patronus._invalid_job_id(job_id) or job_id in ids or job.get('status') != 'completed':
            raise GuardRejected()
        if (job.get('decision') != 'allow' or job.get('safety_status', 'benign') != 'benign' or
                response.get('decision', 'allow') != 'allow' or response.get('safety_status', 'benign') != 'benign'):
            raise GuardRejected('blocked')
        completion = job.get('completion') or {}
        if (not complete_metadata(job.get('coverage', response.get('coverage'))) or
                not complete_metadata(job.get('extraction', response.get('extraction'))) or
                not isinstance(completion, dict) or completion.get('state') != 'complete' or
                'failures' in completion and (not isinstance(completion['failures'], list) or len(completion['failures']) > 0)):
            raise GuardRejected()
        categories = job.get('categories')
        if not isinstance(categories, dict) or set(categories) != set(CONFIG['categories']):
            raise GuardRejected()
        for name in CONFIG['categories']:
            category = categories[name]
            final = isinstance(category, dict) and 'final_result' in category
            result = category.get('final_result') if final else category
            if not isinstance(result, dict):
                raise GuardRejected()
            if result.get('class_name') not in {'benign', 'safe'}:
                raise GuardRejected('blocked')
            confidence = result.get('confidence')
            if (type(confidence) not in (int, float) or not 0 <= confidence <= 1 or
                    (final and (not isinstance(result.get('source'), str) or not result['source'].strip())) or
                    (not final and (not isinstance(category.get('model'), str) or not category['model'].strip() or category.get('level') not in {'L1', 'L2', 'L3'}))):
                raise GuardRejected()
        ids.append(job_id)
    return ids


def guard_input(credentials, text, timeout=10):
    api = client(credentials)
    body = {**scan_body('text', text), 'config': CONFIG}
    deadline = time.monotonic() + timeout

    def check_deadline():
        if time.monotonic() >= deadline:
            raise GuardRejected()

    result = api.submit(body)
    check_deadline()
    if result.get('status') == 'accepted':
        accepted = result.get('jobs')
        if not isinstance(accepted, list) or not 0 < len(accepted) <= 32:
            raise GuardRejected()
        ids = [job.get('job_id') if isinstance(job, dict) else None for job in accepted]
        if any(api._invalid_job_id(job_id) for job_id in ids) or len(set(ids)) != len(ids):
            raise GuardRejected()
        jobs = []
        for job_id in ids:
            delay = .25
            while True:
                check_deadline()
                job = api.get_job(job_id)
                check_deadline()
                if job.get('job_id') != job_id:
                    raise GuardRejected()
                if job.get('status') in {'queued', 'running'}:
                    time.sleep(min(delay, deadline - time.monotonic()))
                    delay = min(delay * 2, 1)
                else:
                    jobs.append(job)
                    break
        result = {**result, 'status': 'completed', 'jobs': jobs}
    ids = verify_guard_result(result)
    return {'text': text, 'patronus': {'status': 'allowed', 'job_ids': ids}}

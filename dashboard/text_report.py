"""Plain-text snapshot with explicit evidence and collection boundaries."""


def clean(value):
    if value is None:
        return 'Unknown'
    return ' '.join(str(value).split())


def flag(value):
    return {True: 'yes', False: 'no'}.get(value, 'unknown')


def format_text_report(snapshot):
    coverage = snapshot.get('coverage') or {}
    retained = 'stored_events' in coverage
    alerts = snapshot.get('alerts', [])[:200]
    rows = [
        'OMEGA quick security snapshot',
        'Generated: ' + clean(snapshot.get('generated')),
        'Mode: ' + ('DEMO — simulated data' if snapshot.get('demo') else 'LIVE'),
        'This limited snapshot is not a full security assessment or the full retained evidence export.',
        'Generate the full report in Reports for the retained evidence and its collection limits.',
        '', 'Coverage',
        'Telemetry available: ' + flag(snapshot.get('available')),
        'Snapshot stale: ' + flag(snapshot.get('stale')),
        ('Retained normalized events: ' if retained else 'Events in bounded snapshot: ') + clean(coverage.get('stored_events') if retained else snapshot.get('events')),
        'DNS events: ' + clean(snapshot.get('dns')),
        'Total detections in this collection: ' + clean(snapshot.get('alert_count')),
        'Skipped malformed records: ' + clean(snapshot.get('invalid')),
        'Source data omitted/truncated: ' + flag(snapshot.get('truncated')),
        'Last event: ' + clean(snapshot.get('updated')),
        'Collection mode: ' + clean(coverage.get('collection_mode')),
        'Collection began: ' + clean(coverage.get('collection_started')),
        'Collector caught up: ' + flag(coverage.get('caught_up')),
    ]
    if snapshot.get('notice'):
        rows.append('Notice: ' + clean(snapshot['notice']))
    for limitation in coverage.get('limitations', []):
        rows.append('Limit: ' + clean(limitation))
    rows += ['', 'Source health']
    for source in snapshot.get('sources', []):
        rows.append('{} | available={} | caught up={} | sync current={} | events={} | last event={}'.format(
            clean(source.get('label') or source.get('id')), flag(source.get('available')),
            flag(source.get('caught_up')), flag(source.get('sync_current')),
            clean(source.get('events')), clean(source.get('updated'))))
        if source.get('notice'):
            rows.append('  ' + clean(source['notice']))
    if not snapshot.get('sources'):
        rows.append('Per-source health was not supplied; completeness is unverified.')
    rows += ['', 'Service checks', 'Active means a system service is running; it does not prove effective protection.']
    for service in snapshot.get('services', []):
        rows.append('{}: {}{}'.format(clean(service.get('label') or service.get('name')),
            clean(service.get('state')), ' — ' + clean(service['detail']) if service.get('detail') else ''))
    rows += ['', 'Recent detection selection: {} shown (maximum 200).'.format(len(alerts)),
             'Selection reserves space for each sensor when retained collection is enabled; it is not an exhaustive incident list.',
             'OMEGA priority: 1=High, 2=Medium, 3=Low. Wazuh rule levels are separate original values.',
             'Unknown endpoints mean the record did not supply that field, not an unidentified person.']
    for alert in alerts:
        priority = {1: 'High', 2: 'Medium', 3: 'Low'}.get(alert.get('severity'), 'Unrated')
        rows.append('{} | OMEGA priority {} | sensor {} | rule {} | original Wazuh level {} | {} | {} -> {}'.format(
            clean(alert.get('timestamp')), priority, clean(alert.get('sensor')), clean(alert.get('rule_id')),
            clean(alert.get('rule_level')) if alert.get('sensor') == 'wazuh' else 'not applicable',
            clean(alert.get('signature')), clean(alert.get('source')), clean(alert.get('destination'))))
    return '\n'.join(rows) + '\n'

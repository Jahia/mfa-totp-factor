import React from 'react';
import {useTranslation} from 'react-i18next';
import {useLazyQuery} from '@apollo/client';
import {Button, Key, Loader, Typography} from '@jahia/moonstone';
import {AuditEventsQuery, EnrollmentReportQuery} from './SiteSettings.gql';

const formatTs = ts => {
    if (!ts) {
        return '';
    }

    const d = new Date(Number(ts));
    return Number.isNaN(d.getTime()) ? String(ts) : d.toISOString().replace('T', ' ').slice(0, 19);
};

/**
 * Admin reporting: a recent-audit-events table and an enrollment summary
 * ("who hasn't enrolled?"). Both load lazily on demand to avoid scanning on every page view.
 */
const AuditReportSection = ({siteKey}) => {
    const {t} = useTranslation('mfa-factors-webauthn');

    const [loadAudit, audit] = useLazyQuery(AuditEventsQuery, {
        variables: {siteKey, limit: 50},
        fetchPolicy: 'network-only'
    });
    const [loadReport, report] = useLazyQuery(EnrollmentReportQuery, {
        variables: {siteKey, limit: 200},
        fetchPolicy: 'network-only'
    });

    const events = (audit.data && audit.data.mfaWebauthn && audit.data.mfaWebauthn.auditEvents) || [];
    const reportData = report.data && report.data.mfaWebauthn && report.data.mfaWebauthn.enrollmentReport;

    return (
        <section data-testid="audit-report-section" data-factor="webauthn">
            <div style={{display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12}}>
                <span aria-hidden="true" style={{display: 'inline-flex'}}><Key/></span>
                <Typography id="webauthn-audit-heading" variant="heading">
                    {t('siteSettings.audit.title')}
                </Typography>
            </div>

            <div style={{display: 'flex', gap: 12, marginBottom: 16}}>
                <Button data-testid="load-audit-btn"
                        isDisabled={audit.loading}
                        label={t('siteSettings.audit.loadEvents')}
                        onClick={() => loadAudit()}/>
                <Button data-testid="load-report-btn"
                        isDisabled={report.loading}
                        label={t('siteSettings.audit.loadReport')}
                        onClick={() => loadReport()}/>
            </div>

            {report.loading && (
                <div data-testid="report-loading" style={{marginBottom: 24}}><Loader/></div>
            )}

            {report.error && (
                <Typography role="alert"
                            data-testid="report-error"
                            style={{color: '#a00000', display: 'block', marginBottom: 24}}
                >
                    {t('siteSettings.audit.reportError')}
                </Typography>
            )}

            {reportData && (
                <div data-testid="enrollment-report" style={{marginBottom: 24}}>
                    <Typography style={{display: 'block'}}>
                        {t('siteSettings.audit.reportSummary', {
                            registered: reportData.registeredUsers,
                            total: reportData.totalUsers
                        })}
                    </Typography>
                    {reportData.notRegistered.length > 0 && (
                        <Typography variant="caption" style={{display: 'block', color: '#555', marginTop: 4}}>
                            {t('siteSettings.audit.notRegistered')}: {reportData.notRegistered.join(', ')}
                            {reportData.truncated ? ' …' : ''}
                        </Typography>
                    )}
                </div>
            )}

            {audit.loading && (
                <div data-testid="audit-loading" style={{marginBottom: 24}}><Loader/></div>
            )}

            {audit.error && (
                <Typography role="alert"
                            data-testid="audit-error"
                            style={{color: '#a00000', display: 'block', marginBottom: 24}}
                >
                    {t('siteSettings.audit.error')}
                </Typography>
            )}

            {audit.called && !audit.loading && !audit.error && events.length === 0 && (
                <Typography data-testid="audit-empty" style={{display: 'block', color: '#555', marginBottom: 24}}>
                    {t('siteSettings.audit.noEvents')}
                </Typography>
            )}

            {events.length > 0 && (
                <table data-testid="audit-table" aria-labelledby="webauthn-audit-heading" style={{borderCollapse: 'collapse', width: '100%', tableLayout: 'fixed'}}>
                    {/* Fixed layout + explicit column widths keep the table at 100% of its container
                        (no horizontal window overflow) while the detail column takes the remainder and
                        wraps. No overflow:auto wrapper, so the page's own vertical scroll is untouched. */}
                    <colgroup>
                        <col style={{width: '9.5rem'}}/>
                        <col style={{width: '8rem'}}/>
                        <col style={{width: '7rem'}}/>
                        <col style={{width: '10rem'}}/>
                        <col/>
                    </colgroup>
                    <caption style={{textAlign: 'left', captionSide: 'top', marginBottom: 8, fontWeight: 600}}>
                        {t('siteSettings.audit.title')}
                    </caption>
                    <thead>
                        <tr>
                            <th scope="col" style={timeCell}>{t('siteSettings.audit.colTime')}</th>
                            <th scope="col" style={cell}>{t('siteSettings.audit.colEvent')}</th>
                            <th scope="col" style={cell}>{t('siteSettings.audit.colOutcome')}</th>
                            <th scope="col" style={cell}>{t('siteSettings.audit.colUser')}</th>
                            <th scope="col" style={cell}>{t('siteSettings.audit.colDetail')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {events.map(e => (
                            <tr key={`${e.timestamp}-${e.eventType}-${e.userId}-${e.detail}`}>
                                <td style={timeCell}>{formatTs(e.timestamp)}</td>
                                <td style={cell}>{e.eventType}</td>
                                <td style={cell}>{e.outcome}</td>
                                <td style={cell}>{e.userId}</td>
                                <td style={cell}>{e.detail}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </section>
    );
};

// overflowWrap/wordBreak let long free-form values (IPs, user agents, messages) wrap inside their
// fixed-width column instead of forcing the table wider than its container.
const cell = {border: '1px solid #e0e0e0', padding: '4px 8px', textAlign: 'left', fontSize: '0.85rem', verticalAlign: 'top', wordBreak: 'break-word', overflowWrap: 'anywhere'};
// The timestamp is a fixed-shape value: keep it on one line in its sized column.
const timeCell = {...cell, whiteSpace: 'nowrap', wordBreak: 'normal', overflowWrap: 'normal'};

export default AuditReportSection;
